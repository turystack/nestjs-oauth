import { type DynamicModule, Module, type Provider } from '@nestjs/common'
import { ModuleRef } from '@nestjs/core'
import { ConfigService } from '@turystack/nestjs-config'

import { OAUTH_CODE_STORE, OAUTH_OPTIONS } from '@/oauth.constants.js'
import { OAuthController } from '@/oauth.controller.js'
import { OAuthService } from '@/oauth.service.js'
import type {
	OAuthCodeStore,
	OAuthModuleFactoryOptions,
	OAuthModuleOptions,
	OAuthOptions,
} from '@/oauth.types.js'

import { MemoryOAuthCodeStore } from '@/store/memory-code-store.js'

const OAUTH_RESOLVED_OPTIONS = Symbol('OAUTH_RESOLVED_OPTIONS')

@Module({})
export class OAuthModule {
	/**
	 * Registers the authorization server globally — once, in the API root.
	 *
	 * It needs `AccessModule` registered: this module decides *whether* a session
	 * may be issued, and `AccessTokenService` is what mints it.
	 *
	 * The `(config) => options` factory form injects the `ConfigService` from
	 * `@turystack/nestjs-config` at boot.
	 */
	static register(
		options:
			| OAuthModuleOptions
			| ((config: ConfigService) => OAuthModuleFactoryOptions),
	): DynamicModule {
		return {
			controllers: [
				OAuthController,
			],
			exports: [
				OAUTH_OPTIONS,
				OAUTH_CODE_STORE,
				OAuthService,
			],
			global: true,
			imports: typeof options === 'function' ? [] : (options.imports ?? []),
			module: OAuthModule,
			providers: OAuthModule._resolveProviders(options),
		}
	}

	private static _resolveOptions(
		optionsOrFactory:
			| OAuthModuleOptions
			| ((config: ConfigService) => OAuthModuleFactoryOptions),
		config?: ConfigService,
	): OAuthModuleFactoryOptions {
		if (typeof optionsOrFactory !== 'function') {
			return optionsOrFactory
		}

		if (!config) {
			throw new Error(
				'[OAuthModule] register((config) => ...) requires ConfigModule (@turystack/nestjs-config) to be registered',
			)
		}

		return optionsOrFactory(config)
	}

	private static _resolveProviders(
		optionsOrFactory:
			| OAuthModuleOptions
			| ((config: ConfigService) => OAuthModuleFactoryOptions),
	): Provider[] {
		// The factory form's options exist only once the factory runs, so its
		// `store` is chosen then and built by Nest with its dependencies; the
		// object form names it up front, as a class provider.
		const storeProvider: Provider =
			typeof optionsOrFactory === 'function'
				? {
						inject: [
							OAUTH_RESOLVED_OPTIONS,
							ModuleRef,
						],
						provide: OAUTH_CODE_STORE,
						useFactory: (
							options: OAuthModuleFactoryOptions,
							moduleRef: ModuleRef,
						): Promise<OAuthCodeStore> =>
							moduleRef.create(options.store ?? MemoryOAuthCodeStore),
					}
				: {
						provide: OAUTH_CODE_STORE,
						useClass: optionsOrFactory.store ?? MemoryOAuthCodeStore,
					}

		return [
			{
				inject: [
					{
						optional: true,
						token: ConfigService,
					},
				],
				provide: OAUTH_RESOLVED_OPTIONS,
				useFactory: (config?: ConfigService) =>
					OAuthModule._resolveOptions(optionsOrFactory, config),
			},
			{
				inject: [
					OAUTH_RESOLVED_OPTIONS,
				],
				provide: OAUTH_OPTIONS,
				useFactory: (options: OAuthModuleOptions): OAuthOptions => {
					const { imports, store, ...oauthOptions } = options

					return oauthOptions
				},
			},
			storeProvider,
			OAuthService,
		]
	}
}
