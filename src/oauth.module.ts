import { type DynamicModule, Module, type Provider } from '@nestjs/common'
import { ConfigService } from '@turystack/nestjs-config'

import { OAUTH_CODE_STORE, OAUTH_OPTIONS } from '@/oauth.constants.js'
import { OAuthController } from '@/oauth.controller.js'
import { OAuthService } from '@/oauth.service.js'
import type {
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
	 * It needs `IamModule` registered: this module decides *whether* a session
	 * may be issued, and `IamTokenService` is what mints it.
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
		const storeProvider: Provider =
			typeof optionsOrFactory !== 'function' && optionsOrFactory.store
				? {
						provide: OAUTH_CODE_STORE,
						useClass: optionsOrFactory.store,
					}
				: {
						provide: OAUTH_CODE_STORE,
						useClass: MemoryOAuthCodeStore,
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
