import { Global, Injectable, Module, type OnModuleInit } from '@nestjs/common'
import { Test } from '@nestjs/testing'
import {
	AccessModule,
	type AccessProfile,
	type AccessProfileResolver,
} from '@turystack/nestjs-access'
import { ConfigService } from '@turystack/nestjs-config'
import { describe, expect, it } from 'vitest'

import { OAUTH_CODE_STORE, OAUTH_OPTIONS } from '@/oauth.constants.js'
import { OAuthController } from '@/oauth.controller.js'
import { OAuthModule } from '@/oauth.module.js'
import { OAuthService } from '@/oauth.service.js'
import type { OAuthCodeStore } from '@/oauth.types.js'

import { MemoryOAuthCodeStore } from '@/store/memory-code-store.js'

@Injectable()
class StubProfileResolver implements AccessProfileResolver {
	resolveProfile(): Promise<AccessProfile | null> {
		return Promise.resolve(null)
	}
}

@Injectable()
class RecordingStore extends MemoryOAuthCodeStore {}

@Injectable()
class StoreClient {
	readonly name = 'shared-redis'
}

@Global()
@Module({
	exports: [
		ConfigService,
		StoreClient,
	],
	providers: [
		{
			provide: ConfigService,
			useValue: {
				get: (key: string) =>
					key === 'AUTH_APP_URL' ? OPTIONS.signInUrl : undefined,
			},
		},
		StoreClient,
	],
})
class StubConfigModule {}

/** A shared store: its client injected, its connection opened on init. */
@Injectable()
class SharedStore extends MemoryOAuthCodeStore implements OnModuleInit {
	opened = false

	constructor(readonly client: StoreClient) {
		super()
	}

	onModuleInit(): void {
		this.opened = true
	}
}

const OPTIONS = {
	clients: [
		{
			id: 'web',
			redirectUris: [
				'https://app.example.com/callback',
			],
		},
	],
	signInUrl: 'https://auth.example.com/',
}

async function createModule(store?: typeof RecordingStore) {
	return Test.createTestingModule({
		imports: [
			AccessModule.register({
				permissions: {},
				profileResolver: StubProfileResolver,
				secret: 'a-secret-long-enough-for-hs256-signing',
			}),
			OAuthModule.register(
				store
					? {
							...OPTIONS,
							store,
						}
					: OPTIONS,
			),
		],
	}).compile()
}

async function createFactoryModule(store?: typeof SharedStore) {
	const moduleRef = await Test.createTestingModule({
		imports: [
			StubConfigModule,
			AccessModule.register({
				permissions: {},
				profileResolver: StubProfileResolver,
				secret: 'a-secret-long-enough-for-hs256-signing',
			}),
			OAuthModule.register((config) => ({
				clients: OPTIONS.clients,
				signInUrl: config.get('AUTH_APP_URL' as never) as string,
				...(store && {
					store,
				}),
			})),
		],
	}).compile()

	await moduleRef.init()

	return moduleRef
}

/**
 * These tests boot the module rather than construct the classes.
 *
 * Constructing by hand proves the logic and hides the wiring: a constructor
 * parameter whose type was imported with `import type` still compiles, still
 * passes every unit test, and resolves to `Object` once Nest reads the emitted
 * metadata — so the failure arrives at boot, in the application, not here.
 */
describe('OAuthModule', () => {
	it('resolves the service with its dependencies injected', async () => {
		const moduleRef = await createModule()

		expect(moduleRef.get(OAuthService)).toBeInstanceOf(OAuthService)
	})

	it('resolves the controller, which is what serves the routes', async () => {
		const moduleRef = await createModule()

		expect(moduleRef.get(OAuthController)).toBeInstanceOf(OAuthController)
	})

	it('exposes the options without the wiring-only keys', async () => {
		const moduleRef = await createModule()
		const options = moduleRef.get(OAUTH_OPTIONS)

		expect(options).toMatchObject(OPTIONS)
		expect(options).not.toHaveProperty('store')
		expect(options).not.toHaveProperty('imports')
	})

	it('defaults to the in-memory store', async () => {
		const moduleRef = await createModule()

		expect(moduleRef.get<OAuthCodeStore>(OAUTH_CODE_STORE)).toBeInstanceOf(
			MemoryOAuthCodeStore,
		)
	})

	it('uses the store the application provided', async () => {
		const moduleRef = await createModule(RecordingStore)

		expect(moduleRef.get<OAuthCodeStore>(OAUTH_CODE_STORE)).toBeInstanceOf(
			RecordingStore,
		)
	})

	it('runs an authorization end to end through the injected service', async () => {
		const moduleRef = await createModule()
		const service = moduleRef.get(OAuthService)
		const target = await service.authorize({
			client_id: 'web',
			code_challenge: 'a'.repeat(43),
			code_challenge_method: 'S256',
			redirect_uri: 'https://app.example.com/callback',
		})

		expect(new URL(target).searchParams.get('tx')).toBeTruthy()
	})

	it('uses the store the factory form returned, built with its dependencies', async () => {
		const moduleRef = await createFactoryModule(SharedStore)
		const store = moduleRef.get<OAuthCodeStore>(OAUTH_CODE_STORE)

		expect(store).toBeInstanceOf(SharedStore)
		expect((store as SharedStore).client).toBeInstanceOf(StoreClient)
		expect((store as SharedStore).opened).toBe(true)
		expect(moduleRef.get(OAUTH_OPTIONS)).not.toHaveProperty('store')
		await moduleRef.close()
	})

	it('defaults the factory form to the in-memory store', async () => {
		const moduleRef = await createFactoryModule()

		expect(moduleRef.get<OAuthCodeStore>(OAUTH_CODE_STORE)).toBeInstanceOf(
			MemoryOAuthCodeStore,
		)
		expect(moduleRef.get(OAUTH_OPTIONS)).toMatchObject({
			signInUrl: OPTIONS.signInUrl,
		})
		await moduleRef.close()
	})
})
