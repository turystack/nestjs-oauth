import { Injectable } from '@nestjs/common'
import { Test } from '@nestjs/testing'
import {
	IamModule,
	type IamProfile,
	type IamProfileResolver,
} from '@turystack/nestjs-iam'
import { describe, expect, it } from 'vitest'

import { OAUTH_CODE_STORE, OAUTH_OPTIONS } from '@/oauth.constants.js'
import { OAuthController } from '@/oauth.controller.js'
import { OAuthModule } from '@/oauth.module.js'
import { OAuthService } from '@/oauth.service.js'
import type { OAuthCodeStore } from '@/oauth.types.js'

import { MemoryOAuthCodeStore } from '@/store/memory-code-store.js'

@Injectable()
class StubProfileResolver implements IamProfileResolver {
	resolveProfile(): Promise<IamProfile | null> {
		return Promise.resolve(null)
	}
}

@Injectable()
class RecordingStore extends MemoryOAuthCodeStore {}

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
			IamModule.register({
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
			clientId: 'web',
			codeChallenge: 'a'.repeat(43),
			codeChallengeMethod: 'S256',
			redirectUri: 'https://app.example.com/callback',
		})

		expect(new URL(target).searchParams.get('tx')).toBeTruthy()
	})
})
