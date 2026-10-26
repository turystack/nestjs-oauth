import { randomBytes } from 'node:crypto'

import { AccessTokenService } from '@turystack/nestjs-access'
import { beforeEach, describe, expect, it } from 'vitest'

import { OAuthService } from '@/oauth.service.js'
import { deriveChallenge } from '@/pkce.js'

import { MemoryOAuthCodeStore } from '@/store/memory-code-store.js'

const REDIRECT_URI = 'https://app.example.com/callback'

const verifier = randomBytes(32).toString('base64url')

/**
 * The service against the real `AccessTokenService`, with nothing mocked.
 *
 * The unit suite mocks the token service, and a mock only proves the contract
 * it was written against. When `@turystack/nestjs-access` moved to snake_case the
 * mocks kept answering `accessToken` and `userId`, the suite stayed green, and
 * every real session came back with `undefined` tokens — and every refresh
 * minted a token for no user and no workspace. This suite reads what the other
 * package actually returns.
 */
describe('OAuthService with the real AccessTokenService', () => {
	let tokens: AccessTokenService
	let service: OAuthService

	beforeEach(() => {
		tokens = new AccessTokenService({
			permissions: {},
			secret: 'a-secret-long-enough-for-hs256-signing',
		})
		service = new OAuthService(
			{
				clients: [
					{
						id: 'web',
						redirectUris: [
							REDIRECT_URI,
						],
					},
				],
				signInUrl: 'https://auth.example.com/',
			},
			new MemoryOAuthCodeStore(),
			tokens,
		)
	})

	async function signIn(options?: { workspaceId?: string }) {
		const started = new URL(
			await service.authorize({
				client_id: 'web',
				code_challenge: deriveChallenge(verifier),
				code_challenge_method: 'S256',
				redirect_uri: REDIRECT_URI,
			}),
		)
		const back = new URL(
			await service.completeAuthorization(
				started.searchParams.get('tx') as string,
				'user-1',
				options,
			),
		)

		return service.exchangeCode({
			client_id: 'web',
			code: back.searchParams.get('code') as string,
			code_verifier: verifier,
			redirect_uri: REDIRECT_URI,
		})
	}

	it('returns the tokens AccessTokenService minted, with a future expiry', async () => {
		const session = await signIn()

		expect(session.access_token).toEqual(expect.any(String))
		expect(session.refresh_token).toEqual(expect.any(String))
		expect(session.expires_at).toBeGreaterThan(Date.now())
	})

	it('mints the session for the user and workspace the sign-in completed for', async () => {
		const session = await signIn({
			workspaceId: 'ws-1',
		})

		await expect(
			tokens.verifyRefreshToken(session.refresh_token),
		).resolves.toEqual({
			user_id: 'user-1',
			workspace_id: 'ws-1',
		})
	})

	it('keeps the user and workspace across a refresh', async () => {
		const first = await signIn({
			workspaceId: 'ws-1',
		})
		const second = await service.refresh(first.refresh_token)

		await expect(
			tokens.verifyRefreshToken(second.refresh_token),
		).resolves.toEqual({
			user_id: 'user-1',
			workspace_id: 'ws-1',
		})
	})

	it('keeps an organization-only session organization-only across a refresh', async () => {
		const first = await signIn()
		const second = await service.refresh(first.refresh_token)

		await expect(
			tokens.verifyRefreshToken(second.refresh_token),
		).resolves.toEqual({
			user_id: 'user-1',
		})
	})
})
