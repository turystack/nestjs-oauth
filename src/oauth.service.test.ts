import { randomBytes } from 'node:crypto'

import type { AccessTokenService } from '@turystack/nestjs-access'
import { beforeEach, describe, expect, it, vi } from 'vitest'

import { OAuthService } from '@/oauth.service.js'
import type { OAuthOptions } from '@/oauth.types.js'
import { deriveChallenge } from '@/pkce.js'

import {
	OAuthInvalidGrantException,
	OAuthInvalidRequestException,
} from '@/exceptions/oauth.exceptions.js'
import { MemoryOAuthCodeStore } from '@/store/memory-code-store.js'

const REDIRECT_URI = 'https://app.example.com/callback'
const OTHER_URI = 'https://app.example.com/other'

const verifier = randomBytes(32).toString('base64url')
const challenge = deriveChallenge(verifier)

function createOptions(overrides: Partial<OAuthOptions> = {}): OAuthOptions {
	return {
		clients: [
			{
				id: 'web',
				redirectUris: [
					REDIRECT_URI,
				],
			},
			{
				id: 'admin',
				redirectUris: [
					OTHER_URI,
				],
			},
		],
		signInUrl: 'https://auth.example.com/',
		...overrides,
	}
}

function authorizeRequest(overrides: Record<string, unknown> = {}) {
	return {
		client_id: 'web',
		code_challenge: challenge,
		code_challenge_method: 'S256',
		redirect_uri: REDIRECT_URI,
		...overrides,
	} as Parameters<OAuthService['authorize']>[0]
}

describe('OAuthService', () => {
	let store: MemoryOAuthCodeStore
	let tokens: AccessTokenService
	let service: OAuthService

	beforeEach(() => {
		store = new MemoryOAuthCodeStore()
		// Typed against the real signatures: an untyped `vi.fn()` resolving a
		// camelCase pair is how this suite once stayed green while the service
		// read keys `AccessTokenService` no longer returned.
		tokens = {
			issueTokens: vi
				.fn<AccessTokenService['issueTokens']>()
				.mockResolvedValue({
					access_token: 'access',
					expires_in: 900,
					refresh_token: 'refresh',
				}),
			verifyRefreshToken: vi
				.fn<AccessTokenService['verifyRefreshToken']>()
				.mockResolvedValue({
					user_id: 'user-1',
				}),
		} as Pick<
			AccessTokenService,
			'issueTokens' | 'verifyRefreshToken'
		> as AccessTokenService
		service = new OAuthService(createOptions(), store, tokens)
	})

	describe('authorize', () => {
		it('sends the browser to the sign-in application with a transaction id', async () => {
			const target = new URL(await service.authorize(authorizeRequest()))

			expect(target.origin).toBe('https://auth.example.com')
			expect(target.searchParams.get('tx')).toBeTruthy()
		})

		it('refuses an unknown client rather than redirecting anywhere', async () => {
			await expect(
				service.authorize(
					authorizeRequest({
						client_id: 'ghost',
					}),
				),
			).rejects.toBeInstanceOf(OAuthInvalidRequestException)
		})

		it('refuses a redirect_uri the client did not register', async () => {
			await expect(
				service.authorize(
					authorizeRequest({
						redirect_uri: 'https://evil.example.com/callback',
					}),
				),
			).rejects.toBeInstanceOf(OAuthInvalidRequestException)
		})

		it("refuses another client's registered redirect_uri", async () => {
			await expect(
				service.authorize(
					authorizeRequest({
						redirect_uri: OTHER_URI,
					}),
				),
			).rejects.toBeInstanceOf(OAuthInvalidRequestException)
		})

		it('refuses a redirect_uri that merely starts with a registered one', async () => {
			await expect(
				service.authorize(
					authorizeRequest({
						redirect_uri: `${REDIRECT_URI}.evil.com`,
					}),
				),
			).rejects.toBeInstanceOf(OAuthInvalidRequestException)
		})

		it('refuses the plain challenge method', async () => {
			await expect(
				service.authorize(
					authorizeRequest({
						code_challenge_method: 'plain',
					}),
				),
			).rejects.toBeInstanceOf(OAuthInvalidRequestException)
		})

		it('refuses a malformed challenge', async () => {
			await expect(
				service.authorize(
					authorizeRequest({
						code_challenge: 'nope',
					}),
				),
			).rejects.toBeInstanceOf(OAuthInvalidRequestException)
		})
	})

	describe('completeAuthorization', () => {
		it('redirects back to the client with a code and the original state', async () => {
			const started = new URL(
				await service.authorize(
					authorizeRequest({
						state: 'xyz',
					}),
				),
			)
			const back = new URL(
				await service.completeAuthorization(
					started.searchParams.get('tx') as string,
					'user-1',
				),
			)

			expect(back.origin + back.pathname).toBe(REDIRECT_URI)
			expect(back.searchParams.get('code')).toBeTruthy()
			expect(back.searchParams.get('state')).toBe('xyz')
		})

		it('spends the transaction, so one sign-in cannot mint two codes', async () => {
			const started = new URL(await service.authorize(authorizeRequest()))
			const tx = started.searchParams.get('tx') as string

			await service.completeAuthorization(tx, 'user-1')

			await expect(
				service.completeAuthorization(tx, 'user-1'),
			).rejects.toBeInstanceOf(OAuthInvalidGrantException)
		})

		it('refuses a transaction that never existed', async () => {
			await expect(
				service.completeAuthorization('made-up', 'user-1'),
			).rejects.toBeInstanceOf(OAuthInvalidGrantException)
		})
	})

	describe('exchangeCode', () => {
		async function issueCode(state?: string) {
			const started = new URL(
				await service.authorize(
					authorizeRequest(
						state === undefined
							? {}
							: {
									state,
								},
					),
				),
			)
			const back = new URL(
				await service.completeAuthorization(
					started.searchParams.get('tx') as string,
					'user-1',
				),
			)

			return back.searchParams.get('code') as string
		}

		it('returns a session for the right verifier', async () => {
			const session = await service.exchangeCode({
				client_id: 'web',
				code: await issueCode(),
				code_verifier: verifier,
				redirect_uri: REDIRECT_URI,
			})

			expect(session.access_token).toBe('access')
			expect(session.refresh_token).toBe('refresh')
			expect(session.expires_at).toBeGreaterThan(Date.now())
		})

		it('refuses a wrong verifier', async () => {
			await expect(
				service.exchangeCode({
					client_id: 'web',
					code: await issueCode(),
					code_verifier: randomBytes(32).toString('base64url'),
					redirect_uri: REDIRECT_URI,
				}),
			).rejects.toBeInstanceOf(OAuthInvalidGrantException)
		})

		it('burns the code on a wrong verifier, leaving nothing to guess against', async () => {
			const code = await issueCode()

			await expect(
				service.exchangeCode({
					client_id: 'web',
					code,
					code_verifier: randomBytes(32).toString('base64url'),
					redirect_uri: REDIRECT_URI,
				}),
			).rejects.toBeInstanceOf(OAuthInvalidGrantException)

			await expect(
				service.exchangeCode({
					client_id: 'web',
					code,
					code_verifier: verifier,
					redirect_uri: REDIRECT_URI,
				}),
			).rejects.toBeInstanceOf(OAuthInvalidGrantException)
		})

		it('answers a code exactly once', async () => {
			const code = await issueCode()
			const input = {
				client_id: 'web',
				code,
				code_verifier: verifier,
				redirect_uri: REDIRECT_URI,
			}

			await service.exchangeCode(input)

			await expect(service.exchangeCode(input)).rejects.toBeInstanceOf(
				OAuthInvalidGrantException,
			)
		})

		it('refuses a code presented by a different client', async () => {
			await expect(
				service.exchangeCode({
					client_id: 'admin',
					code: await issueCode(),
					code_verifier: verifier,
					redirect_uri: REDIRECT_URI,
				}),
			).rejects.toBeInstanceOf(OAuthInvalidGrantException)
		})

		it('refuses a code redeemed against a different redirect_uri', async () => {
			await expect(
				service.exchangeCode({
					client_id: 'web',
					code: await issueCode(),
					code_verifier: verifier,
					redirect_uri: OTHER_URI,
				}),
			).rejects.toBeInstanceOf(OAuthInvalidGrantException)
		})

		it('refuses a code that never existed', async () => {
			await expect(
				service.exchangeCode({
					client_id: 'web',
					code: 'invented',
					code_verifier: verifier,
					redirect_uri: REDIRECT_URI,
				}),
			).rejects.toBeInstanceOf(OAuthInvalidGrantException)
		})

		it('carries the workspace the authorization was completed for', async () => {
			const started = new URL(await service.authorize(authorizeRequest()))
			const back = new URL(
				await service.completeAuthorization(
					started.searchParams.get('tx') as string,
					'user-1',
					{
						workspaceId: 'ws-1',
					},
				),
			)

			await service.exchangeCode({
				client_id: 'web',
				code: back.searchParams.get('code') as string,
				code_verifier: verifier,
				redirect_uri: REDIRECT_URI,
			})

			expect(tokens.issueTokens).toHaveBeenCalledWith('user-1', {
				workspaceId: 'ws-1',
			})
		})
	})

	describe('refresh', () => {
		it('mints a new session from a valid refresh token', async () => {
			const session = await service.refresh('refresh')

			expect(session.access_token).toBe('access')
			expect(session.refresh_token).toBe('refresh')
			expect(tokens.verifyRefreshToken).toHaveBeenCalledWith('refresh')
			expect(tokens.issueTokens).toHaveBeenCalledWith('user-1', undefined)
		})

		it('keeps the user and the workspace the refresh token was minted for', async () => {
			vi.mocked(tokens.verifyRefreshToken).mockResolvedValueOnce({
				user_id: 'user-1',
				workspace_id: 'ws-1',
			})

			await service.refresh('refresh')

			expect(tokens.issueTokens).toHaveBeenCalledWith('user-1', {
				workspaceId: 'ws-1',
			})
		})

		it('turns expires_in seconds into an expires_at instant', async () => {
			const before = Date.now()
			const session = await service.refresh('refresh')

			expect(session.expires_at).toBeGreaterThanOrEqual(before + 900_000)
			expect(session.expires_at).toBeLessThanOrEqual(Date.now() + 900_000)
		})

		it('propagates the rejection when the refresh token does not verify', async () => {
			vi.mocked(tokens.verifyRefreshToken).mockRejectedValueOnce(
				new Error('nope'),
			)

			await expect(service.refresh('bad')).rejects.toThrow()
		})
	})
})
