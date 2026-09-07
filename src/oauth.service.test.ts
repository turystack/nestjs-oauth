import { randomBytes } from 'node:crypto'

import type { IamTokenService } from '@turystack/nestjs-iam'
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
		clientId: 'web',
		codeChallenge: challenge,
		codeChallengeMethod: 'S256',
		redirectUri: REDIRECT_URI,
		...overrides,
	} as Parameters<OAuthService['authorize']>[0]
}

describe('OAuthService', () => {
	let store: MemoryOAuthCodeStore
	let tokens: IamTokenService
	let service: OAuthService

	beforeEach(() => {
		store = new MemoryOAuthCodeStore()
		tokens = {
			issueTokens: vi.fn().mockResolvedValue({
				accessToken: 'access',
				expiresIn: 900,
				refreshToken: 'refresh',
			}),
			verifyRefreshToken: vi.fn().mockResolvedValue({
				userId: 'user-1',
			}),
		} as unknown as IamTokenService
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
						clientId: 'ghost',
					}),
				),
			).rejects.toBeInstanceOf(OAuthInvalidRequestException)
		})

		it('refuses a redirect_uri the client did not register', async () => {
			await expect(
				service.authorize(
					authorizeRequest({
						redirectUri: 'https://evil.example.com/callback',
					}),
				),
			).rejects.toBeInstanceOf(OAuthInvalidRequestException)
		})

		it("refuses another client's registered redirect_uri", async () => {
			await expect(
				service.authorize(
					authorizeRequest({
						redirectUri: OTHER_URI,
					}),
				),
			).rejects.toBeInstanceOf(OAuthInvalidRequestException)
		})

		it('refuses a redirect_uri that merely starts with a registered one', async () => {
			await expect(
				service.authorize(
					authorizeRequest({
						redirectUri: `${REDIRECT_URI}.evil.com`,
					}),
				),
			).rejects.toBeInstanceOf(OAuthInvalidRequestException)
		})

		it('refuses the plain challenge method', async () => {
			await expect(
				service.authorize(
					authorizeRequest({
						codeChallengeMethod: 'plain',
					}),
				),
			).rejects.toBeInstanceOf(OAuthInvalidRequestException)
		})

		it('refuses a malformed challenge', async () => {
			await expect(
				service.authorize(
					authorizeRequest({
						codeChallenge: 'nope',
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
				clientId: 'web',
				code: await issueCode(),
				codeVerifier: verifier,
				redirectUri: REDIRECT_URI,
			})

			expect(session.accessToken).toBe('access')
			expect(session.refreshToken).toBe('refresh')
			expect(session.expiresAt).toBeGreaterThan(Date.now())
		})

		it('refuses a wrong verifier', async () => {
			await expect(
				service.exchangeCode({
					clientId: 'web',
					code: await issueCode(),
					codeVerifier: randomBytes(32).toString('base64url'),
					redirectUri: REDIRECT_URI,
				}),
			).rejects.toBeInstanceOf(OAuthInvalidGrantException)
		})

		it('burns the code on a wrong verifier, leaving nothing to guess against', async () => {
			const code = await issueCode()

			await expect(
				service.exchangeCode({
					clientId: 'web',
					code,
					codeVerifier: randomBytes(32).toString('base64url'),
					redirectUri: REDIRECT_URI,
				}),
			).rejects.toBeInstanceOf(OAuthInvalidGrantException)

			await expect(
				service.exchangeCode({
					clientId: 'web',
					code,
					codeVerifier: verifier,
					redirectUri: REDIRECT_URI,
				}),
			).rejects.toBeInstanceOf(OAuthInvalidGrantException)
		})

		it('answers a code exactly once', async () => {
			const code = await issueCode()
			const input = {
				clientId: 'web',
				code,
				codeVerifier: verifier,
				redirectUri: REDIRECT_URI,
			}

			await service.exchangeCode(input)

			await expect(service.exchangeCode(input)).rejects.toBeInstanceOf(
				OAuthInvalidGrantException,
			)
		})

		it('refuses a code presented by a different client', async () => {
			await expect(
				service.exchangeCode({
					clientId: 'admin',
					code: await issueCode(),
					codeVerifier: verifier,
					redirectUri: REDIRECT_URI,
				}),
			).rejects.toBeInstanceOf(OAuthInvalidGrantException)
		})

		it('refuses a code redeemed against a different redirect_uri', async () => {
			await expect(
				service.exchangeCode({
					clientId: 'web',
					code: await issueCode(),
					codeVerifier: verifier,
					redirectUri: OTHER_URI,
				}),
			).rejects.toBeInstanceOf(OAuthInvalidGrantException)
		})

		it('refuses a code that never existed', async () => {
			await expect(
				service.exchangeCode({
					clientId: 'web',
					code: 'invented',
					codeVerifier: verifier,
					redirectUri: REDIRECT_URI,
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
				clientId: 'web',
				code: back.searchParams.get('code') as string,
				codeVerifier: verifier,
				redirectUri: REDIRECT_URI,
			})

			expect(tokens.issueTokens).toHaveBeenCalledWith('user-1', {
				workspaceId: 'ws-1',
			})
		})
	})

	describe('refresh', () => {
		it('mints a new session from a valid refresh token', async () => {
			const session = await service.refresh('refresh')

			expect(session.accessToken).toBe('access')
			expect(tokens.verifyRefreshToken).toHaveBeenCalledWith('refresh')
		})

		it('propagates the rejection when the refresh token does not verify', async () => {
			vi.mocked(tokens.verifyRefreshToken).mockRejectedValueOnce(
				new Error('nope'),
			)

			await expect(service.refresh('bad')).rejects.toThrow()
		})
	})
})
