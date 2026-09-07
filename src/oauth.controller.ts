import { Body, Inject, Query, Req, Res } from '@nestjs/common'
import { Controller, Route } from '@turystack/nestjs-server'
import { z } from 'zod'

import { clearSessionCookies, writeSessionCookies } from '@/cookies.js'
import {
	DEFAULT_REFRESH_COOKIE,
	DEFAULT_REFRESH_TTL,
	OAUTH_OPTIONS,
} from '@/oauth.constants.js'
import { OAuthService } from '@/oauth.service.js'
import type { OAuthOptions, OAuthSession } from '@/oauth.types.js'

import { OAuthInvalidGrantException } from '@/exceptions/oauth.exceptions.js'

const authorizeQuery = z.object({
	client_id: z.string().min(1),
	code_challenge: z.string().min(1),
	code_challenge_method: z.string().min(1),
	redirect_uri: z.string().url(),
	scope: z.string().optional(),
	state: z.string().optional(),
})

const transactionQuery = z.object({
	tx: z.string().min(1),
})

const transactionResponse = z.object({
	clientId: z.string(),
	redirectUri: z.string(),
	scopes: z.array(z.string()).optional(),
})

const tokenBody = z.object({
	client_id: z.string().min(1),
	code: z.string().min(1),
	code_verifier: z.string().min(1),
	redirect_uri: z.string().url(),
})

/**
 * What the browser gets back instead of a token.
 *
 * The session itself is two httpOnly cookies, unreadable by the page. This is
 * the one thing the page is allowed to know: when the session stops being
 * valid, so a reload can decide which route to render without asking the API
 * first — which is what keeps a protected screen from flashing a login form.
 */
const sessionResponse = z.object({
	expiresAt: z.number(),
})

type ResponseLike = {
	getHeader?: (name: string) => number | string | string[] | undefined
	redirect: (url: string) => void
	setHeader: (name: string, value: string | string[]) => unknown
	status: (code: number) => ResponseLike
	send: (body?: unknown) => unknown
}

type RequestLike = {
	cookies?: Record<string, string | undefined>
	headers?: Record<string, string | string[] | undefined>
}

function readCookie(request: RequestLike, name: string): string | undefined {
	const parsed = request.cookies?.[name]

	if (parsed) {
		return parsed
	}

	const header = request.headers?.cookie

	if (typeof header !== 'string') {
		return undefined
	}

	for (const part of header.split(';')) {
		const separator = part.indexOf('=')

		if (separator === -1) {
			continue
		}

		if (part.slice(0, separator).trim() !== name) {
			continue
		}

		const value = part.slice(separator + 1).trim()

		return value.length > 0 ? decodeURIComponent(value) : undefined
	}

	return undefined
}

/**
 * The authorization server's HTTP surface.
 *
 * It carries the mechanics and none of the identity: signing in with a password
 * or with a social provider belongs to the product, which authenticates however
 * it likes and then calls `OAuthService.completeAuthorization`.
 */
@Controller({
	prefix: 'auth',
	tag: 'Auth',
})
export class OAuthController {
	constructor(
		@Inject(OAUTH_OPTIONS)
		private readonly options: OAuthOptions,
		@Inject(OAuthService)
		private readonly oauth: OAuthService,
	) {}

	@Route({
		description:
			'Validates the client, the redirect target and the PKCE challenge, then sends the browser to the sign-in application.',
		method: 'GET',
		parameters: {
			query: authorizeQuery,
		},
		path: 'authorize',
		summary: 'Start an authorization',
	})
	async authorize(
		@Query() query: z.infer<typeof authorizeQuery>,
		@Res() response: ResponseLike,
	): Promise<void> {
		const target = await this.oauth.authorize({
			clientId: query.client_id,
			codeChallenge: query.code_challenge,
			codeChallengeMethod: query.code_challenge_method,
			redirectUri: query.redirect_uri,
			...(query.scope === undefined
				? {}
				: {
						scope: query.scope,
					}),
			...(query.state === undefined
				? {}
				: {
						state: query.state,
					}),
		})

		response.redirect(target)
	}

	@Route({
		description:
			'What the sign-in application shows: which client is asking, and where the browser goes next.',
		method: 'GET',
		parameters: {
			query: transactionQuery,
		},
		path: 'transaction',
		responses: {
			200: transactionResponse,
		},
		summary: 'Read a pending authorization',
	})
	async transaction(
		@Query() query: z.infer<typeof transactionQuery>,
	): Promise<z.infer<typeof transactionResponse>> {
		const transaction = await this.oauth.readTransaction(query.tx)

		return {
			clientId: transaction.clientId,
			redirectUri: transaction.redirectUri,
			...(transaction.scopes === undefined
				? {}
				: {
						scopes: transaction.scopes,
					}),
		}
	}

	@Route({
		description:
			'Exchanges a single-use authorization code for a session, delivered as httpOnly cookies.',
		method: 'POST',
		parameters: {
			body: tokenBody,
		},
		path: 'token',
		responses: {
			200: sessionResponse,
		},
		summary: 'Exchange an authorization code',
	})
	async token(
		@Body() body: z.infer<typeof tokenBody>,
		@Res({
			passthrough: true,
		})
		response: ResponseLike,
	): Promise<z.infer<typeof sessionResponse>> {
		const session = await this.oauth.exchangeCode({
			clientId: body.client_id,
			code: body.code,
			codeVerifier: body.code_verifier,
			redirectUri: body.redirect_uri,
		})

		return this.deliver(response, session)
	}

	@Route({
		description:
			'Rotates the refresh cookie into a new session. The browser sends the cookie on its own.',
		method: 'POST',
		path: 'refresh',
		responses: {
			200: sessionResponse,
		},
		summary: 'Refresh the session',
	})
	async refresh(
		@Req() request: RequestLike,
		@Res({
			passthrough: true,
		})
		response: ResponseLike,
	): Promise<z.infer<typeof sessionResponse>> {
		const refreshToken = readCookie(
			request,
			this.options.cookie?.refreshName ?? DEFAULT_REFRESH_COOKIE,
		)

		if (!refreshToken) {
			throw new OAuthInvalidGrantException('No session to refresh.')
		}

		return this.deliver(response, await this.oauth.refresh(refreshToken))
	}

	@Route({
		description:
			'Expires both session cookies in the browser. Signing out has to reach the browser, not only the server.',
		method: 'POST',
		path: 'sign-out',
		responses: {
			204: {
				description: 'The session cookies were expired.',
			},
		},
		summary: 'Sign out',
	})
	async signOut(
		@Res({
			passthrough: true,
		})
		response: ResponseLike,
	): Promise<void> {
		clearSessionCookies(response, this.options.cookie ?? {})
	}

	private deliver(
		response: ResponseLike,
		session: OAuthSession,
	): {
		expiresAt: number
	} {
		writeSessionCookies(response, session, {
			...(this.options.cookie ?? {}),
			refreshMaxAge: this.options.refreshTtl ?? DEFAULT_REFRESH_TTL,
		})

		return {
			expiresAt: session.expiresAt,
		}
	}
}
