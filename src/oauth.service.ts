import { Inject, Injectable } from '@nestjs/common'
import { IamTokenService } from '@turystack/nestjs-iam'

import {
	DEFAULT_CODE_TTL,
	DEFAULT_TRANSACTION_TTL,
	OAUTH_CODE_STORE,
	OAUTH_OPTIONS,
} from '@/oauth.constants.js'
import type {
	OAuthAuthorizeRequest,
	OAuthClient,
	OAuthCodeStore,
	OAuthOptions,
	OAuthSession,
	OAuthTransaction,
} from '@/oauth.types.js'
import {
	CODE_CHALLENGE_METHOD,
	isValidCodeChallenge,
	randomToken,
	verifyChallenge,
} from '@/pkce.js'

import {
	OAuthInvalidGrantException,
	OAuthInvalidRequestException,
} from '@/exceptions/oauth.exceptions.js'

/**
 * The authorization server's mechanics: who may start a flow, what a code is
 * worth, and how a code becomes a session.
 *
 * What it deliberately does not know is **who the user is**. Checking a
 * password, verifying a provider's ID token and looking a person up all belong
 * to the product's identity domain. The seam is `completeAuthorization`: the
 * login application authenticates however it likes and then says "this
 * transaction belongs to this user", and this service turns that into a code.
 */
@Injectable()
export class OAuthService {
	constructor(
		@Inject(OAUTH_OPTIONS)
		private readonly options: OAuthOptions,
		@Inject(OAUTH_CODE_STORE)
		private readonly store: OAuthCodeStore,
		// Injected by explicit token rather than by reflected type: a
		// type-only import erases the runtime reference `emitDecoratorMetadata`
		// depends on, and the failure would only appear when the module boots.
		@Inject(IamTokenService)
		private readonly tokens: IamTokenService,
	) {}

	/**
	 * Validates an authorization request and returns where to send the browser.
	 *
	 * Everything checked here is checked *before* any redirect happens, because
	 * an unvalidated `redirect_uri` is an open redirect and the thing it would
	 * carry is the authorization code.
	 */
	async authorize(request: OAuthAuthorizeRequest): Promise<string> {
		if (request.codeChallengeMethod !== CODE_CHALLENGE_METHOD) {
			throw new OAuthInvalidRequestException(
				`code_challenge_method must be ${CODE_CHALLENGE_METHOD}`,
			)
		}

		if (!isValidCodeChallenge(request.codeChallenge)) {
			throw new OAuthInvalidRequestException('code_challenge is malformed')
		}

		const client = this.findClient(request.clientId)

		if (!client.redirectUris.includes(request.redirectUri)) {
			throw new OAuthInvalidRequestException(
				'redirect_uri is not registered for this client',
			)
		}

		const transaction: OAuthTransaction = {
			clientId: client.id,
			codeChallenge: request.codeChallenge,
			expiresAt:
				Date.now() +
				(this.options.transactionTtl ?? DEFAULT_TRANSACTION_TTL) * 1000,
			id: randomToken(),
			redirectUri: request.redirectUri,
			...(request.state === undefined
				? {}
				: {
						state: request.state,
					}),
			...(request.scope
				? {
						scopes: request.scope.split(' ').filter(Boolean),
					}
				: {}),
		}

		await this.store.saveTransaction(transaction)

		const url = new URL(this.options.signInUrl)
		url.searchParams.set('tx', transaction.id)

		return url.toString()
	}

	/** What the login application reads to show who is signing in, and where to. */
	async readTransaction(id: string): Promise<OAuthTransaction> {
		const transaction = await this.store.readTransaction(id)

		if (!transaction) {
			throw new OAuthInvalidGrantException(
				'This sign-in request expired. Start again from the application.',
			)
		}

		return transaction
	}

	/**
	 * The login application says who the user is; this issues the code and
	 * returns the URL to send the browser back to.
	 */
	async completeAuthorization(
		transactionId: string,
		userId: string,
		options?: {
			workspaceId?: string
		},
	): Promise<string> {
		const transaction = await this.readTransaction(transactionId)
		const code = randomToken()

		await this.store.saveCode({
			clientId: transaction.clientId,
			code,
			codeChallenge: transaction.codeChallenge,
			expiresAt: Date.now() + (this.options.codeTtl ?? DEFAULT_CODE_TTL) * 1000,
			redirectUri: transaction.redirectUri,
			userId,
			...(options?.workspaceId === undefined
				? {}
				: {
						workspaceId: options.workspaceId,
					}),
		})
		// The transaction is spent: one sign-in produces one code, so a replayed
		// transaction id cannot mint a second.
		await this.store.deleteTransaction(transaction.id)

		const url = new URL(transaction.redirectUri)
		url.searchParams.set('code', code)

		if (transaction.state !== undefined) {
			url.searchParams.set('state', transaction.state)
		}

		return url.toString()
	}

	/**
	 * Exchanges a code for a session.
	 *
	 * The code is consumed before anything else is checked, so a wrong verifier
	 * burns the code rather than leaving it available for another guess.
	 */
	async exchangeCode(input: {
		clientId: string
		code: string
		codeVerifier: string
		redirectUri: string
	}): Promise<OAuthSession> {
		const grant = await this.store.takeCode(input.code)

		if (!grant) {
			throw new OAuthInvalidGrantException()
		}

		if (
			grant.clientId !== input.clientId ||
			grant.redirectUri !== input.redirectUri
		) {
			throw new OAuthInvalidGrantException()
		}

		if (!verifyChallenge(input.codeVerifier, grant.codeChallenge)) {
			throw new OAuthInvalidGrantException()
		}

		return this.issue(grant.userId, grant.workspaceId)
	}

	/** Rotates a refresh token into a new session. */
	async refresh(refreshToken: string): Promise<OAuthSession> {
		const { userId, workspaceId } =
			await this.tokens.verifyRefreshToken(refreshToken)

		return this.issue(userId, workspaceId)
	}

	private async issue(
		userId: string,
		workspaceId?: string,
	): Promise<OAuthSession> {
		const pair = await this.tokens.issueTokens(
			userId,
			workspaceId === undefined
				? undefined
				: {
						workspaceId,
					},
		)

		return {
			accessToken: pair.accessToken,
			expiresAt: Date.now() + pair.expiresIn * 1000,
			refreshToken: pair.refreshToken,
		}
	}

	private findClient(clientId: string): OAuthClient {
		const client = this.options.clients.find(
			(candidate) => candidate.id === clientId,
		)

		if (!client) {
			throw new OAuthInvalidRequestException('Unknown client_id')
		}

		return client
	}
}
