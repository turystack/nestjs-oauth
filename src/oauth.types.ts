import type { ModuleMetadata, Type } from '@nestjs/common'

/**
 * One registered client — an application allowed to start an authorization.
 *
 * A public client (a browser SPA) holds no secret: anything shipped to the page
 * is readable, so a secret there proves nothing. What protects the exchange is
 * PKCE plus an exact-match `redirectUris` list, which is why both are required
 * rather than optional.
 */
export type OAuthClient = {
	id: string
	/** Exact absolute URLs. A prefix or wildcard match is an open redirect. */
	redirectUris: string[]
	scopes?: string[]
}

export type OAuthCookieOptions = {
	/** Cookie carrying the access token. Default `session`. */
	accessName?: string
	/** Cookie carrying the refresh token. Default `refresh`. */
	refreshName?: string
	domain?: string
	/** Default `/`. */
	path?: string
	/** Default `lax` — enough for a top-level redirect back from the login app. */
	sameSite?: 'lax' | 'none' | 'strict'
	/** Default `true`. Set false only for plain-HTTP local development. */
	secure?: boolean
}

export type OAuthOptions = {
	clients: OAuthClient[]
	/**
	 * Absolute URL of the login application. `/authorize` validates the request
	 * and then sends the browser here with the transaction id.
	 */
	signInUrl: string
	/** Seconds an authorization code stays usable. Default 60. */
	codeTtl?: number
	/** Seconds an unfinished authorization stays usable. Default 600. */
	transactionTtl?: number
	/**
	 * Seconds the refresh cookie lives. Default 604800 (7 days), matching
	 * `AccessModule`'s own `refreshExpiresIn` default — set both together, or the
	 * browser drops a token the API would still have accepted.
	 */
	refreshTtl?: number
	cookie?: OAuthCookieOptions
}

export type OAuthModuleOptions = OAuthOptions & {
	/** Replaces the in-memory store. Required for more than one API process. */
	store?: Type<OAuthCodeStore>
	imports?: ModuleMetadata['imports']
}

export type OAuthModuleFactoryOptions = Omit<OAuthModuleOptions, 'imports'>

/**
 * An authorization that has started and is waiting for the user to sign in.
 *
 * A stored record, so its keys are the model's snake_case — the spelling a
 * shared store writes to its table or hash, and the one the OAuth parameters
 * already use on the wire (`client_id`, `redirect_uri`, `code_challenge`).
 */
export type OAuthTransaction = {
	id: string
	client_id: string
	redirect_uri: string
	code_challenge: string
	state?: string
	scopes?: string[]
	/** Epoch milliseconds. */
	expires_at: number
}

/** An authorization the user completed, waiting to be exchanged for a session. */
export type OAuthAuthorizationCode = {
	code: string
	client_id: string
	redirect_uri: string
	code_challenge: string
	user_id: string
	workspace_id?: string
	/** Epoch milliseconds. */
	expires_at: number
}

/**
 * Where transactions and codes live between requests.
 *
 * The default implementation keeps them in memory, which is correct for one
 * process and wrong for two: a code issued by one instance cannot be redeemed
 * by another, and the failure looks like a random broken login. Any deployment
 * with more than one API process passes a shared store.
 */
export interface OAuthCodeStore {
	saveTransaction(transaction: OAuthTransaction): Promise<void>
	/** Reads without consuming — the user may reload the login screen. */
	readTransaction(id: string): Promise<OAuthTransaction | null>
	deleteTransaction(id: string): Promise<void>
	saveCode(code: OAuthAuthorizationCode): Promise<void>
	/** Consumes: a code answers once, and a replay finds nothing. */
	takeCode(code: string): Promise<OAuthAuthorizationCode | null>
}

/** The `/authorize` query, carried with the names RFC 6749 and RFC 7636 give it. */
export type OAuthAuthorizeRequest = {
	client_id: string
	redirect_uri: string
	code_challenge: string
	code_challenge_method: string
	state?: string
	scope?: string
}

/** The `/token` body: a code, the verifier for its challenge, and who redeems it. */
export type OAuthTokenRequest = {
	client_id: string
	code: string
	code_verifier: string
	redirect_uri: string
}

/**
 * A session as `AccessTokenService` minted it, with the lifetime turned into an
 * instant. The token keys are `TokenPair`'s, which are already RFC 6749's.
 */
export type OAuthSession = {
	access_token: string
	refresh_token: string
	/** Epoch milliseconds the access token stops being valid. */
	expires_at: number
}
