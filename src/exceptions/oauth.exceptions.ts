import { BadRequestError, UnauthorizedError } from '@turystack/exceptions'

/**
 * A request that cannot be trusted enough to redirect anywhere. HTTP 400,
 * code `oauth.invalid_request`.
 *
 * An unknown `client_id` or a `redirect_uri` that is not registered must render
 * an error rather than bounce the browser: redirecting to an unvalidated URL is
 * the open redirect the registry exists to prevent, and it would hand the
 * attacker the very `code` this flow protects.
 *
 * A `BadRequestError` from `@turystack/exceptions`, serialized by
 * `AppErrorTransform` as `{ status_code: 400, code: 'oauth.invalid_request',
 * message }`.
 */
export class OAuthInvalidRequestException extends BadRequestError {
	static readonly code = 'oauth.invalid_request'

	override readonly name = 'OAuthInvalidRequestException'

	constructor(message = 'Invalid authorization request.') {
		super(message, undefined, OAuthInvalidRequestException.code)
	}
}

/**
 * A grant that was malformed, expired, already used, or not this client's.
 * HTTP 401, code `oauth.invalid_grant`.
 *
 * An `UnauthorizedError` from `@turystack/exceptions`, serialized by
 * `AppErrorTransform` as `{ status_code: 401, code: 'oauth.invalid_grant',
 * message }`.
 */
export class OAuthInvalidGrantException extends UnauthorizedError {
	static readonly code = 'oauth.invalid_grant'

	override readonly name = 'OAuthInvalidGrantException'

	constructor(message = 'Invalid or expired grant.') {
		super(message, undefined, OAuthInvalidGrantException.code)
	}
}
