import { BadRequestException, UnauthorizedException } from '@nestjs/common'

/**
 * A request that cannot be trusted enough to redirect anywhere.
 *
 * An unknown `client_id` or a `redirect_uri` that is not registered must render
 * an error rather than bounce the browser: redirecting to an unvalidated URL is
 * the open redirect the registry exists to prevent, and it would hand the
 * attacker the very `code` this flow protects.
 */
export class OAuthInvalidRequestException extends BadRequestException {
	constructor(message = 'Invalid authorization request.') {
		super(message)
		this.name = 'OAuthInvalidRequestException'
	}
}

/** A grant that was malformed, expired, already used, or not this client's. */
export class OAuthInvalidGrantException extends UnauthorizedException {
	constructor(message = 'Invalid or expired grant.') {
		super(message)
		this.name = 'OAuthInvalidGrantException'
	}
}
