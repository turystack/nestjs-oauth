import {
	DEFAULT_ACCESS_COOKIE,
	DEFAULT_REFRESH_COOKIE,
} from '@/oauth.constants.js'
import type { OAuthCookieOptions, OAuthSession } from '@/oauth.types.js'

type CookieWritable = {
	getHeader?: (name: string) => number | string | string[] | undefined
	setHeader: (name: string, value: string | string[]) => unknown
}

type SerializeOptions = OAuthCookieOptions & {
	/** Seconds. `0` expires the cookie immediately. */
	maxAge: number
}

export function serializeCookie(
	name: string,
	value: string,
	options: SerializeOptions,
): string {
	const parts = [
		`${name}=${encodeURIComponent(value)}`,
		`Path=${options.path ?? '/'}`,
		`Max-Age=${Math.max(0, Math.floor(options.maxAge))}`,
		`SameSite=${(options.sameSite ?? 'lax').replace(/^./u, (first) => first.toUpperCase())}`,
		// HttpOnly is not configurable on purpose: a session a script can read is
		// a session a script can steal, and that is the whole reason the token is
		// delivered as a cookie instead of as JSON.
		'HttpOnly',
	]

	if (options.domain) {
		parts.push(`Domain=${options.domain}`)
	}

	if (options.secure !== false) {
		parts.push('Secure')
	}

	return parts.join('; ')
}

function append(response: CookieWritable, cookies: string[]): void {
	const existing = response.getHeader?.('Set-Cookie')
	const previous = Array.isArray(existing)
		? existing
		: typeof existing === 'string'
			? [
					existing,
				]
			: []

	response.setHeader('Set-Cookie', [
		...previous,
		...cookies,
	])
}

/**
 * Writes the session as two httpOnly cookies.
 *
 * The refresh cookie outlives the access cookie on purpose: when the access
 * token expires the browser still sends the refresh one, which is what lets the
 * session continue without the user seeing anything.
 */
export function writeSessionCookies(
	response: CookieWritable,
	session: OAuthSession,
	options: OAuthCookieOptions & {
		refreshMaxAge: number
	},
): void {
	const accessMaxAge = Math.max(
		0,
		Math.floor((session.expires_at - Date.now()) / 1000),
	)

	append(response, [
		serializeCookie(
			options.accessName ?? DEFAULT_ACCESS_COOKIE,
			session.access_token,
			{
				...options,
				maxAge: accessMaxAge,
			},
		),
		serializeCookie(
			options.refreshName ?? DEFAULT_REFRESH_COOKIE,
			session.refresh_token,
			{
				...options,
				maxAge: options.refreshMaxAge,
			},
		),
	])
}

/** Expires both cookies. Sign-out has to reach the browser, not only the store. */
export function clearSessionCookies(
	response: CookieWritable,
	options: OAuthCookieOptions,
): void {
	append(response, [
		serializeCookie(options.accessName ?? DEFAULT_ACCESS_COOKIE, '', {
			...options,
			maxAge: 0,
		}),
		serializeCookie(options.refreshName ?? DEFAULT_REFRESH_COOKIE, '', {
			...options,
			maxAge: 0,
		}),
	])
}
