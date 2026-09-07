import { describe, expect, it } from 'vitest'

import {
	clearSessionCookies,
	serializeCookie,
	writeSessionCookies,
} from '@/cookies.js'

function createResponse() {
	const headers = new Map<string, string | string[]>()

	return {
		getHeader: (name: string) => headers.get(name),
		setHeader: (name: string, value: string | string[]) => {
			headers.set(name, value)
		},
		written: () => (headers.get('Set-Cookie') as string[]) ?? [],
	}
}

describe('serializeCookie', () => {
	it('is always HttpOnly, because a readable session is a stealable one', () => {
		expect(
			serializeCookie('session', 'value', {
				maxAge: 60,
			}),
		).toContain('HttpOnly')
	})

	it('is Secure unless explicitly turned off for local HTTP', () => {
		expect(
			serializeCookie('session', 'value', {
				maxAge: 60,
			}),
		).toContain('Secure')
		expect(
			serializeCookie('session', 'value', {
				maxAge: 60,
				secure: false,
			}),
		).not.toContain('Secure')
	})

	it('defaults to SameSite=Lax, which survives the redirect back from sign-in', () => {
		expect(
			serializeCookie('session', 'value', {
				maxAge: 60,
			}),
		).toContain('SameSite=Lax')
	})

	it('encodes the value so a token never breaks the header', () => {
		expect(
			serializeCookie('session', 'a b;c', {
				maxAge: 60,
			}),
		).toContain('session=a%20b%3Bc')
	})

	it('never writes a negative Max-Age', () => {
		expect(
			serializeCookie('session', 'value', {
				maxAge: -10,
			}),
		).toContain('Max-Age=0')
	})

	it('carries the domain when one is configured', () => {
		expect(
			serializeCookie('session', 'value', {
				domain: '.example.com',
				maxAge: 60,
			}),
		).toContain('Domain=.example.com')
	})
})

describe('writeSessionCookies', () => {
	it('writes both cookies, the refresh one outliving the access one', () => {
		const response = createResponse()

		writeSessionCookies(
			response,
			{
				accessToken: 'access',
				expiresAt: Date.now() + 900_000,
				refreshToken: 'refresh',
			},
			{
				refreshMaxAge: 604_800,
			},
		)

		const [access, refresh] = response.written()

		expect(access).toContain('session=access')
		expect(refresh).toContain('refresh=refresh')
		// The access cookie dies with the token it carries; the refresh cookie is
		// what lets the session continue past that moment.
		expect(access).toMatch(/Max-Age=(?:900|89\d)\b/u)
		expect(refresh).toContain('Max-Age=604800')
	})

	it('honours custom cookie names', () => {
		const response = createResponse()

		writeSessionCookies(
			response,
			{
				accessToken: 'access',
				expiresAt: Date.now() + 1000,
				refreshToken: 'refresh',
			},
			{
				accessName: 'acme_session',
				refreshMaxAge: 10,
				refreshName: 'acme_refresh',
			},
		)

		expect(response.written()[0]).toContain('acme_session=')
		expect(response.written()[1]).toContain('acme_refresh=')
	})

	it('appends to cookies another handler already set', () => {
		const response = createResponse()
		response.setHeader('Set-Cookie', 'other=1')

		writeSessionCookies(
			response,
			{
				accessToken: 'access',
				expiresAt: Date.now() + 1000,
				refreshToken: 'refresh',
			},
			{
				refreshMaxAge: 10,
			},
		)

		expect(response.written()).toHaveLength(3)
		expect(response.written()[0]).toBe('other=1')
	})
})

describe('clearSessionCookies', () => {
	it('expires both cookies, so signing out reaches the browser', () => {
		const response = createResponse()

		clearSessionCookies(response, {})

		expect(response.written()).toHaveLength(2)

		for (const cookie of response.written()) {
			expect(cookie).toContain('Max-Age=0')
			expect(cookie).toContain('HttpOnly')
		}
	})
})
