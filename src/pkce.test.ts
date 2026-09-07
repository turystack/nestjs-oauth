import { createHash, randomBytes } from 'node:crypto'

import { describe, expect, it } from 'vitest'

import {
	deriveChallenge,
	isValidCodeChallenge,
	isValidCodeVerifier,
	randomToken,
	verifyChallenge,
} from '@/pkce.js'

const verifier = randomBytes(32).toString('base64url')

describe('deriveChallenge', () => {
	it('is the base64url SHA-256 of the verifier, as S256 requires', () => {
		expect(deriveChallenge(verifier)).toBe(
			createHash('sha256').update(verifier).digest('base64url'),
		)
	})
})

describe('isValidCodeVerifier', () => {
	it('accepts the shortest and longest lengths the spec allows', () => {
		expect(isValidCodeVerifier('a'.repeat(43))).toBe(true)
		expect(isValidCodeVerifier('a'.repeat(128))).toBe(true)
	})

	it('rejects a verifier short enough to guess', () => {
		expect(isValidCodeVerifier('a'.repeat(42))).toBe(false)
	})

	it('rejects one longer than the spec allows', () => {
		expect(isValidCodeVerifier('a'.repeat(129))).toBe(false)
	})

	it('rejects characters outside the unreserved set', () => {
		expect(isValidCodeVerifier(`${'a'.repeat(42)}/`)).toBe(false)
	})
})

describe('isValidCodeChallenge', () => {
	it('accepts a base64url SHA-256 digest', () => {
		expect(isValidCodeChallenge(deriveChallenge(verifier))).toBe(true)
	})

	it('rejects a padded or wrongly sized digest', () => {
		expect(isValidCodeChallenge(`${deriveChallenge(verifier)}=`)).toBe(false)
		expect(isValidCodeChallenge('short')).toBe(false)
	})

	it('rejects standard base64, which is what a plain method would send', () => {
		expect(isValidCodeChallenge('a'.repeat(42) + '+')).toBe(false)
	})
})

describe('verifyChallenge', () => {
	it('accepts the verifier the challenge was derived from', () => {
		expect(verifyChallenge(verifier, deriveChallenge(verifier))).toBe(true)
	})

	it('rejects a different verifier', () => {
		expect(
			verifyChallenge(
				randomBytes(32).toString('base64url'),
				deriveChallenge(verifier),
			),
		).toBe(false)
	})

	it('rejects a malformed verifier before hashing it', () => {
		expect(verifyChallenge('too-short', deriveChallenge(verifier))).toBe(false)
	})

	it('rejects a malformed challenge rather than comparing loosely', () => {
		expect(verifyChallenge(verifier, 'not-a-digest')).toBe(false)
	})

	it('rejects the plain verifier used as its own challenge', () => {
		expect(verifyChallenge(verifier, verifier)).toBe(false)
	})
})

describe('randomToken', () => {
	it('does not repeat across calls', () => {
		const tokens = new Set(
			Array.from({
				length: 200,
			}).map(() => randomToken()),
		)

		expect(tokens.size).toBe(200)
	})

	it('is url-safe, because it travels in a query string', () => {
		expect(randomToken()).toMatch(/^[A-Za-z0-9\-_]+$/u)
	})
})
