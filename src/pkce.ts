import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'

/** The only challenge method accepted. `plain` offers no protection at all. */
export const CODE_CHALLENGE_METHOD = 'S256'

const VERIFIER_PATTERN = /^[A-Za-z0-9\-._~]{43,128}$/u
const CHALLENGE_PATTERN = /^[A-Za-z0-9\-_]{43}$/u

export function isValidCodeVerifier(verifier: string): boolean {
	return VERIFIER_PATTERN.test(verifier)
}

export function isValidCodeChallenge(challenge: string): boolean {
	return CHALLENGE_PATTERN.test(challenge)
}

export function deriveChallenge(verifier: string): string {
	return createHash('sha256').update(verifier).digest('base64url')
}

/**
 * Whether the verifier presented at the token endpoint matches the challenge
 * recorded when the authorization started.
 *
 * The comparison is constant-time. A byte-by-byte compare that returns early
 * leaks, through timing, how much of the value was right, which is exactly the
 * feedback an attacker needs to guess the rest.
 */
export function verifyChallenge(verifier: string, challenge: string): boolean {
	if (!isValidCodeVerifier(verifier) || !isValidCodeChallenge(challenge)) {
		return false
	}

	const derived = Buffer.from(deriveChallenge(verifier))
	const expected = Buffer.from(challenge)

	if (derived.length !== expected.length) {
		return false
	}

	return timingSafeEqual(derived, expected)
}

/** A high-entropy opaque value, for a transaction id or an authorization code. */
export function randomToken(bytes = 32): string {
	return randomBytes(bytes).toString('base64url')
}
