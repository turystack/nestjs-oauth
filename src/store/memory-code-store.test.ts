import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import type { OAuthAuthorizationCode, OAuthTransaction } from '@/oauth.types.js'

import { MemoryOAuthCodeStore } from '@/store/memory-code-store.js'

function transaction(overrides: Partial<OAuthTransaction> = {}) {
	return {
		clientId: 'web',
		codeChallenge: 'challenge',
		expiresAt: Date.now() + 60_000,
		id: 'tx-1',
		redirectUri: 'https://app.example.com/callback',
		...overrides,
	} satisfies OAuthTransaction
}

function code(overrides: Partial<OAuthAuthorizationCode> = {}) {
	return {
		clientId: 'web',
		code: 'code-1',
		codeChallenge: 'challenge',
		expiresAt: Date.now() + 60_000,
		redirectUri: 'https://app.example.com/callback',
		userId: 'user-1',
		...overrides,
	} satisfies OAuthAuthorizationCode
}

describe('MemoryOAuthCodeStore', () => {
	let store: MemoryOAuthCodeStore

	beforeEach(() => {
		vi.useFakeTimers()
		store = new MemoryOAuthCodeStore()
	})

	afterEach(() => {
		vi.useRealTimers()
	})

	it('reads a transaction back without consuming it', async () => {
		await store.saveTransaction(transaction())

		expect(await store.readTransaction('tx-1')).not.toBeNull()
		expect(await store.readTransaction('tx-1')).not.toBeNull()
	})

	it('forgets a transaction once it expires', async () => {
		await store.saveTransaction(transaction())

		vi.advanceTimersByTime(60_001)

		expect(await store.readTransaction('tx-1')).toBeNull()
	})

	it('deletes a transaction on request, so one sign-in yields one code', async () => {
		await store.saveTransaction(transaction())
		await store.deleteTransaction('tx-1')

		expect(await store.readTransaction('tx-1')).toBeNull()
	})

	it('answers a code exactly once', async () => {
		await store.saveCode(code())

		expect(await store.takeCode('code-1')).not.toBeNull()
		expect(await store.takeCode('code-1')).toBeNull()
	})

	it('refuses an expired code and does not keep it around to probe', async () => {
		await store.saveCode(code())

		vi.advanceTimersByTime(60_001)

		expect(await store.takeCode('code-1')).toBeNull()
		expect(await store.takeCode('code-1')).toBeNull()
	})

	it('returns null for a code that never existed', async () => {
		expect(await store.takeCode('nothing')).toBeNull()
	})

	it('sweeps expired entries when something new is written', async () => {
		await store.saveCode(
			code({
				code: 'old',
			}),
		)
		await store.saveTransaction(
			transaction({
				id: 'old-tx',
			}),
		)

		vi.advanceTimersByTime(60_001)

		await store.saveCode(
			code({
				code: 'fresh',
				expiresAt: Date.now() + 60_000,
			}),
		)

		expect(await store.takeCode('old')).toBeNull()
		expect(await store.readTransaction('old-tx')).toBeNull()
		expect(await store.takeCode('fresh')).not.toBeNull()
	})
})
