import { Injectable } from '@nestjs/common'

import type {
	OAuthAuthorizationCode,
	OAuthCodeStore,
	OAuthTransaction,
} from '@/oauth.types.js'

/**
 * The default store: transactions and codes in this process's memory.
 *
 * It is correct for a single API process and wrong for two — a code issued by
 * one instance cannot be redeemed by another, and the symptom is a login that
 * fails for roughly half the users, intermittently. Anything running more than
 * one process passes its own `store`.
 *
 * Expiry is enforced on read as well as swept on write, because a store that
 * only sweeps grows without bound when nobody reads, and a store that only
 * checks on read hands out entries it should have forgotten.
 */
@Injectable()
export class MemoryOAuthCodeStore implements OAuthCodeStore {
	private readonly transactions = new Map<string, OAuthTransaction>()
	private readonly codes = new Map<string, OAuthAuthorizationCode>()

	async saveTransaction(transaction: OAuthTransaction): Promise<void> {
		this.sweep()
		this.transactions.set(transaction.id, transaction)
	}

	async readTransaction(id: string): Promise<OAuthTransaction | null> {
		const transaction = this.transactions.get(id)

		if (!transaction) {
			return null
		}

		if (transaction.expires_at <= Date.now()) {
			this.transactions.delete(id)

			return null
		}

		return transaction
	}

	async deleteTransaction(id: string): Promise<void> {
		this.transactions.delete(id)
	}

	async saveCode(code: OAuthAuthorizationCode): Promise<void> {
		this.sweep()
		this.codes.set(code.code, code)
	}

	async takeCode(code: string): Promise<OAuthAuthorizationCode | null> {
		const found = this.codes.get(code)

		// Deleted whether or not it is still valid: an expired code that stays
		// in the map is a value someone can keep probing.
		this.codes.delete(code)

		if (!found || found.expires_at <= Date.now()) {
			return null
		}

		return found
	}

	private sweep(): void {
		const now = Date.now()

		for (const [id, transaction] of this.transactions) {
			if (transaction.expires_at <= now) {
				this.transactions.delete(id)
			}
		}

		for (const [value, code] of this.codes) {
			if (code.expires_at <= now) {
				this.codes.delete(value)
			}
		}
	}
}
