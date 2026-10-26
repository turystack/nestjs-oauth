import type { ArgumentsHost } from '@nestjs/common'
import {
	AppError,
	BadRequestError,
	UnauthorizedError,
} from '@turystack/exceptions'
import { AppErrorTransform } from '@turystack/nestjs-server'
import { describe, expect, it } from 'vitest'

import {
	OAuthInvalidGrantException,
	OAuthInvalidRequestException,
} from '@/exceptions/oauth.exceptions.js'

function bodyOf(error: unknown): {
	body: unknown
	status: number
} {
	const sent: {
		body?: unknown
		status?: number
	} = {}
	const response = {
		headersSent: false,
		json(body: unknown) {
			sent.body = body
			return response
		},
		status(status: number) {
			sent.status = status
			return response
		},
	}
	const host = {
		switchToHttp: () => ({
			getResponse: () => response,
		}),
	} as unknown as ArgumentsHost

	new AppErrorTransform().catch(error, host)

	return {
		body: sent.body,
		status: sent.status ?? 0,
	}
}

describe('OAuth exceptions', () => {
	it('answers an invalid request as a 400 with oauth.invalid_request', () => {
		const error = new OAuthInvalidRequestException('Unknown client_id')

		expect(error).toBeInstanceOf(AppError)
		expect(error).toBeInstanceOf(BadRequestError)
		expect(error.name).toBe('OAuthInvalidRequestException')
		expect(OAuthInvalidRequestException.code).toBe('oauth.invalid_request')
		expect(bodyOf(error)).toEqual({
			body: {
				code: 'oauth.invalid_request',
				message: 'Unknown client_id',
				status_code: 400,
			},
			status: 400,
		})
		expect(bodyOf(error).body).not.toHaveProperty('statusCode')
	})

	it('answers an invalid grant as a 401 with oauth.invalid_grant', () => {
		const error = new OAuthInvalidGrantException()

		expect(error).toBeInstanceOf(AppError)
		expect(error).toBeInstanceOf(UnauthorizedError)
		expect(error.name).toBe('OAuthInvalidGrantException')
		expect(OAuthInvalidGrantException.code).toBe('oauth.invalid_grant')
		expect(bodyOf(error)).toEqual({
			body: {
				code: 'oauth.invalid_grant',
				message: 'Invalid or expired grant.',
				status_code: 401,
			},
			status: 401,
		})
	})
})
