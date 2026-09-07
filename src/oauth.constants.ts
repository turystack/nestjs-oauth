export const OAUTH_OPTIONS = Symbol('OAUTH_OPTIONS')
export const OAUTH_CODE_STORE = Symbol('OAUTH_CODE_STORE')

/** Seconds an authorization code stays usable, when nothing else is set. */
export const DEFAULT_CODE_TTL = 60

/** Seconds an unfinished authorization stays usable, when nothing else is set. */
export const DEFAULT_TRANSACTION_TTL = 600

/** Seconds the refresh cookie lives, when nothing else is set. */
export const DEFAULT_REFRESH_TTL = 604800

export const DEFAULT_ACCESS_COOKIE = 'session'
export const DEFAULT_REFRESH_COOKIE = 'refresh'
