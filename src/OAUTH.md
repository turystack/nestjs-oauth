# OAuth

Authorization Code + PKCE for NestJS. The session leaves as two httpOnly
cookies, so a script on the page has no token to steal.

## What it owns, and what it does not

It owns the **mechanics**: who may start a flow, whether a redirect target is
registered, what an authorization code is worth, and how a code becomes a
session.

It deliberately does not know **who the user is**. Checking a password,
verifying a social provider's ID token and looking a person up belong to the
product's identity domain. The seam is one call:

```text
apps/<product>  →  GET  /api/v1/auth/authorize     this package validates
                                                   and redirects
apps/auth       →  authenticates however it likes  YOUR code
apps/auth       →  OAuthService.completeAuthorization(tx, user.user_id)
                                                   this package issues the code
apps/<product>  →  POST /api/v1/auth/token         this package sets the cookies
```

## Setup

Register it once, in the API root, beside `AccessModule` — this module decides
*whether* a session may be issued, and `AccessTokenService` is what mints it.

```ts
import { AccessModule } from '@turystack/nestjs-access'
import { OAuthModule } from '@turystack/nestjs-oauth'

@Module({
  imports: [
    ConfigModule.register({ schema: configSchema }),
    AccessModule.register((config) => ({
      secret: config.get('ACCESS_SECRET'),
      permissions: PERMISSIONS,
      profileResolver: ProfileResolverService,
      // The web session arrives as a cookie; a server-to-server client or a CLI
      // sends Authorization: Bearer against the same API.
      tokenSource: 'both',
    })),
    OAuthModule.register((config) => ({
      clients: [
        { id: 'console', redirectUris: ['https://console.acme.com/callback'] },
        { id: 'app', redirectUris: ['https://app.acme.com/callback'] },
      ],
      signInUrl: config.get('AUTH_APP_URL'),
    })),
  ],
})
export class AppModule {}
```

### OAuthModuleOptions

| Property | Type | Required | Description |
|---|---|---|---|
| `clients` | `OAuthClient[]` | Yes | Registered clients. Each carries exact `redirectUris` |
| `signInUrl` | `string` | Yes | Absolute URL of the sign-in application |
| `codeTtl` | `number` | No | Seconds an authorization code stays usable. Default `60` |
| `transactionTtl` | `number` | No | Seconds an unfinished authorization stays usable. Default `600` |
| `refreshTtl` | `number` | No | Seconds the refresh cookie lives. Default `604800` |
| `cookie` | `OAuthCookieOptions` | No | Names, domain, `SameSite`, `Secure` |
| `store` | `Type<OAuthCodeStore>` | No | Replaces the in-memory store. **Required for more than one API process**. Works in both forms: the factory's `store` is built once the factory runs, with its dependencies injected and its lifecycle hooks called |

## Routes

All under the `auth` prefix, so they land in the `auth` audience's own OpenAPI
document.

| Route | Purpose |
|---|---|
| `GET /authorize` | Validates client, redirect target and challenge, then redirects to `signInUrl` |
| `GET /transaction?tx=` | What the sign-in app shows: `client_id`, `redirect_uri`, `scopes` |
| `POST /token` | Exchanges a single-use code for the session cookies; answers `{ expires_at }` |
| `POST /refresh` | Rotates the refresh cookie into a new session; answers `{ expires_at }` |
| `POST /sign-out` | Expires both cookies in the browser |

Signing in itself is **not** here. The sign-in application authenticates the
person and then calls:

```ts
const redirectTo = await oauth.completeAuthorization(transactionId, user.user_id)

// A session minted for one workspace. A refresh keeps it on that workspace.
await oauth.completeAuthorization(transactionId, user.user_id, {
  workspaceId: membership.workspace_id,
})
```

The arguments are camelCase because they are arguments — the same seam
`AccessTokenService.issueTokens(userId, { workspaceId })` draws. Everything that is
a record is snake_case: the query and body carry RFC 6749's own names
(`client_id`, `redirect_uri`, `code_verifier`), `OAuthSession` mirrors
`TokenPair` (`access_token`, `refresh_token`) with `expires_at` in place of
`expires_in`, and the store keeps `OAuthTransaction` and
`OAuthAuthorizationCode` under the same keys.

## Errors

| Exception | HTTP | `code` | When |
|---|---|---|---|
| `OAuthInvalidRequestException` | 400 | `oauth.invalid_request` | Unknown `client_id`, unregistered `redirect_uri`, a `code_challenge_method` other than `S256`, a malformed `code_challenge` |
| `OAuthInvalidGrantException` | 401 | `oauth.invalid_grant` | A code or transaction that is unknown, expired, already used or another client's; a wrong verifier; no refresh cookie |

Both are `AppError`s from `@turystack/exceptions` (`BadRequestError` /
`UnauthorizedError`), not Nest `HttpException`s. The global
`AppErrorTransform` of `Server.create` (`@turystack/nestjs-server`) answers
them as `{ status_code, code, message }` — e.g.
`{ "status_code": 401, "code": "oauth.invalid_grant", "message": "Invalid or expired grant." }`.
The client translates by `code`, under the `oauth` namespace; the `message`
is English for a developer reading the response.

## What is enforced, and why

- **PKCE is mandatory, `S256` only.** A public client ships no secret — anything
  in the page is readable — so the verifier is what proves the app redeeming the
  code is the app that started the flow. `plain` proves nothing and is refused.
- **`redirect_uri` matches exactly.** Prefix or wildcard matching turns the
  authorization endpoint into an open redirect, and what it would carry is the
  code itself.
- **Validation happens before any redirect.** An unknown client or an
  unregistered target renders an error rather than bouncing the browser
  somewhere unvalidated.
- **A code answers once.** It is consumed on read, *before* the verifier is
  checked, so a wrong guess burns it instead of leaving it to guess again.
- **A transaction is spent when it completes.** One sign-in produces one code.
- **The cookies are always `HttpOnly`.** That is not configurable: a session the
  page can read is a session a script can exfiltrate, which is the whole reason
  the token is delivered as a cookie instead of as JSON.

The only thing the page is told is `expires_at`. That is enough to decide, on
reload and synchronously, whether to render the protected route or send the user
to sign in — which is what keeps a protected screen from flashing a login form.

## The store

The default keeps transactions and codes in this process's memory. That is
correct for one API process and wrong for two: a code issued by one instance
cannot be redeemed by another, and the symptom is a login that fails for roughly
half the users, intermittently.

Anything running more than one process implements `OAuthCodeStore` over shared
storage and passes it as `store` — in the object form or returned by the
`(config) => options` factory, which is where its connection settings usually
come from. The records arrive snake_case
(`client_id`, `code_challenge`, `user_id`, `workspace_id`, `expires_at`), so a
table or hash can take the keys as its columns without re-casing them.

## Never do

- Registering a `redirect_uri` with a wildcard, or matching it by prefix.
- Accepting `code_challenge_method=plain`.
- Returning the tokens as JSON so the page can "keep them handy".
- Running more than one API process on the default in-memory store.
- Reusing one transaction to mint a second code.
