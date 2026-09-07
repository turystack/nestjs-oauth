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
apps/auth       →  OAuthService.completeAuthorization(tx, userId)
                                                   this package issues the code
apps/<product>  →  POST /api/v1/auth/token         this package sets the cookies
```

## Setup

Register it once, in the API root, beside `IamModule` — this module decides
*whether* a session may be issued, and `IamTokenService` is what mints it.

```ts
import { IamModule } from '@turystack/nestjs-iam'
import { OAuthModule } from '@turystack/nestjs-oauth'

@Module({
  imports: [
    ConfigModule.register({ schema: configSchema }),
    IamModule.register((config) => ({
      secret: config.get('IAM_SECRET'),
      permissions: PERMISSIONS,
      profileResolver: ProfileResolverService,
      // The web session arrives as a cookie; a mobile client keeps sending
      // Authorization: Bearer against the same API.
      tokenSource: 'both',
    })),
    OAuthModule.register((config) => ({
      clients: [
        { id: 'admin', redirectUris: ['https://admin.acme.com/callback'] },
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
| `store` | `Type<OAuthCodeStore>` | No | Replaces the in-memory store. **Required for more than one API process** |

## Routes

All under the `auth` prefix, so they land in the `auth` audience's own OpenAPI
document.

| Route | Purpose |
|---|---|
| `GET /authorize` | Validates client, redirect target and challenge, then redirects to `signInUrl` |
| `GET /transaction?tx=` | What the sign-in app shows: which client is asking, and where the browser goes next |
| `POST /token` | Exchanges a single-use code for the session cookies |
| `POST /refresh` | Rotates the refresh cookie into a new session |
| `POST /sign-out` | Expires both cookies in the browser |

Signing in itself is **not** here. The sign-in application authenticates the
person and then calls:

```ts
const redirectTo = await oauth.completeAuthorization(transactionId, user.id)
```

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

The only thing the page is told is `expiresAt`. That is enough to decide, on
reload and synchronously, whether to render the protected route or send the user
to sign in — which is what keeps a protected screen from flashing a login form.

## The store

The default keeps transactions and codes in this process's memory. That is
correct for one API process and wrong for two: a code issued by one instance
cannot be redeemed by another, and the symptom is a login that fails for roughly
half the users, intermittently.

Anything running more than one process implements `OAuthCodeStore` over shared
storage and passes it as `store`.

## Never do

- Registering a `redirect_uri` with a wildcard, or matching it by prefix.
- Accepting `code_challenge_method=plain`.
- Returning the tokens as JSON so the page can "keep them handy".
- Running more than one API process on the default in-memory store.
- Reusing one transaction to mint a second code.
