# pathos-auth

Accounts of pathos: one sign-in for every service. Users sign up only by invite.

Two ways in:

- **API** for pathos' own pages (lambda, delta): `POST /api/auth/login` returns a token pair,
  other services verify the access token against the public JWKS.
- **Sign in with pathos** for services with accounts of their own (the forum): OAuth 2.0 /
  OpenID Connect, authorization code with PKCE. The service sends the visitor to
  `/oauth2/authorize`, the visitor signs in on this domain and comes back with a code.

An account gets into a service only if an admin let it in: each OAuth client names the
`access` it requires, an admin ticks it per account, admins get in everywhere. A refusal
goes back to the service as `error=access_denied`.

Spring Boot 4, Spring Authorization Server, Java 21, PostgreSQL, Flyway.

## API

| method | path | who | what |
|---|---|---|---|
| POST | `/api/auth/register` | anyone with an invite | `{inviteCode, username, password}` → token pair |
| POST | `/api/auth/login` | anyone | `{username, password}` → token pair |
| POST | `/api/auth/refresh` | anyone | `{refreshToken}` → new pair, old refresh token is burned |
| POST | `/api/auth/logout` | anyone | `{refreshToken}` → 204 |
| GET | `/api/auth/me` | user | `{id, username, role, enabled, createdAt}` |
| POST | `/api/auth/password` | user | `{currentPassword, newPassword}` → new pair, other sessions revoked |
| POST | `/api/invites` | admin | `{ttlDays?}` (1–30, default 7) → invite |
| GET | `/api/invites` | admin | own invites, newest first, with who used them |
| GET | `/api/users` | admin | all users |
| PATCH | `/api/users/{id}` | admin | `{enabled?, access?}`; disabling revokes the user's sessions |
| GET | `/api/users/services` | admin | names that can be ticked in `access` |
| GET | `/.well-known/jwks.json` | anyone | public signing key |
| GET | `/oauth2/authorize` | browser | start of "sign in with pathos" |
| POST | `/oauth2/token` | service | code + `code_verifier` → access token and id token |
| GET | `/userinfo` | service | `{sub, preferred_username, role, access}` |
| GET | `/.well-known/openid-configuration` | anyone | discovery |
| GET, POST | `/login`, `/logout` | browser | the sign-in page; eight misses rest a name for 15 minutes |
| GET | `/actuator/health` | anyone | liveness |

Token pair: `{accessToken, refreshToken, expiresIn}`. Access token is an RS256 JWT
with `sub` (user id), `username` and `role` (`USER` / `ADMIN`), 10 minutes by default.
Refresh tokens are opaque, stored hashed, single use; reusing a burned one revokes
every session of that user.

Errors are `application/problem+json`: 400 bad input, 401 wrong credentials or
token, 403 bad invite or not an admin, 409 username taken.

## Configuration

| variable | default | |
|---|---|---|
| `PATHOS_AUTH_DB_URL` | `jdbc:postgresql://localhost:5432/pathos_auth` | |
| `PATHOS_AUTH_DB_USER` / `PATHOS_AUTH_DB_PASSWORD` | `pathos_auth` | |
| `PATHOS_AUTH_PORT` | `8081` | |
| `PATHOS_AUTH_MANAGEMENT_PORT` | same as `PATHOS_AUTH_PORT` | where `/actuator/health` and `/actuator/prometheus` are served |
| `PATHOS_AUTH_OAUTH_CLIENTS_<ID>_SECRET` | — | an OAuth client; with `_REDIRECT_URIS` (comma separated) and `_ACCESS` (what an admin ticks, empty = everyone) |
| `PATHOS_AUTH_TRUSTED_PROXIES` | private ranges | regex of proxies whose `X-Forwarded-*` are believed |
| `PATHOS_AUTH_JWT_KEY` | — | path to an RSA private key, PKCS#8 PEM |
| `PATHOS_AUTH_JWT_ISSUER` | `http://localhost:8081` | the public address, e.g. `https://auth.pathos.su`; verifiers expect exactly it |
| `PATHOS_AUTH_JWT_KEY_ID` | `pathos-auth-1` | |
| `PATHOS_AUTH_JWT_ACCESS_TTL` | `10m` | |
| `PATHOS_AUTH_REFRESH_TTL` | `30d` | |
| `PATHOS_AUTH_ADMIN_USERNAME` / `PATHOS_AUTH_ADMIN_PASSWORD` | empty | first admin, created only while there is no admin |

Key:

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out jwt.pem
```

## Run

```sh
./mvnw test                       # needs Docker for Testcontainers
docker build -t pathos-auth .
```

Deployed by `lambda-deploy` next to lambda, published as `auth.pathos.su`.
