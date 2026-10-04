# pathos-auth

Accounts, sessions and token issuing for lambda. Users sign up only by invite,
other services verify access tokens against the public JWKS.

Spring Boot 4, Java 21, PostgreSQL, Flyway.

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
| PATCH | `/api/users/{id}` | admin | `{enabled}`; disabling revokes the user's sessions |
| GET | `/.well-known/jwks.json` | anyone | public signing key |
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
| `PATHOS_AUTH_JWT_KEY` | — | path to an RSA private key, PKCS#8 PEM |
| `PATHOS_AUTH_JWT_ISSUER` | `http://localhost:8081` | must match what verifiers expect |
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

The whole stack (auth, core, web, PostgreSQL) is deployed by `lambda-deploy`.
