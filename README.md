# R!OTS Sovereign Centralized Identity Provider (`mw-rid`)

Centralized OIDC/OAuth2 Identity Provider and `@moonwitness/rid-sdk` implementing ADR-001.

## Architecture

- **`apps/id` (`@moonwitness/rid-server`)**: Standards-compliant OIDC Provider powered by `oidc-provider` + `jose` with Node 24 native SQLite (`node:sqlite`) persistence.
  - Asymmetric RS256 signing only (fails closed in `NODE_ENV=production` without `MW_RID_SIGNING_KEY_PEM` or `MW_RID_SIGNING_KEY_PATH`).
  - OIDC/OAuth2 endpoints: `/.well-known/openid-configuration`, `/jwks`, `/auth`, `/token`, `/me`, `/token/revocation`, `/health`.
  - Mandatory PKCE `S256` for public clients, exact redirect URI allowlist, rotating refresh tokens with replay detection, and `client_credentials` machine grants.
  - Identity & Outbox API:
    - `POST /api/bootstrap` — atomic one-time Platform Owner bootstrap (SHA-256 verifier hash, disabled immediately on first use).
    - `POST /api/accounts` — creates active account with `scrypt` salted password hash and opaque `rid_<uuid>` subject.
    - `POST /api/service-principals` — registers OAuth2 `client_credentials` machine clients with hashed secrets.
    - `GET /api/outbox` & `POST /api/outbox/:id/ack` — transactional `identity_outbox` lifecycle events (`account.created`, `account.disabled`, `grant.revoked`).
- **`packages/rid-sdk` (`@moonwitness/rid-sdk`)**: Resource-server verification and OIDC client helpers using only `jose` (zero private keys).
  - `verifyAccessToken({ token, issuer, audience, jwksUri })` — enforces `iss`, `aud`, `exp`, asymmetric algorithm allowlist, and rejects OIDC ID tokens.
  - `createPkcePair()` & `buildAuthorizationUrl(...)` — PKCE S256 helpers for `mw-board`, `mw-echo`, `mw-mylove`.

## Quick Start

```bash
npm install
npm test
```

Default port: `MW_RID_PORT=4480`.
