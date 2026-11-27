# mw-rid — Sovereign OIDC/OAuth2 identity provider and TypeScript SDK.

**Repository:** [`A-L-L-A-H/mw-rid`](https://github.com/A-L-L-A-H/mw-rid) · **Stack:** TypeScript · Node 24 · SQLite

## What it does

Implements mandatory PKCE S256, RS256 signing with JWKS, rotating refresh tokens, service principals, Google OAuth, and bootstrap admin flows.

## Quick start

```bash
npm install
npm run build
npm run start
```

## Verify

```bash
npm test
```

## Configuration

- **Port:** 4480
- **Key configuration:** MW_RID_PORT · MW_RID_ISSUER · MW_RID_SIGNING_KEY_PATH

## Notes

Production fails closed without an RS256 signing key. Bootstrap uses MW_RID_BOOTSTRAP_SECRET once.
