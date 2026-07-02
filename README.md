# @plasius/oauth2-issuer

Zero-trust OAuth 2.1 authorization-server and resource-server engine with
injected persistence, key management, audit, clock, and randomness ports.

## Boundary

This package implements reusable OAuth state-machine behavior. It does not own
Plasius site routes, admin capability decisions, cookies, environment reads, or
production storage clients.

Consumers inject:

- storage
- key management
- audit sink
- clock
- random identifier source

## Default-Deny Policy

The engine denies by default:

- implicit grant
- password grant
- token-in-query usage
- wildcard redirects
- unknown clients
- missing PKCE
- non-S256 PKCE
- missing resource/audience
- unregistered scopes
- replayed authorization codes
- reused refresh tokens
- revoked access-token JTIs
- unsigned or unsupported JWTs

DPoP is supported as an optional resource-server profile. It is not mandatory
for ChatGPT v1 unless connector compatibility requires it.

## Development

```bash
npm install
npm run build
npm test
npm run test:coverage
npm run pack:check
```

## License

Apache-2.0
