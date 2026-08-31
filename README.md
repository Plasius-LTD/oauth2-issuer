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

Access-token JWTs are emitted and accepted only with `typ: at+jwt` (RFC 9068
§§2.1 and 4). Confidential clients are authenticated before authorization-code
or refresh-token exchange (RFC 6749 §§2.3.1 and 3.2.1).

`requireDpop: true` currently fails closed. The package does not advertise DPoP
because a presence check is not RFC 9449 proof validation; consumers must not
enable the mode until signature, method/URI, freshness, nonce/replay, `ath`, and
key-binding verification are implemented and released.

Runtime-visible rollout inherits
`governance.rfc-compliance-remediation.enabled`. Enabled consumers require the
correct token type and confidential-client credential. During a documented
migration window, disabling the flag may retain the prior verifier; rollback
also restores the prior package while existing short-lived tokens expire. DPoP
has no permissive fallback.

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

<!-- BEGIN PLASIUS RELEASE INTEGRITY -->
## Release integrity

CI keeps the administrative contributor registry outside Git and npm package
artifacts using exact, case-normalised path checks. CI runs on approved
GitHub-hosted runners for same-repository pull requests and `main`, with
package-manager cache finalization disabled; fork PR code is denied.
Publication uses the GitHub-hosted `production` job with Node 24 and a pinned
npm 11.6.2 client. It is token-free and proceeds only while the prepared SHA
is the exact `main` head after successful push-triggered CI. Do not dispatch CD
until the npm trusted-publisher binding is verified.
<!-- END PLASIUS RELEASE INTEGRITY -->
