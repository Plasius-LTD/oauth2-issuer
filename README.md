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
artifacts using exact, case-normalised path checks. CI runs only for repository branch pushes on the approved
`Public CI - Quarantined` runner group with explicit `[self-hosted, Linux, X64]`
labels. Both jobs require the canonical repository and a push event. Pull-request
and manual triggers are absent, so external-fork code cannot reach this capacity.
Checkouts do not persist credentials, package-manager caching is disabled, and
both jobs have bounded timeouts. There is no hosted CI fallback or caller-selected
runner. CI retains clean lockfile installation, lint, type checks, runtime audit,
build, the 80% line-coverage gate, and final package-manifest admission.
Publication uses the GitHub-hosted `production` job with Node 24 and a pinned
npm 11.6.2 client. It is token-free and proceeds only while the prepared SHA
is the exact `main` head after successful push-triggered CI. Do not dispatch CD
until the npm trusted-publisher binding is verified.

Before pushing a reviewed source branch, an authorised runner-group operator must
admit only `Plasius-LTD/oauth2-issuer/.github/workflows/ci.yml@refs/heads/<branch>`
to the existing workflow allowlist. Preserve the group's selected repositories,
public-repository policy and all other admitted refs. `main` remains admitted.
Inspect the release-preparation App's generated metadata PR and exact diff before
admitting its exact branch; run its CI and required reviews/checks before merging
when the repository policy holds the PR open. The existing release workflow may
auto-merge metadata immediately under a policy with no required checks. In that
case, verify the exact merged metadata diff and successful metadata/main CI before
publication; do not describe that as a protected review gate. If the App deleted
the branch, restoring only its reviewed, unchanged PR-head SHA with an ordinary
non-force push to the same absent branch allows the queued CI to run. Remove
temporary source/metadata admissions and branches after successful checks.
Missing runner access is a blocker; do not broaden admission with wildcards or
change repository/production protections to make a release pass.

`platform.public-artifact-integrity.enabled` controls staged distribution
restoration through the remote backend evaluator. All source, artifact and release
checks remain mandatory whether enabled, disabled or rolled back. Disabling the
flag stops restoration; it never bypasses admission. Operational rollback disables
the affected workflow/channel and removes temporary branch admissions, without
restoring the administrative path or introducing hosted CI. No capability is
needed because there is no user-visible entitlement surface.
<!-- END PLASIUS RELEASE INTEGRITY -->
