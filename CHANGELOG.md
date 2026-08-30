# Changelog

## Unreleased

- **Added**
  - (placeholder)

- **Changed**
  - (placeholder)

- **Fixed**
  - (placeholder)

- **Security**
  - Pinned patched transitive npm dependencies to clear the current audit baseline.
  - Added fail-closed source and npm-package admission for the administrative contributor registry and pinned the CI/CD runtime to Node.js 24.18.0 LTS.
  - Pinned patched transitive build-tool dependencies for the current npm audit advisories.
  - (placeholder)

## [0.1.2] - 2026-07-13

- **Added**
  - (placeholder)

- **Changed**
  - Raised the minimum `@plasius/oauth2-core` dependency to `^0.1.1` so fresh
    installs and retained lockfiles consume the RFC-remediated core release for
    task `#4`.

- **Fixed**
  - (placeholder)

- **Security**
  - (placeholder)

## [0.1.1] - 2026-07-12

- **Added**
  - (placeholder)

- **Changed**
  - Access-token JWTs now use and require RFC 9068 `typ: at+jwt`.
  - DPoP-required configuration now fails closed instead of advertising an
    incomplete RFC 9449 implementation.

- **Fixed**
  - Confidential clients must authenticate before token exchange, and
    unsupported authorization response types now return
    `unsupported_response_type`.

- **Security**
  - (placeholder)

## [0.1.0] - 2026-07-02

- Added the initial zero-trust OAuth 2.1 issuer/resource-server engine.


[0.1.0]: https://github.com/Plasius-LTD/oauth2-issuer/releases/tag/v0.1.0
[0.1.1]: https://github.com/Plasius-LTD/oauth2-issuer/releases/tag/v0.1.1
[0.1.2]: https://github.com/Plasius-LTD/oauth2-issuer/releases/tag/v0.1.2
