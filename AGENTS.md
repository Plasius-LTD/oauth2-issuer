# AGENTS.md

## Scope
- This repository is `@plasius/oauth2-issuer`, a reusable zero-trust OAuth authorization-server and resource-server engine built on injected storage, key-management, audit, clock, randomness, logger, consent, and subject-resolution ports.
- Keep site-specific ChatGPT, MCP, widget, Plasius admin, and HTTP route wiring out of this package.

## Tooling
- Use Node.js 24, npm, TypeScript, Vitest, ESLint, and tsup.
- Install with `npm ci`.
- Common checks:
  - `npm run lint`
  - `npm run typecheck`
  - `npm run test:coverage`
  - `npm run build`
  - `npm run pack:check`

## Packaging
- Publish only through approved GitHub CD workflows. Do not run `npm publish` locally.
- Depend on `@plasius/oauth2-core` through its npm package version, not `file:` or workspace-local dependencies.
- Generated output in `dist/`, `coverage/`, and `node_modules/` must not be committed.

## Quality
- Add or update tests for changed behavior and keep coverage at or above 80%.
- Public API changes require README, CHANGELOG, and ADR updates where applicable.
- Every token, authorization code, refresh grant, key, and client secret path must preserve revocation, replay detection, auditability, and least-privilege defaults.
- Never include secrets, real PII, tokens, authorization codes, refresh tokens, or private keys in examples, tests, logs, fixtures, or docs.
