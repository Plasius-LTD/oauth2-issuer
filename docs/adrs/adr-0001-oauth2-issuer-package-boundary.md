# ADR 0001: OAuth 2 Issuer Package Boundary

## Status

Accepted.

## Context

Plasius needs a standards-aligned OAuth issuer for ChatGPT MCP account linking
without embedding the OAuth state machine directly inside `plasius-ltd-site`.

## Decision

Create `@plasius/oauth2-issuer` as a reusable authorization-server and
resource-server engine that consumes `@plasius/oauth2-core` primitives and
uses injected ports for storage, keys, audit, clock, and randomness.

The package provides in-memory adapters for tests, but production consumers
must provide durable ports and site-specific authorization checks.

## Consequences

- OAuth grant logic becomes reusable and testable outside one host app.
- Zero-trust defaults can be covered once and reused by site integrations.
- Site apps remain responsible for routing, user sessions, admin capability
  checks, rollout flags, rate limits, and operational audit policy.
