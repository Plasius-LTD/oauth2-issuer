# ADR-0003: Approved Self-Hosted CI and Hosted Publication

- Status: Accepted
- Date: 2026-10-21
- Task: Plasius-LTD/oauth2-issuer#9
- Parent Story: Plasius-LTD/plasius-ltd-site#1626
- Parent Feature: Plasius-LTD/plasius-ltd-site#1597
- Feature flag: `platform.public-artifact-integrity.enabled`

## Context

Hosted CI contradicted the task and parent Story. The repository is already
selected by the `Public CI - Quarantined` group, whose workflow allowlist admits
its exact `ci.yml@refs/heads/main`. Public self-hosted capacity must never execute
external-fork or pull-request-target head code. Publication requires a separate
GitHub-hosted OIDC identity.

## Decision

Both CI jobs run only on canonical-repository branch pushes using the literal
`Public CI - Quarantined` group and `[self-hosted, Linux, X64]` labels. Remove
pull-request/manual triggers, persist no checkout credentials, disable caching,
and bound job timeouts. Keep clean `npm ci`, lint, typecheck, audit, build, coverage
at 80% or higher, source admission and final package-manifest checks. Reuse existing
package/admission tooling and the demonstrated oauth2-core CI pattern; no runtime
or public API/dependency changes are needed.

Operators review each source and generated release-metadata branch before admitting
its exact workflow ref; they preserve selected repositories and all unrelated refs.
Remove temporary refs after successful validation. README documents the existing
metadata auto-merge behavior, exact reviewed SHA restoration for a deleted branch,
and the requirement to verify metadata/main CI before publication. Missing access
is a blocker and cannot justify hosted fallback or wildcard workflow admission.

Keep CD phase-isolated and hosted on literal `ubuntu-latest`, publishing only via
`production`, npm OIDC, immutable artifact digests and successful exact-main push
CI. Keep the approved release preparation flow; it owns package/lockfile versions
and changelog promotion. Choose an unused version and verify registry provenance,
manifest, digest and consumer behavior before completion.

The remote backend flag controls restoration only. Enabled, disabled and rollback
states all retain unconditional integrity checks. Disable the workflow/channel and
remove temporary refs for rollback; never restore the administrative path. There
is no user-visible capability change.

## Alternatives

Hosted CI fails the authoritative runner requirement. Pull-request CI with a fork
guard does not meet the parent Story's trusted-push-only boundary. Caller-selected
runners or broad workflow refs would weaken isolation. Replacing the package or
runtime code is unnecessary because the remaining mismatch is CI policy.

## Consequences and validation

Every source/release branch needs exact workflow admission and may wait for shared
runner capacity. Release preparation remains hosted; it is outside the CI call
graph, as is the existing scheduled monthly dependency-maintenance workflow.
No repository selection, visibility, branch protection or production policy change
is part of this task. Do not claim required reviews or checks exist when absent.

Workflow regressions fail against the prior hosted/PR-triggered CI, then enforce
the trusted event, every job's runner/permissions/timeout/cache/checkout boundary,
and retained quality/artifact gates. Validate baseline and final lint, types,
coverage, build, package, audits, strict dependencies and actionlint. Runtime
source is unchanged, so changed-runtime-file LCOV is N/A; combined runtime
coverage remains required. Accessibility, browser/SEO and ACA secret references
are N/A because this delivers an npm package workflow with no UI or deployment.
