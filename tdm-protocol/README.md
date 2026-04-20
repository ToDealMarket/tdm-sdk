# TDM Protocol Boundary

`mvp/tdm-protocol` is the public contract layer that sits between:

- public SDKs and integrations
- private gateway / treasury implementation

The goal is not to open-source every client-side detail.
The goal is to open the product plane and keep the control plane private.

## Public vs Private

Open these parts publicly:

- request and response schemas for stable external endpoints
- public error codes and machine-readable error shapes
- header names, auth modes, and payment-required response metadata
- public bridge descriptors such as checkout, buy, x402 listing, and MPP links
- stable type definitions shared by SDKs, docs, examples, and gateway responses

Keep these parts private:

- gateway internals
- treasury execution
- payout orchestration and settlement internals
- operator dashboards and unfinished setup UIs
- internal telemetry, audit, risk, and admin mutation flows
- local sandboxes, dev launchers, and experimental CLI surfaces

## Mental Model

Use the same split that companies like Stripe effectively use:

- public protocol: "what the outside world can rely on"
- public SDK: "ergonomic wrappers around that protocol"
- private control plane: "how the platform actually decides, executes, settles, audits, and recovers"

For TDM that means:

- `mvp/tdm-protocol` owns the stable external wire contract
- `mvp/tdm-sdk` owns developer UX around that contract
- `mvp/tdm-gateway` and `mvp/tdm-treasury-executor` stay private

## What Should Stay Public In `tdm-sdk`

These are good candidates for the public SDK because they help adoption, grants, and external analysis without exposing settlement internals:

- `runtime/gateway/*` client transport and auth wrappers
- `runtime/session/authorize.ts`
- `runtime/modes/framework-mode.ts`
- `domain/payments/make-payable.ts`
- `domain/payments/checkout.ts`
- wallet bridge server and wallet adapters
- local vault and local-first runtime helpers, if you want the local-agent story to be auditable
- examples, docs, and integration snippets

These are the parts that show the product:

- how a developer gates a resource
- how authorization is requested
- how checkout and bridge links are handled
- how an agent or app integrates TDM without learning your backend internals

## What Should Be Hidden Or Split Out From `tdm-sdk`

These are the highest-risk areas to leave in a public root package because they reveal control-plane shape, unfinished UX, or operator-only flows:

- `src/ui`
- `src/server-ui/setup`
- `dev`
- telemetry and update-check implementation details
- internal reports and operator diagnostics
- payout mutation flows that directly model private operational policy
- sweep, cashout, and treasury-adjacent automation
- local signer server if it is not yet a deliberate public product surface

More concretely, review these areas before treating them as public API:

- `src/domain/payments/payouts.ts`
- `src/domain/payments/cashout-workflow.ts`
- `src/domain/payments/cli-sweep-*`
- `src/domain/payments/adapters/BaseOdosSweeper.ts`
- `src/domain/payments/adapters/SolanaJupiterSweeper.ts`
- `src/runtime/session/local-signer-server.ts`
- `src/runtime/telemetry/*`
- `src/runtime/reports/*`
- most of `src/cli/commands/*` outside onboarding flows

## Current `tdm-sdk` Problem

Today `tdm-sdk` mixes three different responsibilities:

1. Public integration surface
2. Local runtime and UX helpers
3. Private-ish operator and experimental workflows

That makes the repo harder to open safely because publishing the whole SDK implies support and review of flows that are not really part of the public contract.

## Recommended Package Split

### 1. `tdm-protocol`

Move here the stable wire-level contract:

- authorize request and response types
- API envelope schemas
- gateway URL and path validation primitives
- bridge metadata types
- shared error codes
- stable public header constants
- x402-related response metadata

Good first extraction candidates from `tdm-sdk`:

- `src/runtime/gateway/gateway-schemas.ts`
- stable DTOs from `src/runtime/session/authorize.ts`
- stable bridge types from `src/runtime/gateway/fetch-hook-client.ts`
- stable response metadata from `src/runtime/modes/framework-mode.ts`

### 2. `tdm-sdk`

Keep this as the public developer package:

- framework integrations
- fetch hooks
- checkout helpers
- wallet bridge
- wallet adapters
- local vault if intentionally public
- ergonomic wrappers around `tdm-protocol`

This package should depend on `tdm-protocol`, not define the external contract itself.

### 3. Private control-plane repos

Keep private:

- `mvp/tdm-gateway`
- `mvp/tdm-treasury-executor`

Optionally also keep a private ops package if needed:

- `tdm-ops`
- `tdm-cli-internal`
- `tdm-runtime-private`

## Sanitization Rule

A simple rule helps:

If a type, route, or payload is visible to third-party developers, docs, or examples, it belongs in `tdm-protocol`.

If a module exists to:

- operate treasury
- mutate payout policy
- inspect private runtime state
- handle internal telemetry or audits
- support unfinished dashboards
- support experimental operator tooling

it should not be part of the public SDK root.

## Public Surface Policy

Before exporting anything from `tdm-sdk`, ask:

1. Is this part of the stable external contract?
2. Would we be comfortable documenting this publicly?
3. Would we be comfortable supporting this for outside developers?
4. Does publishing this reveal internal control-plane shape or policy?
5. Can this be replaced by a narrower type from `tdm-protocol`?

If the answer to 2, 3, or 4 is "no", keep it out of the public root.

## Recommended Near-Term Move

The safest near-term shape is:

- public GitHub repo for a sanitized `tdm-sdk`
- no `src/ui`
- no `src/server-ui/setup`
- no `dev`
- no treasury-adjacent sweep or cashout flows in the public root exports
- introduce `tdm-protocol` as the only place that defines external response shapes

That gives you a credible open-source surface for grants and external review without exposing private operational logic or unstable product areas.

## What Is Already Extracted Here

The current `tdm-protocol` package now holds the public contract source for:

- gateway URL and API path validation
- common API response envelope shape
- `POST /authorize` request shape
- authorization response shape
- checkout session request and response shapes
- session tank and delegated session shapes
- published payout request and wallet status shapes
- payment option descriptors
- bridge metadata returned to clients
- payment-required body shape for framework integrations
- public `X-TDM-*` payment-required response headers

Current entrypoint:

- `src/index.js`
- `src/index.d.ts`

Current `tdm-sdk` public modules already read these definitions from `tdm-protocol`:

- `src/runtime/gateway/gateway-schemas.ts`
- `src/runtime/session/authorize.ts`
- `src/domain/payments/checkout.ts`
- `src/runtime/session/session-tanks.ts`
- `src/domain/payments/payouts.ts`
- `src/runtime/gateway/fetch-hook-client.ts`
- `src/runtime/modes/framework-mode.ts`
