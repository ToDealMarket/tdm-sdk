<div align="center">

# TDM SDK

<img src="https://img.shields.io/badge/TDM-SDK-ff69b4?style=for-the-badge" alt="TDM SDK" />

**Open contract-facing SDK for payable routes and gateway-backed integrations**

[![npm](https://img.shields.io/badge/npm-tdm--sdk-ff69b4?style=flat-square&logo=npm&logoColor=white)](https://www.npmjs.com/package/tdm-sdk)
[![License: MIT](https://img.shields.io/badge/License-MIT-ff69b4?style=flat-square)](./LICENSE)

*Thin public surface for payable code, authorize, checkout, and session-tank flows*

[Documentation](https://todealmarket.com/docs) • [SDK Reference](https://todealmarket.com/docs/api/sdk) • [GitHub](https://github.com/ToDealMarket/tdm-sdk) • [X/Twitter](https://x.com/todealmarket)

```
████████╗ ██████╗  ███╗   ███╗
╚══██╔══╝ ██╔══██╗ ████╗ ████║
   ██║    ██║  ██║ ██╔████╔██║
   ██║    ██║  ██║ ██║╚██╔╝██║
   ██║    ██████╔╝ ██║ ╚═╝ ██║
   ╚═╝    ╚═════╝  ╚═╝     ╚═╝

TDM SDK [OPEN SURFACE]
Routes + Contracts + Gateway Helpers
Mode: public-facing | Docs: todealmarket.com/docs
```

</div>

---

## What Is This Repo?

This GitHub repo shows the open contract-facing SDK surface for TDM:

- payable wrappers for application code
- route-first framework helpers
- thin clients around the public gateway contract
- small copy-paste examples for fast integration

This repo intentionally does **not** include:

- private gateway or treasury execution logic
- operator dashboards or setup UI
- unfinished control-plane tooling
- recovery, sweeper, or payout-operation internals

## GitHub Repo vs npm Beta

The public GitHub repo is intentionally thinner than the wider TDM beta
distribution used across some onboarding docs.

- GitHub repo: open SDK surface for external review, grants, and integration analysis
- current npm beta: broader distribution used by the current CLI/operator onboarding path

That split is deliberate. It keeps the public developer surface auditable
without exposing private control-plane implementation.

## Install

```bash
npm install tdm-sdk
```

## Fastest JS Path: Protect One Route

```ts
import { chargeFetchHandler, createFetchHookClient } from "tdm-sdk";

const hooks = createFetchHookClient({
  baseUrl: process.env.TDM_GATEWAY_URL ?? "https://tdm.todealmarket.com",
});

export const POST = chargeFetchHandler(
  {
    operation: "demo:route",
    resourceId: "demo:route",
    priceUsd: "0.05",
    tokenResolver: (request: Request) =>
      request.headers.get("x-tdm-token") ?? "demo-user",
    hooks,
  },
  async (_request: Request) => Response.json({ ok: true }),
);
```

## Function Wrapper Path

```ts
import { createFetchHookClient, makePayable } from "tdm-sdk";

const hooks = createFetchHookClient({
  baseUrl: "https://tdm.todealmarket.com",
});

const run = makePayable(
  async (input: string) => `processed:${input}`,
  {
    operation: "demo:process",
    tokenOrUuid: "demo-user",
    priceUsd: "0.05",
    hooks,
  },
);

console.log(await run("hello"));
```

## Call The Payment Gate Directly

```ts
import { createAuthorizeClient } from "tdm-sdk/authorize";

const authorize = createAuthorizeClient({
  baseUrl: "https://tdm.todealmarket.com",
  sessionToken: process.env.TDM_SESSION_TOKEN,
});

const result = await authorize.authorizePayment({
  requestId: "req_demo_1",
  tokenOrUuid: "demo-user",
  operation: "demo:authorize",
  priceUsd: "0.05",
});

console.log(result);
```

## Create A Hosted Checkout Session

```ts
import { createCheckoutClient } from "tdm-sdk/checkout";

const checkout = createCheckoutClient({
  baseUrl: "https://tdm.todealmarket.com",
});

const session = await checkout.createSession({
  resourceId: "res_demo_123",
  chain: "solana",
});

console.log(session);
```

## Share One Transport Across Clients

```ts
import { createGatewayClients } from "tdm-sdk";

const clients = createGatewayClients({
  baseUrl: "https://tdm.todealmarket.com",
  sessionToken: process.env.TDM_SESSION_TOKEN,
});

await clients.authorize.authorizePayment({
  requestId: "req_demo_2",
  tokenOrUuid: "demo-user",
  operation: "demo:authorize",
});

const checkout = await clients.checkout.createSession({
  resourceId: "res_demo_123",
  chain: "base",
});

console.log(checkout);
```

## Public Modules

- `tdm-sdk`
- `tdm-sdk/authorize`
- `tdm-sdk/checkout`
- `tdm-sdk/fetch-hook-client`
- `tdm-sdk/framework-mode`
- `tdm-sdk/gateway-auth`
- `tdm-sdk/gateway-clients`
- `tdm-sdk/gateway-transport`
- `tdm-sdk/local-402-circuit`
- `tdm-sdk/local-vault`
- `tdm-sdk/make-payable`
- `tdm-sdk/session-tanks`

## In-Repo Examples

The repo ships intentionally small examples in [`examples/`](./examples/README.md):

- `authorize-basic.ts`
- `checkout-basic.ts`
- `framework-mode-basic.ts`
- `gateway-clients-basic.ts`
- `session-tanks-basic.ts`
- `make-payable-route.ts`
- `protocol-first/*`

## Protocol Boundary

The stable wire contract lives in [`tdm-protocol`](./tdm-protocol/README.md).

Use:

- `tdm-protocol` when you need stable DTOs, schemas, headers, and response shapes
- `tdm-sdk` when you want ergonomic wrappers around that contract

## Build

```bash
npm install
npm run build
```
