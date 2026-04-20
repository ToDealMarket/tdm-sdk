# Protocol-First HTTP Contract

This folder documents the lowest-friction integration path for languages that do not have a native TDM SDK yet.

Public production examples in this folder use:

- base URL: `https://tdm.todealmarket.com`
- authorize endpoint: `https://tdm.todealmarket.com/authorize`

If you deploy your own gateway behind Cloudflare Workers, you can still use a `*.workers.dev` origin internally. For public documentation and production-facing clients, prefer your branded domain and keep the Worker origin behind it.

## Supported approach

1. Register a payable resource in the gateway.
2. Choose billing mode:
   - `account`: debit the user's off-chain account balance.
   - `session_gas_tank`: debit a prepaid Session Gas Tank.
3. Call `POST /authorize` before you return the protected content.
4. If the gateway returns `200`, execute your handler.
5. If the gateway returns `402`, stop and surface the payment challenge.

## Core endpoints

### 1. Register a payable resource

`POST https://tdm.todealmarket.com/discovery/payable-resources`

Headers:

- `Content-Type: application/json`
- `X-TDM-Root-Id: root_...`

Body:

```json
{
  "resource_identifier": "https://your-app.example/api/premium",
  "operation": "premium:api",
  "requested_price_usd": "0.05",
  "billing_mode": "session_gas_tank",
  "settlement_mode": "platform",
  "name": "Premium API"
}
```

### 2. Pre-fund a Session Gas Tank

`POST https://tdm.todealmarket.com/v1/tanks/create-sub`

Headers:

- `Content-Type: application/json`
- `X-TDM-Root-Id: root_...`

Body:

```json
{
  "profile": "DISCRETE",
  "public_key": "AGENT_PUBLIC_KEY_HEX_OR_BASE58",
  "limit": "10.00"
}
```

### 3. Delegate a short-lived session token

`POST https://tdm.todealmarket.com/v1/sessions/delegate`

Headers:

- `Content-Type: application/json`
- `X-TDM-Public-Key: AGENT_PUBLIC_KEY`
- `X-TDM-Signature: ED25519_SIGNATURE_OF_EXACT_REQUEST_BODY`

Body:

```json
{
  "sandbox_id": "sandbox_demo",
  "max_spend": "2.00",
  "ttl_seconds": 3600,
  "tank_id": "SESSION_TANK_UUID"
}
```

### 4. Authorize a paid request

`POST https://tdm.todealmarket.com/authorize`

Headers, option A:

- `Content-Type: application/json`
- `X-TDM-Session-Token: tdm_session_...`

Headers, option B:

- `Content-Type: application/json`
- `X-TDM-Public-Key: AGENT_PUBLIC_KEY`
- `X-TDM-Signature: ED25519_SIGNATURE_OF_EXACT_REQUEST_BODY`

Body:

```json
{
  "requestId": "req_123",
  "resourceId": "premium:api",
  "operation": "premium:api",
  "tokenOrUuid": "agent-or-user-id",
  "priceMinor": 5
}
```

Success response:

```json
{
  "success": true,
  "data": {
    "allowed": true,
    "authorizationId": "auth_...",
    "charged": true,
    "balanceMinor": 995,
    "priceMinor": 5,
    "billingMode": "session_gas_tank",
    "settlementMode": "platform"
  }
}
```

Payment required response:

```json
{
  "success": true,
  "data": {
    "allowed": false,
    "reason": "insufficient_balance",
    "balanceMinor": 0,
    "priceMinor": 5,
    "billingMode": "session_gas_tank",
    "retryEndpoint": "/authorize"
  }
}
```

## Seller settlement

For registered payable resources, the gateway performs the off-chain revenue split during `POST /authorize`:

- buyer account or session tank: `-price`
- seller publisher credits: `+seller_share`
- platform fee: retained internally

Payout request endpoint:

`POST https://tdm.todealmarket.com/publisher/payouts`

## Minimal flow

1. Merchant registers `billing_mode: session_gas_tank`.
2. Root account pre-funds an agent tank once.
3. Agent gets a delegated session token.
4. Every premium request calls `POST /authorize` off-chain.
5. Gateway debits the tank, credits the seller, and returns `200`.
