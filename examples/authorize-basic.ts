import { createAuthorizeClient } from "tdm-sdk/authorize";

const authorize = createAuthorizeClient({
  baseUrl: process.env.TDM_GATEWAY_URL ?? "https://tdm.todealmarket.com",
  sessionToken: process.env.TDM_SESSION_TOKEN,
});

const result = await authorize.authorizePayment({
  requestId: "req_demo_authorize",
  tokenOrUuid: "demo-user",
  operation: "demo:authorize",
  priceUsd: "0.05",
});

console.log(result);
