import { createGatewayClients } from "tdm-sdk";

const clients = createGatewayClients({
  baseUrl: process.env.TDM_GATEWAY_URL ?? "https://tdm.todealmarket.com",
  sessionToken: process.env.TDM_SESSION_TOKEN,
});

const authorized = await clients.authorize.authorizePayment({
  requestId: "req_demo_composer",
  tokenOrUuid: "demo-user",
  operation: "demo:composer",
  priceUsd: "0.05",
});

console.log(authorized);
