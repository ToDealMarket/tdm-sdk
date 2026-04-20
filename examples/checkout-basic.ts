import { createCheckoutClient } from "tdm-sdk/checkout";

const checkout = createCheckoutClient({
  baseUrl: process.env.TDM_GATEWAY_URL ?? "https://tdm.todealmarket.com",
});

const session = await checkout.createSession({
  resourceId: "res_demo_123",
  chain: "solana",
});

console.log(session);
