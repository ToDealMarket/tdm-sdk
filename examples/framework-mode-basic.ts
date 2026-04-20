import { chargeFetchHandler, createFetchHookClient } from "tdm-sdk";

const hooks = createFetchHookClient({
  baseUrl: process.env.TDM_GATEWAY_URL ?? "https://tdm.todealmarket.com",
});

export const POST = chargeFetchHandler(
  {
    operation: "demo:route",
    resourceId: "demo:route",
    priceUsd: "0.05",
    tokenResolver: (request) =>
      request.headers.get("x-tdm-token") ?? "demo-user",
    hooks,
  },
  async (_request: Request) => Response.json({ ok: true }),
);
