import { createFetchHookClient, makePayable } from "tdm-sdk";

const hooks = createFetchHookClient({
  baseUrl: process.env.TDM_GATEWAY_URL ?? "https://tdm.todealmarket.com",
});

const run = makePayable(
  async (input: string) => {
    return { ok: true, echoed: input };
  },
  {
    operation: "demo:route",
    tokenOrUuid: "demo-user",
    hooks,
  },
);

console.log(await run("hello"));
