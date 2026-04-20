import { createSessionTanksClient } from "tdm-sdk/session-tanks";

const tanks = createSessionTanksClient({
  baseUrl: process.env.TDM_GATEWAY_URL ?? "https://tdm.todealmarket.com",
  rootId: process.env.TDM_ROOT_ID,
});

const tank = await tanks.createSubTank({
  publicKey: "<agent_public_key>",
  profile: "DISCRETE",
  limitUsd: "5.00",
});

const delegated = await tanks.delegateSession({
  tankId: tank.tank_id,
  sandboxId: "agent-sandbox-demo",
  maxSpendUsd: "1.00",
  ttlSeconds: 3600,
});

console.log({ tank, delegated });
