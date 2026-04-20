import { ZodSchema } from "zod";
import { createGatewayTransport, type GatewayTransportLike, type GatewayTransportOptions } from "../gateway/gateway-transport.js";
import {
  DelegatedSessionSchema,
  SessionBalanceSchema,
  SessionIncrementSchema,
  SessionTankSchema,
  type DelegatedSessionRecord,
  type SessionBalanceRecord,
  type SessionTankRecord,
} from "../gateway/gateway-schemas.js";

export interface SessionTanksClientOptions extends GatewayTransportOptions {
  transport?: GatewayTransportLike;
}

export function createSessionTanksClient(options: SessionTanksClientOptions = {}) {
  const transport = options.transport ?? createGatewayTransport(options);

  return {
    async createSubTank(request: {
      publicKey: string;
      profile?: "DISCRETE" | "AUTO_REFILL";
      limitUsd?: string;
      refillCapUsd?: string;
    }): Promise<SessionTankRecord> {
      return await transport.request({
        method: "POST",
        path: "/v1/tanks/create-sub",
        sign: "always",
        payload: {
          public_key: request.publicKey,
          ...(request.profile ? { profile: request.profile } : {}),
          ...(request.limitUsd ? { limit: request.limitUsd } : {}),
          ...(request.refillCapUsd ? { refill_cap: request.refillCapUsd } : {}),
        },
        schema: SessionTankSchema as unknown as ZodSchema<SessionTankRecord>,
      });
    },

    async deleteTank(tankId: string): Promise<unknown> {
      return await transport.request({
        method: "DELETE",
        path: `/v1/tanks/${encodeURIComponent(tankId)}`,
        sign: "always",
      });
    },

    async delegateSession(request: {
      tankId: string;
      sandboxId: string;
      maxSpendUsd: string;
      ttlSeconds: number;
    }): Promise<DelegatedSessionRecord> {
      return await transport.request({
        method: "POST",
        path: "/v1/sessions/delegate",
        sign: "always",
        payload: {
          tank_id: request.tankId,
          sandbox_id: request.sandboxId,
          max_spend: request.maxSpendUsd,
          ttl_seconds: request.ttlSeconds,
        },
        schema: DelegatedSessionSchema as unknown as ZodSchema<DelegatedSessionRecord>,
      });
    },

    async getBalance(sessionId?: string): Promise<SessionBalanceRecord> {
      return await transport.request({
        method: "GET",
        path: sessionId
          ? `/session/balance/${encodeURIComponent(sessionId)}`
          : "/session/balance",
        sign: "always",
        schema: SessionBalanceSchema as unknown as ZodSchema<SessionBalanceRecord>,
      });
    },

    async incrementBalance(request: {
      sessionId: string;
      amountUsd: string;
      idempotencyKey: string;
    }): Promise<{ success: boolean }> {
      return await transport.request({
        method: "POST",
        path: "/session/increment",
        sign: "always",
        payload: {
          sessionId: request.sessionId,
          amount: request.amountUsd,
          idempotencyKey: request.idempotencyKey,
        },
        schema: SessionIncrementSchema as unknown as ZodSchema<{ success: boolean }>,
      });
    },
  };
}

export const createSessionTankClient = createSessionTanksClient;
