import { ZodSchema } from "zod";
import { createGatewayTransport, type GatewayTransportLike, type GatewayTransportOptions } from "../../runtime/gateway/gateway-transport.js";
import {
  CheckoutConfirmSchema,
  CheckoutSessionSchema,
  CheckoutStatusSchema,
  type CheckoutConfirmRecord,
  type CheckoutSessionRecord,
  type CheckoutStatusRecord,
} from "../../runtime/gateway/gateway-schemas.js";

export interface CheckoutClientOptions extends GatewayTransportOptions {
  transport?: GatewayTransportLike;
}

export function createCheckoutClient(options: CheckoutClientOptions = {}) {
  const transport = options.transport ?? createGatewayTransport(options);

  return {
    async createSession(request: {
      resourceId: string;
      chain?: "solana" | "base" | "SOLANA" | "BASE";
    }): Promise<CheckoutSessionRecord> {
      return await transport.request({
        method: "POST",
        path: "/v1/checkout-sessions",
        sign: "never",
        payload: {
          resourceId: request.resourceId,
          ...(request.chain ? { chain: request.chain } : {}),
        },
        schema: CheckoutSessionSchema as unknown as ZodSchema<CheckoutSessionRecord>,
      });
    },

    async getStatus(paymentId: string): Promise<CheckoutStatusRecord> {
      return await transport.request({
        method: "GET",
        path: `/v1/checkout-status/${encodeURIComponent(paymentId)}`,
        sign: "never",
        schema: CheckoutStatusSchema as unknown as ZodSchema<CheckoutStatusRecord>,
      });
    },

    async confirmPayment(request: {
      paymentId: string;
      network?: "solana" | "base";
      txHash?: string;
      checkoutSecret?: string;
    }): Promise<CheckoutConfirmRecord> {
      return await transport.request({
        method: "POST",
        path: "/v1/checkout-confirm",
        sign: "never",
        payload: {
          paymentId: request.paymentId,
          ...(request.network ? { network: request.network } : {}),
          ...(request.txHash ? { txHash: request.txHash } : {}),
          ...(request.checkoutSecret ? { checkoutSecret: request.checkoutSecret } : {}),
        },
        schema: CheckoutConfirmSchema as unknown as ZodSchema<CheckoutConfirmRecord>,
      });
    },
  };
}
