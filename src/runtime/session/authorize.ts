import type { ZodSchema } from "zod";
import { AuthorizationResponseSchema } from "../gateway/gateway-schemas.js";
import { createGatewayTransport, type GatewayTransportLike, type GatewayTransportOptions } from "../gateway/gateway-transport.js";
import type {
  AuthorizePaymentRequest,
  AuthorizationResponse,
} from "../../../tdm-protocol/src/index.js";

export type AuthorizePaymentResponse = AuthorizationResponse;

export interface AuthorizeClientOptions extends GatewayTransportOptions {
  transport?: GatewayTransportLike;
}

export function createAuthorizeClient(options: AuthorizeClientOptions = {}) {
  const transport = options.transport ?? createGatewayTransport(options);

  return {
    async authorizePayment(request: AuthorizePaymentRequest): Promise<AuthorizePaymentResponse> {
      return await transport.request({
        method: "POST",
        path: "/authorize",
        payload: request as unknown as Record<string, unknown>,
        sign: "auto",
        schema:
          AuthorizationResponseSchema as unknown as ZodSchema<AuthorizePaymentResponse>,
      });
    },
  };
}
