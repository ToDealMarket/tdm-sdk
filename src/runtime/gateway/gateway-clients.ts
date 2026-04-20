import { createAuthorizeClient } from "../session/authorize.js";
import { createCheckoutClient } from "../../domain/payments/checkout.js";
import { createGatewayTransport, type GatewayTransportLike, type GatewayTransportOptions } from "./gateway-transport.js";
import { createSessionTanksClient } from "../session/session-tanks.js";

export interface GatewayClientComposerOptions extends GatewayTransportOptions {
  transport?: GatewayTransportLike;
}

export function createGatewayClients(options: GatewayClientComposerOptions = {}) {
  const transport = options.transport ?? createGatewayTransport(options);

  return {
    transport,
    authorize: createAuthorizeClient({ transport }),
    sessionTanks: createSessionTanksClient({ transport }),
    checkout: createCheckoutClient({ transport }),
  };
}
