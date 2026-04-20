import {
  LocalPaymentRequiredError,
  type MakePayableOptions,
  makePayable,
} from "../../domain/payments/make-payable.js";
import { Global402Circuit } from "../session/local-402-circuit.js";
import {
  TDM_PAYMENT_REQUIRED_HEADERS,
  type PaymentOptionDescriptor as ProtocolPaymentOptionDescriptor,
  type PaymentRequiredBody as ProtocolPaymentRequiredBody,
  type PaymentRequiredBridgeDescriptor as ProtocolPaymentRequiredBridgeDescriptor,
} from "../../../tdm-protocol/src/index.js";

type MaybePromise<T> = T | Promise<T>;

export type PaymentOptionDescriptor = ProtocolPaymentOptionDescriptor;
export type PaymentRequiredBridgeDescriptor =
  ProtocolPaymentRequiredBridgeDescriptor;

export interface PayableDescriptor {
  operation: string;
  priceUsd?: string;
  resourceId?: string;
  settlementMode?: "platform" | "direct";
  recipientWalletAddress?: string;
  recipientNetwork?: string;
  recipientCurrency?: string;
  paymentOptions?: readonly PaymentOptionDescriptor[];
  retryEndpoint?: string;
}

export interface ChargeOptions<
  TArgs extends readonly unknown[] = readonly unknown[],
> extends Omit<MakePayableOptions, "tokenOrUuid">,
    PayableDescriptor {
  tokenOrUuid?: string;
  tokenResolver?: (...args: TArgs) => string;
}

export type PaymentRequiredBody = ProtocolPaymentRequiredBody;

export interface ExpressResponseLike {
  status(code: number): this;
  setHeader?(name: string, value: string): void;
  json(body: unknown): unknown;
}

function resolveTokenOrUuid<TArgs extends readonly unknown[]>(
  options: ChargeOptions<TArgs>,
  args: TArgs,
): string {
  if (typeof options.tokenResolver === "function") {
    return options.tokenResolver(...args);
  }
  if (typeof options.tokenOrUuid === "string" && options.tokenOrUuid.trim()) {
    return options.tokenOrUuid.trim();
  }
  throw new Error(
    `TDM charge("${options.operation}") requires tokenOrUuid or tokenResolver`,
  );
}

function buildPaymentRequiredBody<TArgs extends readonly unknown[]>(
  error: LocalPaymentRequiredError,
  options: ChargeOptions<TArgs>,
): PaymentRequiredBody {
  return {
    success: true,
    data: {
      allowed: false,
      reason: error.reason ?? "payment_required",
      retryAfterMs: error.retryAfterMs,
      balanceMinor: error.balanceMinor,
      priceMinor: error.priceMinor,
      settlementMode: error.settlementMode ?? options.settlementMode,
      recipientWalletAddress:
        error.recipientWalletAddress ?? options.recipientWalletAddress,
      recipientNetwork: error.recipientNetwork ?? options.recipientNetwork,
      recipientCurrency: error.recipientCurrency ?? options.recipientCurrency,
      paymentOptions: error.paymentOptions ?? options.paymentOptions,
      retryEndpoint: error.retryEndpoint ?? options.retryEndpoint,
      resourceKey: error.resourceKey,
      operation: error.operation ?? options.operation,
      bridge: error.bridge,
    },
  };
}

export function createPaymentRequiredResponse<TArgs extends readonly unknown[]>(
  error: LocalPaymentRequiredError,
  options: ChargeOptions<TArgs>,
): Response {
  const body = buildPaymentRequiredBody(error, options);
  const headers = new Headers({
    "Content-Type": "application/json",
    [TDM_PAYMENT_REQUIRED_HEADERS.paymentRequired]: "1",
  });

  if (body.data.settlementMode) {
    headers.set(
      TDM_PAYMENT_REQUIRED_HEADERS.settlementMode,
      body.data.settlementMode,
    );
  }
  if (body.data.recipientWalletAddress) {
    headers.set(
      TDM_PAYMENT_REQUIRED_HEADERS.recipient,
      body.data.recipientWalletAddress,
    );
  }
  if (body.data.retryEndpoint) {
    headers.set(
      TDM_PAYMENT_REQUIRED_HEADERS.retryEndpoint,
      body.data.retryEndpoint,
    );
  }
  if (body.data.resourceKey) {
    headers.set(
      TDM_PAYMENT_REQUIRED_HEADERS.resourceKey,
      body.data.resourceKey,
    );
  }
  if (body.data.operation) {
    headers.set(TDM_PAYMENT_REQUIRED_HEADERS.operation, body.data.operation);
  }
  if (body.data.bridge) {
    headers.set(
      TDM_PAYMENT_REQUIRED_HEADERS.checkoutUrl,
      body.data.bridge.checkoutUrl,
    );
    headers.set(TDM_PAYMENT_REQUIRED_HEADERS.buyUrl, body.data.bridge.buyUrl);
    headers.set(
      TDM_PAYMENT_REQUIRED_HEADERS.publicResourceUrl,
      body.data.bridge.publicResourceUrl,
    );
    headers.set(
      TDM_PAYMENT_REQUIRED_HEADERS.x402ListingUrl,
      body.data.bridge.x402ListingUrl,
    );
    headers.set(
      TDM_PAYMENT_REQUIRED_HEADERS.mppServiceUrl,
      body.data.bridge.mppServiceUrl,
    );
    headers.append("Link", `<${body.data.bridge.publicResourceUrl}>; rel="describedby"`);
  }

  return Response.json(body, {
    status: 402,
    headers,
  });
}

export function charge<TArgs extends readonly unknown[], TResult>(
  options: ChargeOptions<TArgs>,
): (
  handler: (...args: TArgs) => MaybePromise<TResult>,
) => (...args: TArgs) => Promise<TResult> {
  const sharedCircuit = options.circuit ?? Global402Circuit;

  return (handler) => {
    return async (...args: TArgs): Promise<TResult> => {
      const tokenOrUuid = resolveTokenOrUuid(options, args);
      const payableOptions: MakePayableOptions = {
        operation: options.operation,
        tokenOrUuid,
        priceUsd: options.priceUsd,
        resourceId: options.resourceId,
        strictGateAuthorization: options.strictGateAuthorization,
        authorizationTimeoutMs: options.authorizationTimeoutMs,
        telemetryTimeoutMs: options.telemetryTimeoutMs,
        endpoint: options.endpoint,
        endpointResolver: options.endpointResolver,
        systemAllowlist: options.systemAllowlist,
        allowlist: options.allowlist,
        enforceAllowlist: options.enforceAllowlist,
        sanitizeOpaqueResponse: options.sanitizeOpaqueResponse,
        hooks: options.hooks,
        circuit: sharedCircuit,
      };
      const wrapped = makePayable(handler, payableOptions);
      return await wrapped(...args);
    };
  };
}

export function chargeFetchHandler<TArgs extends readonly unknown[]>(
  options: ChargeOptions<TArgs>,
  handler: (...args: TArgs) => MaybePromise<Response>,
): (...args: TArgs) => Promise<Response> {
  const wrapped = charge<TArgs, Response>(options)(handler);
  return async (...args: TArgs): Promise<Response> => {
    try {
      return await wrapped(...args);
    } catch (error) {
      if (error instanceof LocalPaymentRequiredError) {
        return createPaymentRequiredResponse(error, options);
      }
      throw error;
    }
  };
}

export function chargeNextHandler<TArgs extends readonly unknown[]>(
  options: ChargeOptions<TArgs>,
  handler: (...args: TArgs) => MaybePromise<Response>,
): (...args: TArgs) => Promise<Response> {
  return chargeFetchHandler(options, handler);
}

export function chargeHonoHandler<TContext>(
  options: ChargeOptions<readonly [TContext]>,
  handler: (context: TContext) => MaybePromise<Response>,
): (context: TContext) => Promise<Response> {
  return chargeFetchHandler(options, handler);
}

export function chargeElysiaHandler<TArgs extends readonly unknown[]>(
  options: ChargeOptions<TArgs>,
  handler: (...args: TArgs) => MaybePromise<Response>,
): (...args: TArgs) => Promise<Response> {
  return chargeFetchHandler(options, handler);
}

export function chargeDenoHandler<TArgs extends readonly unknown[]>(
  options: ChargeOptions<TArgs>,
  handler: (...args: TArgs) => MaybePromise<Response>,
): (...args: TArgs) => Promise<Response> {
  return chargeFetchHandler(options, handler);
}

export function chargeExpressHandler<TRequest>(
  options: ChargeOptions<readonly [TRequest, ExpressResponseLike]>,
  handler: (
    request: TRequest,
    response: ExpressResponseLike,
  ) => MaybePromise<unknown>,
): (
  request: TRequest,
  response: ExpressResponseLike,
  next?: (error?: unknown) => void,
) => Promise<void> {
  const wrapped = charge(options)(handler);
  return async (request, response, next): Promise<void> => {
    try {
      await wrapped(request, response);
    } catch (error) {
      if (error instanceof LocalPaymentRequiredError) {
        const body = buildPaymentRequiredBody(error, options);
        response.setHeader?.("Content-Type", "application/json");
        response.setHeader?.(TDM_PAYMENT_REQUIRED_HEADERS.paymentRequired, "1");
        if (body.data.retryEndpoint) {
          response.setHeader?.(
            TDM_PAYMENT_REQUIRED_HEADERS.retryEndpoint,
            body.data.retryEndpoint,
          );
        }
        if (body.data.resourceKey) {
          response.setHeader?.(
            TDM_PAYMENT_REQUIRED_HEADERS.resourceKey,
            body.data.resourceKey,
          );
        }
        if (body.data.operation) {
          response.setHeader?.(
            TDM_PAYMENT_REQUIRED_HEADERS.operation,
            body.data.operation,
          );
        }
        if (body.data.bridge) {
          response.setHeader?.(
            TDM_PAYMENT_REQUIRED_HEADERS.checkoutUrl,
            body.data.bridge.checkoutUrl,
          );
          response.setHeader?.(
            TDM_PAYMENT_REQUIRED_HEADERS.buyUrl,
            body.data.bridge.buyUrl,
          );
          response.setHeader?.(
            TDM_PAYMENT_REQUIRED_HEADERS.publicResourceUrl,
            body.data.bridge.publicResourceUrl,
          );
          response.setHeader?.(
            TDM_PAYMENT_REQUIRED_HEADERS.x402ListingUrl,
            body.data.bridge.x402ListingUrl,
          );
          response.setHeader?.(
            TDM_PAYMENT_REQUIRED_HEADERS.mppServiceUrl,
            body.data.bridge.mppServiceUrl,
          );
        }
        response.status(402);
        response.json(body);
        return;
      }
      if (next) {
        next(error);
        return;
      }
      throw error;
    }
  };
}
