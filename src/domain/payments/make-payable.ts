import { Global402Circuit, Local402Circuit } from "../../runtime/session/local-402-circuit.js";
import type {
  AuthorizationResponse,
  PayableHooks,
  SafeExecutionTelemetry,
} from "../../runtime/gateway/fetch-hook-client.js";
import {
  evaluateEndpointAllowlist,
  mergeAllowlists,
  tryExtractHttpEndpoint,
} from "../trust/allowlist.js";
import {
  appendOpaqueResponseSystemTag,
  emitOpaqueResponseIsolationNotice,
} from "../security/security-advisory.js";
import { isTelemetryEnabled } from "../../runtime/telemetry/telemetry-control.js";
import type { TdmTelemetryContext } from "../../runtime/telemetry/telemetry-context.js";
import { withTimeout } from "../../runtime/session/timeout.js";

export interface MakePayableOptions {
  operation: string;
  tokenOrUuid: string;
  priceUsd?: string;
  resourceId?: string;
  strictGateAuthorization?: boolean;
  authorizationTimeoutMs?: number;
  telemetryTimeoutMs?: number;
  endpoint?: string;
  endpointResolver?: (args: readonly unknown[]) => string | undefined;
  systemAllowlist?: string[];
  allowlist?: string[];
  enforceAllowlist?: boolean;
  sanitizeOpaqueResponse?: boolean;
  telemetryContext?: TdmTelemetryContext | Record<string, unknown>;
  hooks?: PayableHooks;
  circuit?: Local402Circuit;
}

export class TdmPlatformNotConnectedError extends Error {
  public readonly code = "TDM_PLATFORM_NOT_CONNECTED";

  constructor(
    message = "live action blocked: not connected yet. Run `tdm connect` to activate monetization.",
  ) {
    super(message);
    this.name = "TdmPlatformNotConnectedError";
  }
}

export class LocalPaymentRequiredError extends Error {
  public readonly statusCode = 402;
  public readonly retryAfterMs: number;
  public readonly reason?: string;
  public readonly balanceMinor?: number;
  public readonly priceMinor?: number;
  public readonly settlementMode?: "platform" | "direct";
  public readonly recipientWalletAddress?: string;
  public readonly recipientNetwork?: string;
  public readonly recipientCurrency?: string;
  public readonly paymentOptions?: ReadonlyArray<{
    protocol: string;
    chain_id: string;
    symbol: string;
    address: string;
  }>;
  public readonly retryEndpoint?: string;
  public readonly resourceKey?: string;
  public readonly operation?: string;
  public readonly bridge?: AuthorizationResponse["bridge"];

  constructor(retryAfterMs: number, details?: Partial<AuthorizationResponse>) {
    super(`Local 402 circuit open. Retry after ${retryAfterMs}ms.`);
    this.name = "LocalPaymentRequiredError";
    this.retryAfterMs = retryAfterMs;
    this.reason = details?.reason;
    this.balanceMinor = details?.balanceMinor;
    this.priceMinor = details?.priceMinor;
    this.settlementMode = details?.settlementMode;
    this.recipientWalletAddress = details?.recipientWalletAddress;
    this.recipientNetwork = details?.recipientNetwork;
    this.recipientCurrency = details?.recipientCurrency;
    this.paymentOptions = details?.paymentOptions;
    this.retryEndpoint = details?.retryEndpoint;
    this.resourceKey = details?.resourceKey;
    this.operation = details?.operation;
    this.bridge = details?.bridge;
  }
}

export class EndpointAllowlistError extends Error {
  public readonly endpoint: string;
  public readonly allowlist: readonly string[];

  constructor(endpoint: string, allowlist: readonly string[]) {
    super(
      `Blocked endpoint "${endpoint}". Domain is outside merged allowlist: [${allowlist.join(", ")}].`,
    );
    this.name = "EndpointAllowlistError";
    this.endpoint = endpoint;
    this.allowlist = [...allowlist];
  }
}

export class EndpointAllowlistResolutionError extends Error {
  constructor() {
    super(
      "[TDM] Allowlist strict mode enforced, but endpoint could not be statically resolved from arguments. Request blocked.",
    );
    this.name = "EndpointAllowlistResolutionError";
  }
}

let fallbackRequestCounter = 0;

function bytesToHex(bytes: Uint8Array): string {
  return [...bytes]
    .map((value) => value.toString(16).padStart(2, "0"))
    .join("");
}

function createRequestId(): string {
  if (typeof globalThis.crypto?.randomUUID === "function") {
    return globalThis.crypto.randomUUID();
  }
  if (typeof globalThis.crypto?.getRandomValues === "function") {
    const bytes = new Uint8Array(16);
    globalThis.crypto.getRandomValues(bytes);
    return `req_${bytesToHex(bytes)}`;
  }

  fallbackRequestCounter =
    (fallbackRequestCounter + 1) % Number.MAX_SAFE_INTEGER;
  return `req_${Date.now()}_${fallbackRequestCounter.toString(16).padStart(8, "0")}`;
}

function readStatusCode(error: unknown): number | undefined {
  if (!error || typeof error !== "object") {
    return undefined;
  }
  const direct = (error as Record<string, unknown>)["statusCode"];
  if (typeof direct === "number") {
    return direct;
  }
  const alt = (error as Record<string, unknown>)["status"];
  if (typeof alt === "number") {
    return alt;
  }
  return undefined;
}

function readErrorCode(error: unknown): string | undefined {
  if (!error || typeof error !== "object") {
    return undefined;
  }
  const value = (error as Record<string, unknown>)["code"];
  return typeof value === "string" ? value : undefined;
}

function buildTelemetryEvent(
  requestId: string,
  options: MakePayableOptions,
  startedAt: number,
  payload: {
    ok: boolean;
    statusCode?: number;
    authorizationId?: string;
    financialDelta: "debit" | "refund" | "none";
    errorCode?: string;
    metadata?: Record<string, unknown>;
  },
): SafeExecutionTelemetry {
  const telemetryContextMetadata =
    options.telemetryContext && typeof (options.telemetryContext as TdmTelemetryContext).toMetadata === "function"
      ? (options.telemetryContext as TdmTelemetryContext).toMetadata()
      : options.telemetryContext;

  return {
    eventId: requestId,
    requestId,
    operation: options.operation,
    tokenOrUuid: options.tokenOrUuid,
    durationMs: Date.now() - startedAt,
    ok: payload.ok,
    statusCode: payload.statusCode,
    authorizationId: payload.authorizationId,
    financialDelta: payload.financialDelta,
    errorCode: payload.errorCode,
    metadata: {
      ...(typeof telemetryContextMetadata === "object" && telemetryContextMetadata ? telemetryContextMetadata : {}),
      ...(payload.metadata ?? {}),
    },
  };
}

async function authorizeWithPolicy(
  requestId: string,
  options: MakePayableOptions,
  endpointCandidate?: string,
): Promise<AuthorizationResponse | null> {
  if (!options.hooks?.authorize) {
    throw new TdmPlatformNotConnectedError(
      "live action blocked: not connected yet. Add live authorization hooks or run `tdm connect` before using makePayable(...).",
    );
  }

  const timeoutMs = options.authorizationTimeoutMs ?? 350;
  try {
    return await withTimeout(
      (signal) =>
        options.hooks!.authorize!(
          {
            requestId,
            operation: options.operation,
            tokenOrUuid: options.tokenOrUuid,
            priceUsd: options.priceUsd,
            resourceId: options.resourceId ?? endpointCandidate,
          },
          signal,
        ),
      timeoutMs,
    );
  } catch (error) {
    if (options.strictGateAuthorization === false) {
      return null;
    }
    throw error;
  }
}

async function reportTelemetry(
  options: MakePayableOptions,
  event: SafeExecutionTelemetry,
): Promise<void> {
  if (!isTelemetryEnabled()) {
    return;
  }
  if (!options.hooks?.telemetry) {
    return;
  }

  const timeoutMs = options.telemetryTimeoutMs ?? 250;
  try {
    await withTimeout(
      (signal) => options.hooks!.telemetry!(event, signal),
      timeoutMs,
    );
  } catch (error) {
    // Fail-open: telemetry should never block user execution.
    // INTEGRATION FIX: do not swallow telemetry failures silently.
    console.warn("TDM SDK telemetry delivery failed", {
      requestId: event.requestId,
      operation: event.operation,
      error: error instanceof Error ? error.message : String(error),
    });
  }
}

function resolveEndpointCandidate<TArgs extends readonly unknown[]>(
  args: TArgs,
  options: MakePayableOptions,
): string | undefined {
  if (options.endpoint) {
    return options.endpoint;
  }

  if (typeof options.endpointResolver === "function") {
    return options.endpointResolver(args);
  }

  return tryExtractHttpEndpoint(options.operation);
}

function sanitizeResult<TResult>(
  result: TResult,
  shouldSanitize: boolean,
): TResult {
  if (!shouldSanitize) {
    return result;
  }

  if (typeof result !== "string") {
    return result;
  }

  return appendOpaqueResponseSystemTag(result) as TResult;
}

/**
 * Wraps business logic with payment hooks.
 * Privacy guardrail: function arguments are never serialized or transmitted.
 */
export function makePayable<TArgs extends readonly unknown[], TResult>(
  target: (...args: TArgs) => Promise<TResult> | TResult,
  options: MakePayableOptions,
): (...args: TArgs) => Promise<TResult> {
  emitOpaqueResponseIsolationNotice("wrap");

  const circuit = options.circuit ?? Global402Circuit;
  const operationKey = Local402Circuit.key(
    options.operation,
    options.tokenOrUuid,
  );

  return async (...args: TArgs): Promise<TResult> => {
    const startedAt = Date.now();
    const requestId = createRequestId();

    const localStatus = circuit.check(operationKey);
    if (localStatus.blocked) {
      throw new LocalPaymentRequiredError(localStatus.retryAfterMs);
    }

    const mergedAllowlist = mergeAllowlists(
      options.systemAllowlist ?? [],
      options.allowlist ?? [],
    );
    const endpointCandidate = resolveEndpointCandidate(args, options);
    const allowlistGateEnabled =
      options.enforceAllowlist ?? mergedAllowlist.length > 0;

    if (allowlistGateEnabled) {
      if (!endpointCandidate) {
        throw new EndpointAllowlistResolutionError();
      }
      const verdict = evaluateEndpointAllowlist(
        endpointCandidate,
        mergedAllowlist,
      );
      if (!verdict.allowed) {
        throw new EndpointAllowlistError(endpointCandidate, mergedAllowlist);
      }
    }

    let authorizationId: string | undefined;
    let charged = false;

    const authorization = await authorizeWithPolicy(
      requestId,
      options,
      endpointCandidate,
    );
    if (authorization && authorization.allowed === false) {
      const retryAfterMs = circuit.record402(operationKey);
      throw new LocalPaymentRequiredError(retryAfterMs, authorization);
    }
    if (authorization) {
      circuit.recordSuccess(operationKey);
      authorizationId = authorization.authorizationId;
      charged = Boolean(authorization.charged);
    }

    try {
      const result = await target(...args);
      circuit.recordSuccess(operationKey);

      await reportTelemetry(
        options,
        buildTelemetryEvent(requestId, options, startedAt, {
          ok: true,
          authorizationId,
          financialDelta: charged ? "debit" : "none",
          metadata: {
            channel: "sdk",
            feature: "make_payable",
            direction: "sdk_runtime",
            enforce_allowlist: allowlistGateEnabled,
            endpoint_present: Boolean(endpointCandidate),
            sanitize_opaque_response: options.sanitizeOpaqueResponse ?? true,
            strict_gate_authorization:
              options.strictGateAuthorization !== false,
            charged,
            billing_mode: authorization?.billingMode ?? null,
            settlement_mode: authorization?.settlementMode ?? null,
          },
        }),
      );

      return sanitizeResult(result, options.sanitizeOpaqueResponse ?? true);
    } catch (error) {
      const statusCode = readStatusCode(error);
      if (statusCode === 402) {
        circuit.record402(operationKey);
      }

      await reportTelemetry(
        options,
        buildTelemetryEvent(requestId, options, startedAt, {
          ok: false,
          statusCode,
          authorizationId,
          financialDelta: "none",
          errorCode: readErrorCode(error),
          metadata: {
            channel: "sdk",
            feature: "make_payable",
            direction: "sdk_runtime",
            enforce_allowlist: allowlistGateEnabled,
            endpoint_present: Boolean(endpointCandidate),
            sanitize_opaque_response: options.sanitizeOpaqueResponse ?? true,
            strict_gate_authorization:
              options.strictGateAuthorization !== false,
            charged,
            billing_mode: authorization?.billingMode ?? null,
            settlement_mode: authorization?.settlementMode ?? null,
          },
        }),
      );

      throw error;
    }
  };
}
