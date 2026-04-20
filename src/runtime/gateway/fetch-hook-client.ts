import { withTimeout } from "../session/timeout.js";
import { LocalVault } from "../../domain/vault/local-vault.js";
import {
  createOfflineAuthorizationId,
  warnFutureBackendFeature,
} from "../modes/backendless-mode.js";
import { emitOpaqueResponseIsolationNotice } from "../../domain/security/security-advisory.js";
import { TdmPlatformNotConnectedError } from "../../domain/payments/make-payable.js";
import { combineAbortSignals } from "../../abort-signals.js";
import type {
  AuthorizePaymentRequest,
  AuthorizationBridgeMetadata,
  AuthorizationResponse,
} from "../../../tdm-protocol/src/index.js";

export type AuthorizationRequest = AuthorizePaymentRequest;
export type { AuthorizationBridgeMetadata, AuthorizationResponse };

export interface SafeExecutionTelemetry {
  eventId?: string;
  requestId: string;
  operation: string;
  tokenOrUuid: string;
  durationMs: number;
  ok: boolean;
  statusCode?: number;
  authorizationId?: string;
  financialDelta: "debit" | "refund" | "none";
  errorCode?: string;
  metadata?: Record<string, unknown>;
}

export interface PayableHooks {
  authorize?: (
    request: AuthorizationRequest,
    signal: AbortSignal,
  ) => Promise<AuthorizationResponse>;
  telemetry?: (
    event: SafeExecutionTelemetry,
    signal: AbortSignal,
  ) => Promise<void>;
}

export interface FetchHookClientOptions {
  baseUrl?: string;
  apiKey?: string;
  rootId?: string;
  sessionToken?: string;
  credentialsPath?: string;
  vaultName?: string;
  cwd?: string;
  authorizePath?: string;
  telemetryPath?: string;
  signAuthPayloads?: boolean;
  defaultTimeoutMs?: number;
  fetchImpl?: typeof fetch;
  headers?: HeadersInit;
}

interface ResolvedFetchClientConfig {
  defaultTimeoutMs: number;
  hasFutureBackendHints: boolean;
}

function hasConfiguredHint(value: string | undefined): boolean {
  return typeof value === "string" && value.trim().length > 0;
}

async function resolveConfig(
  options: FetchHookClientOptions,
): Promise<ResolvedFetchClientConfig> {
  const resolvedCredentials = await LocalVault.resolveRuntimeCredentials({
    cwd: options.cwd,
    credentialsPath: options.credentialsPath,
    vaultName: options.vaultName,
    allowVaultFallback: false,
    overrides: {
      gatewayUrl: options.baseUrl,
      apiKey: options.apiKey,
      rootId: options.rootId,
      sessionToken: options.sessionToken,
    },
  });

  const hasFutureBackendHints =
    hasConfiguredHint(options.baseUrl) ||
    hasConfiguredHint(options.apiKey) ||
    hasConfiguredHint(options.rootId) ||
    hasConfiguredHint(options.sessionToken) ||
    hasConfiguredHint(options.authorizePath) ||
    hasConfiguredHint(options.telemetryPath) ||
    hasConfiguredHint(resolvedCredentials.gatewayUrl) ||
    hasConfiguredHint(resolvedCredentials.apiKey) ||
    hasConfiguredHint(resolvedCredentials.rootId) ||
    hasConfiguredHint(resolvedCredentials.sessionToken);

  return {
    defaultTimeoutMs: options.defaultTimeoutMs ?? 350,
    hasFutureBackendHints,
  };
}

/**
 * Local-compatibility fetch hook client.
 *
 * This implementation intentionally does not perform live network authorization
 * or telemetry delivery. It preserves the same hook shape as the main SDK so
 * applications can surface a deterministic "connect first" error when no live
 * TDM payment runtime is configured.
 * 
 * @deprecated Use createFetchHookClient from the main export (now points to live client)
 */
export function createFetchHookClientStub(
  options: FetchHookClientOptions,
): PayableHooks {
  emitOpaqueResponseIsolationNotice("intercept");

  let configPromise: Promise<ResolvedFetchClientConfig> | null = null;
  const getConfig = (): Promise<ResolvedFetchClientConfig> => {
    if (!configPromise) {
      configPromise = resolveConfig(options);
    }
    return configPromise;
  };

  return {
    async authorize(request, outerSignal) {
      const config = await getConfig();

      if (config.hasFutureBackendHints) {
        warnFutureBackendFeature(
          "fetch-hook authorize",
          "Authorization is using the local compatibility surface and does not contact the TDM API",
        );
      } else {
        warnFutureBackendFeature(
          "fetch-hook authorize",
          "No gateway configuration is active; using local fail-open authorization compatibility mode",
        );
      }

      await withTimeout(async (timeoutSignal) => {
        const combined = combineAbortSignals(outerSignal, timeoutSignal);
        try {
          if (combined.signal.aborted) {
            throw new Error("Authorization aborted");
          }
        } finally {
          combined.cleanup();
        }
      }, config.defaultTimeoutMs);

      throw new TdmPlatformNotConnectedError(
        `TDM payable flows require a live gateway-backed authorization path. Request ${createOfflineAuthorizationId(request.requestId)} stayed local-only. Run \`tdm connect\` and use the live fetch hook client to go live.`,
      );
    },

    async telemetry(event, outerSignal) {
      const config = await getConfig();

      if (config.hasFutureBackendHints) {
        warnFutureBackendFeature(
          "fetch-hook telemetry",
          "Telemetry delivery is disabled because no TDM API URL is configured",
        );
      } else {
        warnFutureBackendFeature(
          "fetch-hook telemetry",
          "No gateway configuration is active; telemetry is treated as a local no-op compatibility surface",
        );
      }

      await withTimeout(async (timeoutSignal) => {
        const combined = combineAbortSignals(outerSignal, timeoutSignal);
        try {
          if (combined.signal.aborted) {
            throw new Error("Telemetry aborted");
          }
        } finally {
          combined.cleanup();
        }

        void event;
      }, config.defaultTimeoutMs);
    },
  };
}

/**
 * Live fetch hook client that connects to TDM Gateway.
 * 
 * Re-exported from fetch-hook-client-live for convenience.
 * This is now the default client implementation.
 */
export { createLiveFetchHookClient as createFetchHookClient } from "./fetch-hook-client-live.js";
