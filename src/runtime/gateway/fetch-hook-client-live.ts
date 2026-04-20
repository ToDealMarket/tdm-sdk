import { withTimeout } from "../session/timeout.js";
import { LocalVault } from "../../domain/vault/local-vault.js";
import type { PayableHooks, FetchHookClientOptions } from "./fetch-hook-client.js";
import { emitOpaqueResponseIsolationNotice } from "../../domain/security/security-advisory.js";
import { isTelemetryEnabled } from "../telemetry/telemetry-control.js";
import * as zod from "zod";
import {
  ApiResponseSchema,
  AuthorizationResponseSchema,
  GatewayUrlSchema,
  buildApiPathSchema,
  sanitizeErrorMessage,
} from "./gateway-schemas.js";
import { createGatewayAuthContext } from "./gateway-auth.js";
import { combineAbortSignals } from "../../abort-signals.js";

interface ResolvedLiveConfig {
  baseUrl: string;
  apiKey?: string;
  authorizePath: string;
  telemetryPath: string;
  defaultTimeoutMs: number;
  headers: Record<string, string>;
  fetchImpl: typeof fetch;
  sessionToken?: string;
}

const MAX_RESPONSE_SIZE = 1024 * 1024; // 1MB max response
const TELEMETRY_TIMEOUT_MS = 150;

async function drainResponseBody(response: Response): Promise<void> {
  try {
    await response.text();
  } catch {
    try {
      await response.body?.cancel();
    } catch {
      // Best-effort socket cleanup only.
    }
  }
}

async function resolveLiveConfig(
  options: FetchHookClientOptions,
): Promise<ResolvedLiveConfig> {
  let resolvedCredentials = await LocalVault.resolveRuntimeCredentials({
    cwd: options.cwd,
    credentialsPath: options.credentialsPath,
    vaultName: options.vaultName,
    allowVaultFallback: false,
    overrides: {
      gatewayUrl: options.baseUrl,
      apiKey: options.apiKey,
      sessionToken: options.sessionToken,
    },
  });

  let rawBaseUrl = options.baseUrl ?? resolvedCredentials.gatewayUrl ?? '';
  if (!rawBaseUrl && (options.credentialsPath || options.vaultName || options.signAuthPayloads !== false)) {
    resolvedCredentials = await LocalVault.resolveRuntimeCredentials({
      cwd: options.cwd,
      credentialsPath: options.credentialsPath,
      vaultName: options.vaultName,
      overrides: {
        gatewayUrl: options.baseUrl,
        apiKey: options.apiKey,
        sessionToken: options.sessionToken,
      },
    });
    rawBaseUrl = options.baseUrl ?? resolvedCredentials.gatewayUrl ?? '';
  }

  if (!rawBaseUrl) {
    throw new Error('TDM Gateway URL is required. Set via baseUrl option or TDM_GATEWAY_URL env var.');
  }

  // Validate and sanitize gateway URL
  const baseUrl = GatewayUrlSchema.parse(rawBaseUrl);

  const apiKey = options.apiKey ?? resolvedCredentials.apiKey;
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    ...(options.headers as Record<string, string> || {}),
  };

  if (apiKey) {
    headers['X-API-Key'] = apiKey;
  }

  // Validate API paths
  const authorizePath = buildApiPathSchema('authorizePath').parse(
    options.authorizePath ?? '/authorize',
  );
  const telemetryPath = buildApiPathSchema('telemetryPath').parse(
    options.telemetryPath ?? '/telemetry',
  );

  return {
    baseUrl,
    apiKey,
    authorizePath,
    telemetryPath,
    defaultTimeoutMs: Math.max(100, Math.min(options.defaultTimeoutMs ?? 350, 30000)), // 100ms-30s
    headers,
    fetchImpl: options.fetchImpl ?? fetch,
    sessionToken: options.sessionToken ?? resolvedCredentials.sessionToken,
  };
}

/**
 * Safe JSON parsing with size limit
 */
async function safeJsonParse(response: Response): Promise<unknown> {
  const contentLength = response.headers.get('content-length');
  if (contentLength && parseInt(contentLength, 10) > MAX_RESPONSE_SIZE) {
    throw new Error(`Response too large: ${contentLength} bytes`);
  }

  const text = await response.text();
  if (text.length > MAX_RESPONSE_SIZE) {
    throw new Error(`Response too large: ${text.length} bytes`);
  }

  try {
    return JSON.parse(text);
  } catch {
    throw new Error('Invalid JSON response from gateway');
  }
}

/**
 * Live fetch hook client that connects to TDM Gateway.
 * 
 * Use this instead of createFetchHookClientStub when you have a deployed gateway.
 */
export function createLiveFetchHookClient(
  options: FetchHookClientOptions,
): PayableHooks {
  emitOpaqueResponseIsolationNotice("intercept");
  const authContext = createGatewayAuthContext({
    baseUrl: options.baseUrl,
    apiKey: options.apiKey,
    rootId: options.rootId,
    sessionToken: options.sessionToken,
    credentialsPath: options.credentialsPath,
    vaultName: options.vaultName,
    cwd: options.cwd,
    headers: options.headers,
    fetchImpl: options.fetchImpl,
  });

  let configPromise: Promise<ResolvedLiveConfig> | null = null;
  const getConfig = (): Promise<ResolvedLiveConfig> => {
    if (!configPromise) {
      configPromise = resolveLiveConfig(options);
    }
    return configPromise;
  };

  const resolveSessionToken = (config: ResolvedLiveConfig): string | undefined => {
    if (options.sessionToken && options.sessionToken.trim()) {
      return options.sessionToken.trim();
    }
    if (typeof process !== 'undefined') {
      const envToken = process.env['TDM_SESSION_TOKEN'];
      if (envToken && envToken.trim()) {
        return envToken.trim();
      }
    }
    return config.sessionToken;
  };

  const buildHeaders = (config: ResolvedLiveConfig): Record<string, string> => {
    const headers: Record<string, string> = { ...config.headers };
    const sessionToken = resolveSessionToken(config);
    if (sessionToken) {
      headers['X-TDM-Session-Token'] = sessionToken;
    }
    return headers;
  };

  const buildAuthorizeHeaders = async (
    config: ResolvedLiveConfig,
    body: string,
  ): Promise<Record<string, string>> => {
    return await authContext.buildRequestHeaders({
      method: 'POST',
      path: new URL(config.authorizePath, config.baseUrl).pathname,
      payload: body,
      sign: options.signAuthPayloads === false ? 'never' : 'auto',
    });
  };

  return {
    async authorize(request, outerSignal) {
      try {
        const config = await getConfig();
        const url = `${config.baseUrl}${config.authorizePath}`;
        const requestBody = JSON.stringify(request);
        const headers = await buildAuthorizeHeaders(config, requestBody);

        return await withTimeout(async (timeoutSignal) => {
          const combined = combineAbortSignals(outerSignal, timeoutSignal);
          try {
            const response = await config.fetchImpl(url, {
              method: 'POST',
              headers,
              body: requestBody,
              signal: combined.signal,
            });

            if (!response.ok) {
              // 402 Payment Required is expected
              if (response.status === 402) {
                const body = await safeJsonParse(response);
                const apiResponse = ApiResponseSchema.parse(body);
                
                if (apiResponse.data) {
                  const authResponse = AuthorizationResponseSchema.parse(apiResponse.data);
                  return authResponse;
                }

                return {
                  allowed: false,
                  reason: apiResponse.error?.message || 'payment_required',
                };
              }

              throw new Error(`Authorization failed: HTTP ${response.status}`);
            }

            const body = await safeJsonParse(response);
            const apiResponse = ApiResponseSchema.parse(body);
            
            if (!apiResponse.success || !apiResponse.data) {
              throw new Error('Invalid authorization response format');
            }

            return AuthorizationResponseSchema.parse(apiResponse.data);
          } finally {
            combined.cleanup();
          }
        }, config.defaultTimeoutMs);
      } catch (error) {
        if (error instanceof zod.ZodError) {
          throw error;
        }
        throw new Error(sanitizeErrorMessage(error, 'Authorization request failed'));
      }
    },

    async telemetry(event, outerSignal) {
      if (!isTelemetryEnabled()) {
        return;
      }
      const config = await getConfig();
      const url = `${config.baseUrl}${config.telemetryPath}`;
      const headers = buildHeaders(config);
      const timeoutMs = Math.min(config.defaultTimeoutMs, TELEMETRY_TIMEOUT_MS);

      void withTimeout(async (timeoutSignal) => {
        const combined = combineAbortSignals(outerSignal, timeoutSignal);
        try {
          const response = await config.fetchImpl(url, {
            method: 'POST',
            headers,
            body: JSON.stringify(event),
            signal: combined.signal,
          });

          if (!response.ok) {
            console.warn(`TDM telemetry delivery failed: HTTP ${response.status}`);
          }
          await drainResponseBody(response);
        } finally {
          combined.cleanup();
        }
      }, timeoutMs).catch((error) => {
        console.warn('TDM SDK telemetry delivery failed', {
          requestId: event.requestId,
          operation: event.operation,
          error: sanitizeErrorMessage(error, 'Telemetry'),
        });
      });
    },
  };
}
