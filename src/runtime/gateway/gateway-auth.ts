import { GatewayUrlSchema } from "./gateway-schemas.js";
import { LocalVault } from "../../domain/vault/local-vault.js";

export type GatewayAuthMode = "auto" | "always" | "never";

export interface GatewayAuthContextOptions {
  baseUrl?: string;
  apiKey?: string;
  rootId?: string;
  sessionToken?: string;
  credentialsPath?: string;
  vaultName?: string;
  cwd?: string;
  headers?: HeadersInit;
  fetchImpl?: typeof fetch;
}

export interface ResolvedGatewayAuthConfig {
  baseUrl: string;
  apiKey?: string;
  rootId?: string;
  sessionToken?: string;
  headers: Record<string, string>;
}

export interface GatewayHeaderBuildRequest {
  method: string;
  path: string;
  payload?: unknown;
  sign?: GatewayAuthMode;
  headers?: HeadersInit;
}

function normalizeHeaders(headers?: HeadersInit): Record<string, string> {
  if (!headers) {
    return {};
  }

  if (headers instanceof Headers) {
    return Object.fromEntries(headers.entries());
  }

  if (Array.isArray(headers)) {
    return Object.fromEntries(headers);
  }

  return { ...headers };
}

export function createGatewayAuthContext(options: GatewayAuthContextOptions = {}) {
  const signingVault = new LocalVault({
    credentialsPath: options.credentialsPath,
    vaultName: options.vaultName,
    fetchImpl: options.fetchImpl,
  });

  let configPromise: Promise<ResolvedGatewayAuthConfig> | null = null;

  const resolveConfig = async (): Promise<ResolvedGatewayAuthConfig> => {
    if (!configPromise) {
      configPromise = (async () => {
        const resolved = await LocalVault.resolveRuntimeCredentials({
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

        const rawBaseUrl = options.baseUrl ?? resolved.gatewayUrl;
        if (!rawBaseUrl?.trim()) {
          throw new Error("TDM Gateway URL is required. Set via baseUrl option or TDM_GATEWAY_URL.");
        }

        return {
          baseUrl: GatewayUrlSchema.parse(rawBaseUrl),
          apiKey: options.apiKey ?? resolved.apiKey,
          rootId: options.rootId ?? resolved.rootId,
          sessionToken: options.sessionToken ?? resolved.sessionToken,
          headers: normalizeHeaders(options.headers),
        };
      })();
    }

    return await configPromise;
  };

  const resolveSessionToken = (config: ResolvedGatewayAuthConfig): string | undefined => {
    if (options.sessionToken?.trim()) {
      return options.sessionToken.trim();
    }
    if (typeof process !== "undefined") {
      const envToken = process.env["TDM_SESSION_TOKEN"];
      if (envToken?.trim()) {
        return envToken.trim();
      }
    }
    return config.sessionToken;
  };

  const buildRequestHeaders = async (request: GatewayHeaderBuildRequest): Promise<Record<string, string>> => {
    const config = await resolveConfig();
    const headers: Record<string, string> = {
      Accept: "application/json",
      ...(request.payload !== undefined ? { "Content-Type": "application/json" } : {}),
      ...config.headers,
      ...normalizeHeaders(request.headers),
    };

    if (config.apiKey) {
      headers["X-API-Key"] = config.apiKey;
    }
    if (config.rootId) {
      headers["X-TDM-Root-Id"] = config.rootId;
    }

    const sessionToken = resolveSessionToken(config);
    if (sessionToken) {
      headers["X-TDM-Session-Token"] = sessionToken;
    }

    const signMode = request.sign ?? "auto";
    const shouldSign =
      signMode === "always" ||
      (signMode === "auto" && !headers["X-TDM-Session-Token"]);

    if (!shouldSign) {
      return headers;
    }

    const body =
      typeof request.payload === "string"
        ? request.payload
        : request.payload !== undefined
          ? JSON.stringify(request.payload)
          : "";

    const authHeaders = await signingVault.buildGatewayAuthHeaders(body, {
      method: request.method,
      path: request.path,
    });

    return {
      ...headers,
      ...authHeaders,
    };
  };

  return {
    resolveConfig,
    resolveSessionToken,
    buildRequestHeaders,
  };
}
