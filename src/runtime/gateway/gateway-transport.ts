import { ZodSchema, z } from "zod";
import { ApiResponseSchema, GatewayUrlSchema, sanitizeErrorMessage } from "./gateway-schemas.js";
import { createGatewayAuthContext } from "./gateway-auth.js";
import { combineAbortSignals } from "../../abort-signals.js";

export interface GatewayTransportOptions {
  baseUrl?: string;
  apiKey?: string;
  rootId?: string;
  sessionToken?: string;
  credentialsPath?: string;
  vaultName?: string;
  cwd?: string;
  headers?: HeadersInit;
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
}

export interface GatewayRuntimeConfig {
  baseUrl: string;
  apiKey?: string;
  rootId?: string;
  sessionToken?: string;
}

export interface GatewayRequestOptions<T> {
  method: "GET" | "POST" | "DELETE";
  path: string;
  payload?: Record<string, unknown>;
  signal?: AbortSignal;
  sign?: "auto" | "always" | "never";
  schema?: ZodSchema<T>;
}

export interface GatewayTransportLike {
  request<T>(request: GatewayRequestOptions<T>): Promise<T>;
}

export class TdmGatewayRequestError extends Error {
  public readonly status: number;
  public readonly payload: unknown;
  public readonly code?: string;
  public readonly hint?: string;
  public readonly docsHref?: string;

  public constructor(message: string, options: {
    status: number;
    payload: unknown;
    code?: string;
    hint?: string;
    docsHref?: string;
  }) {
    super(message);
    this.name = "TdmGatewayRequestError";
    this.status = options.status;
    this.payload = options.payload;
    this.code = options.code;
    this.hint = options.hint;
    this.docsHref = options.docsHref;
  }
}

const ErrorPayloadSchema = z.object({
  code: z.string().trim().min(1).optional(),
  message: z.string().trim().min(1).optional(),
}).partial();

function asRecord(value: unknown): Record<string, unknown> | null {
  if (value && typeof value === "object" && !Array.isArray(value)) {
    return value as Record<string, unknown>;
  }
  return null;
}

function unwrapApiData(payload: unknown): unknown {
  const parsed = ApiResponseSchema.safeParse(payload);
  if (parsed.success && parsed.data.success && "data" in parsed.data) {
    return parsed.data.data;
  }
  return payload;
}

function readErrorDetails(payload: unknown): { code?: string; message: string } {
  const parsed = ApiResponseSchema.safeParse(payload);
  if (parsed.success && parsed.data.error) {
    return {
      code: parsed.data.error.code,
      message: parsed.data.error.message,
    };
  }

  const map = asRecord(payload);
  if (!map) {
    return { message: "Unknown gateway error" };
  }

  const directMessage = typeof map["message"] === "string" ? map["message"].trim() : "";
  if (directMessage) {
    return {
      code: typeof map["code"] === "string" ? map["code"].trim() : undefined,
      message: directMessage,
    };
  }

  const nestedError = ErrorPayloadSchema.safeParse(map["error"]);
  if (nestedError.success) {
    return {
      code: nestedError.data.code,
      message: nestedError.data.message ?? nestedError.data.code ?? "Unknown gateway error",
    };
  }

  if (typeof map["error"] === "string" && map["error"].trim()) {
    return { message: map["error"].trim() };
  }

  return { message: "Unknown gateway error" };
}

function buildRequestHint(
  request: GatewayRequestOptions<unknown>,
  details: { code?: string; message: string },
  status: number,
): { hint?: string; docsHref?: string } {
  const path = request.path;
  const code = details.code?.trim().toUpperCase();

  if (path === "/authorize") {
    if (status === 401 || code?.includes("SIGNATURE") || code?.includes("SESSION")) {
      return {
        hint: "For POST /authorize, use either a valid session token or signed wallet headers. Re-check tokenOrUuid, operation, and the active auth mode.",
        docsHref: "https://todealmarket.com/docs/api/rest#authorize",
      };
    }

    return {
      hint: "POST /authorize is the payment gate, not a login endpoint. Re-check requestId, tokenOrUuid, operation, and the selected billing path.",
      docsHref: "https://todealmarket.com/docs/api/rest#authorize",
    };
  }

  if (path.startsWith("/publisher/payout")) {
    return {
      hint: "Payout routes require signed root-wallet headers. Confirm the payout wallet exists for the selected chain and that any required challenge_id has been provided.",
      docsHref: "https://todealmarket.com/docs/api/sdk",
    };
  }

  if (path.startsWith("/v1/tanks") || path.startsWith("/v1/sessions")) {
    return {
      hint: "Session tank routes expect root-wallet signing. Check rootId, wallet credentials, publicKey/tankId values, and session_tank-specific payload fields.",
      docsHref: "https://todealmarket.com/docs/api/sdk",
    };
  }

  if (path.startsWith("/v1/checkout")) {
    return {
      hint: "Checkout routes are unsigned buyer-facing helpers. Re-check resourceId or paymentId, and include checkoutSecret only on confirm flows that require it.",
      docsHref: "https://todealmarket.com/docs/checkout",
    };
  }

  return {};
}

async function safePayloadParse(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!text.trim()) {
    return null;
  }
  try {
    return JSON.parse(text);
  } catch {
    return { error: text };
  }
}

export function createGatewayTransport(options: GatewayTransportOptions = {}): GatewayTransportLike {
  const authContext = createGatewayAuthContext(options);
  let configPromise: Promise<GatewayRuntimeConfig> | null = null;

  const getConfig = async (): Promise<GatewayRuntimeConfig> => {
    if (!configPromise) {
      configPromise = authContext.resolveConfig().then((config) => ({
        baseUrl: GatewayUrlSchema.parse(config.baseUrl),
        apiKey: config.apiKey,
        rootId: config.rootId,
        sessionToken: config.sessionToken,
      }));
    }
    return await configPromise;
  };

  return {
    async request<T>(request: GatewayRequestOptions<T>): Promise<T> {
      try {
        const config = await getConfig();
        const url = new URL(request.path, config.baseUrl).toString();
        const headers = await authContext.buildRequestHeaders(request);
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), options.timeoutMs ?? 5_000);
        const combined = request.signal
          ? combineAbortSignals(request.signal, controller.signal)
          : { signal: controller.signal, cleanup() {} };

        try {
          const response = await (options.fetchImpl ?? fetch)(url, {
            method: request.method,
            headers,
            body: request.payload ? JSON.stringify(request.payload) : undefined,
            signal: combined.signal,
          });

          const payload = await safePayloadParse(response);
          if (!response.ok) {
            const { code, message } = readErrorDetails(payload);
            const guidance = buildRequestHint(request, { code, message }, response.status);
            throw new TdmGatewayRequestError(message, {
              status: response.status,
              payload,
              code,
              hint: guidance.hint,
              docsHref: guidance.docsHref,
            });
          }

          const data = unwrapApiData(payload);
          return request.schema ? request.schema.parse(data) : (data as T);
        } finally {
          combined.cleanup();
          clearTimeout(timeout);
        }
      } catch (error) {
        if (error instanceof TdmGatewayRequestError) {
          throw error;
        }
        throw new Error(sanitizeErrorMessage(error, `Gateway ${request.method} ${request.path}`));
      }
    },
  };
}
