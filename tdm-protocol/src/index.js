import { z } from "zod";

const HTTP_PROTOCOLS = new Set(["https:", "http:"]);

export const RequiredTrimmedStringSchema = z.preprocess(
  (value) => (typeof value === "string" ? value.trim() : value),
  z.string().min(1),
);

export const OptionalStringSchema = z.string().optional();

function isLocalhost(hostname) {
  return (
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "::1" ||
    hostname.endsWith(".localhost")
  );
}

export const GatewayUrlSchema = z
  .string()
  .trim()
  .min(1, { message: "Gateway URL cannot be empty" })
  .superRefine((value, ctx) => {
    let parsed;
    try {
      parsed = new URL(value);
    } catch {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `Invalid gateway URL format: ${value}`,
      });
      return;
    }

    if (!HTTP_PROTOCOLS.has(parsed.protocol)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: `Gateway URL must use HTTP(S) protocol, got: ${parsed.protocol}`,
      });
    }

    if (parsed.username || parsed.password) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Gateway URL must not contain credentials",
      });
    }

    if (parsed.search || parsed.hash) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message: "Gateway URL must not contain query params or hash fragments",
      });
    }
  })
  .transform((value) => {
    const parsed = new URL(value);
    if (parsed.protocol === "http:" && !isLocalhost(parsed.hostname)) {
      console.warn(
        `[TDM Protocol Security Warning] Using HTTP for non-localhost gateway: ${parsed.hostname}. ` +
          "This exposes API keys and payment data. Use HTTPS in production.",
      );
    }
    const normalizedPath =
      parsed.pathname === "/" ? "" : parsed.pathname.replace(/\/+$/, "");
    return `${parsed.protocol}//${parsed.host}${normalizedPath}`;
  });

export const buildApiPathSchema = (name) =>
  z
    .string()
    .trim()
    .superRefine((value, ctx) => {
      if (!value) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `${name} must be a non-empty string`,
        });
        return;
      }

      if (!value.startsWith("/")) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `${name} must start with /`,
        });
      }

      if (value.length > 255) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `${name} too long (max 255 chars)`,
        });
      }

      if (value.includes("..") || value.includes("//")) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `${name} contains invalid path segments`,
        });
      }

      if (!/^[a-zA-Z0-9/_-]+$/.test(value)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `${name} contains invalid characters`,
        });
      }
    });

export const PaymentOptionSchema = z.object({
  protocol: RequiredTrimmedStringSchema,
  chain_id: RequiredTrimmedStringSchema,
  symbol: RequiredTrimmedStringSchema,
  address: RequiredTrimmedStringSchema,
});

export const AuthorizationBridgeMetadataSchema = z.object({
  checkoutUrl: RequiredTrimmedStringSchema,
  buyUrl: RequiredTrimmedStringSchema,
  checkoutSessionUrl: RequiredTrimmedStringSchema,
  checkoutStatusUrlTemplate: RequiredTrimmedStringSchema,
  publicResourceUrl: RequiredTrimmedStringSchema,
  x402ListingUrl: RequiredTrimmedStringSchema,
  mppServiceUrl: RequiredTrimmedStringSchema,
  mppLlmsUrl: RequiredTrimmedStringSchema,
});

export const AuthorizationResponseSchema = z.object({
  allowed: z.boolean(),
  authorizationId: OptionalStringSchema,
  charged: z.boolean().optional(),
  reason: OptionalStringSchema,
  balanceMinor: z.number().finite().optional(),
  priceMinor: z.number().finite().optional(),
  billingMode: z.enum(["account", "session_gas_tank"]).optional(),
  settlementMode: z.enum(["platform", "direct"]).optional(),
  recipientWalletAddress: OptionalStringSchema,
  recipientNetwork: OptionalStringSchema,
  recipientCurrency: OptionalStringSchema,
  paymentOptions: z.array(PaymentOptionSchema).optional(),
  retryEndpoint: OptionalStringSchema,
  resourceKey: OptionalStringSchema,
  operation: OptionalStringSchema,
  bridge: AuthorizationBridgeMetadataSchema.optional(),
});

export const AuthorizePaymentRequestSchema = z.object({
  requestId: RequiredTrimmedStringSchema,
  tokenOrUuid: RequiredTrimmedStringSchema,
  operation: OptionalStringSchema,
  resourceId: OptionalStringSchema,
  priceMinor: z.number().finite().optional(),
  priceUsd: OptionalStringSchema,
});

export const CheckoutChainSchema = z.enum([
  "solana",
  "base",
  "SOLANA",
  "BASE",
]);

export const CreateCheckoutSessionRequestSchema = z.object({
  resourceId: RequiredTrimmedStringSchema,
  chain: CheckoutChainSchema.optional(),
});

export const CheckoutSessionSchema = z.object({
  paymentId: RequiredTrimmedStringSchema,
  status: RequiredTrimmedStringSchema,
  expiresAt: RequiredTrimmedStringSchema.nullable(),
  network: RequiredTrimmedStringSchema,
  selectedNetwork: RequiredTrimmedStringSchema,
  availableNetworks: z.array(RequiredTrimmedStringSchema).default([]),
  currency: RequiredTrimmedStringSchema,
  recipientWalletAddress: RequiredTrimmedStringSchema,
  amountUsd: RequiredTrimmedStringSchema,
  amountMinor: z.union([z.number().int().nonnegative(), RequiredTrimmedStringSchema]),
  paymentMemo: RequiredTrimmedStringSchema.nullable().optional(),
  checkoutSecret: z.null().optional(),
  checkoutAccessToken: RequiredTrimmedStringSchema.nullable().optional(),
  solanaReference: RequiredTrimmedStringSchema.nullable().optional(),
  solanaMemo: RequiredTrimmedStringSchema.nullable().optional(),
  solanaPayUrl: RequiredTrimmedStringSchema.nullable().optional(),
  eip681Url: RequiredTrimmedStringSchema.nullable().optional(),
});

export const CheckoutStatusPendingSchema = z.object({
  paymentId: RequiredTrimmedStringSchema,
  status: RequiredTrimmedStringSchema,
  expiresAt: RequiredTrimmedStringSchema.nullable(),
  transactionHash: RequiredTrimmedStringSchema.nullable().optional(),
});

export const CheckoutStatusConfirmedSchema = z.object({
  paymentId: RequiredTrimmedStringSchema,
  status: z.literal("confirmed"),
  accessToken: RequiredTrimmedStringSchema,
  deliveryUrl: RequiredTrimmedStringSchema,
});

export const CheckoutStatusSchema = z.union([
  CheckoutStatusConfirmedSchema,
  CheckoutStatusPendingSchema,
]);

export const ConfirmCheckoutPaymentRequestSchema = z.object({
  paymentId: RequiredTrimmedStringSchema,
  network: z.enum(["solana", "base"]).optional(),
  txHash: OptionalStringSchema,
  checkoutSecret: OptionalStringSchema,
});

export const CheckoutConfirmConfirmedSchema = z.object({
  paymentId: RequiredTrimmedStringSchema,
  status: z.literal("confirmed"),
  accessToken: RequiredTrimmedStringSchema,
  deliveryUrl: RequiredTrimmedStringSchema,
});

export const CheckoutConfirmPendingSchema = z.object({
  paymentId: RequiredTrimmedStringSchema,
  status: z.literal("pending"),
});

export const CheckoutConfirmSchema = z.union([
  CheckoutConfirmConfirmedSchema,
  CheckoutConfirmPendingSchema,
]);

export const SessionTankProfileSchema = z.enum(["DISCRETE", "AUTO_REFILL"]);

export const SessionTankSchema = z.object({
  tank_id: RequiredTrimmedStringSchema,
  public_key: RequiredTrimmedStringSchema,
  allocated_limit_usd: RequiredTrimmedStringSchema,
  spent_total_usd: RequiredTrimmedStringSchema,
  available_balance_usd: RequiredTrimmedStringSchema,
});

export const CreateSubTankRequestSchema = z.object({
  publicKey: RequiredTrimmedStringSchema,
  profile: SessionTankProfileSchema.optional(),
  limitUsd: OptionalStringSchema,
  refillCapUsd: OptionalStringSchema,
});

export const DelegatedSessionSchema = z.object({
  session_id: RequiredTrimmedStringSchema,
  session_token: RequiredTrimmedStringSchema,
  tank_id: RequiredTrimmedStringSchema,
  max_spend_usd: RequiredTrimmedStringSchema,
  expires_at: RequiredTrimmedStringSchema,
});

export const DelegateSessionRequestSchema = z.object({
  tankId: RequiredTrimmedStringSchema,
  sandboxId: RequiredTrimmedStringSchema,
  maxSpendUsd: RequiredTrimmedStringSchema,
  ttlSeconds: z.number().int().positive(),
});

export const SessionBalanceSchema = z.object({
  balance: RequiredTrimmedStringSchema,
});

export const SessionIncrementSchema = z.object({
  success: z.boolean(),
});

export const IncrementSessionBalanceRequestSchema = z.object({
  sessionId: RequiredTrimmedStringSchema,
  amountUsd: RequiredTrimmedStringSchema,
  idempotencyKey: RequiredTrimmedStringSchema,
});

export const PayoutChainSchema = z.enum(["SOLANA", "BASE"]);

export const PayoutRequestSchema = z.object({
  payout_id: RequiredTrimmedStringSchema,
  remaining_credits_usd: RequiredTrimmedStringSchema,
  chain: RequiredTrimmedStringSchema,
  destination_address: RequiredTrimmedStringSchema,
  status: RequiredTrimmedStringSchema,
  hold_release_at: RequiredTrimmedStringSchema.nullable().optional(),
});

export const RequestPublisherPayoutSchema = z.object({
  amountUsd: RequiredTrimmedStringSchema,
  idempotencyKey: RequiredTrimmedStringSchema,
  chain: PayoutChainSchema.optional(),
  destinationAddress: OptionalStringSchema,
  challengeId: OptionalStringSchema,
});

export const PayoutWalletSchema = z.object({
  chain: RequiredTrimmedStringSchema,
  currency: RequiredTrimmedStringSchema,
  address: RequiredTrimmedStringSchema,
  label: RequiredTrimmedStringSchema.nullable().optional(),
});

export const PayoutWalletStatusSchema = z.object({
  wallets: z.array(PayoutWalletSchema).default([]),
  setup_complete: z.boolean().optional(),
  solana_auto_payout_reset: z.boolean().optional(),
  supported_chains: z.array(z.string()).default([]),
  direct_payment_options: z.array(
    z.object({
      protocol: z.string().trim().min(1).optional(),
      chain_id: z.string().trim().min(1).optional(),
      symbol: z.string().trim().min(1).optional(),
      address: z.string().trim().min(1).optional(),
    }),
  ).default([]),
});

export const SavePayoutWalletsRequestSchema = z.object({
  wallets: z.array(
    z.object({
      chain: PayoutChainSchema,
      address: RequiredTrimmedStringSchema,
      label: OptionalStringSchema,
    }),
  ),
  challengeId: OptionalStringSchema,
});

export const PayoutAutomationSchema = z.object({
  solana: z
    .object({
      enabled: z.boolean().optional(),
      min_amount_usd: RequiredTrimmedStringSchema.optional(),
      interval_days: z.number().int().optional(),
    })
    .optional(),
  base: z
    .object({
      mode: RequiredTrimmedStringSchema.optional(),
      guidance: RequiredTrimmedStringSchema.optional(),
    })
    .optional(),
});

export const UpdatePayoutAutomationRequestSchema = z.object({
  enabled: z.boolean().optional(),
  minAmountUsd: OptionalStringSchema,
  intervalDays: z.number().int().nonnegative().optional(),
  challengeId: OptionalStringSchema,
});

export const ApiResponseSchema = z.object({
  success: z.boolean(),
  data: z.unknown().optional(),
  error: z
    .object({
      code: RequiredTrimmedStringSchema,
      message: RequiredTrimmedStringSchema,
    })
    .optional(),
});

export const TDM_PAYMENT_REQUIRED_HEADERS = Object.freeze({
  paymentRequired: "X-TDM-Payment-Required",
  settlementMode: "X-TDM-Settlement-Mode",
  recipient: "X-TDM-Recipient",
  retryEndpoint: "X-TDM-Retry-Endpoint",
  resourceKey: "X-TDM-Resource-Key",
  operation: "X-TDM-Operation",
  checkoutUrl: "X-TDM-Checkout-Url",
  buyUrl: "X-TDM-Buy-Url",
  publicResourceUrl: "X-TDM-Public-Resource-Url",
  x402ListingUrl: "X-TDM-X402-Listing-Url",
  mppServiceUrl: "X-TDM-MPP-Service-Url",
});

export const PaymentRequiredBodySchema = z.object({
  success: z.literal(true),
  data: z.object({
    allowed: z.literal(false),
    reason: RequiredTrimmedStringSchema,
    retryAfterMs: z.number().int().nonnegative(),
    balanceMinor: z.number().finite().optional(),
    priceMinor: z.number().finite().optional(),
    settlementMode: z.enum(["platform", "direct"]).optional(),
    recipientWalletAddress: OptionalStringSchema,
    recipientNetwork: OptionalStringSchema,
    recipientCurrency: OptionalStringSchema,
    paymentOptions: z.array(PaymentOptionSchema).optional(),
    retryEndpoint: OptionalStringSchema,
    resourceKey: OptionalStringSchema,
    operation: OptionalStringSchema,
    bridge: AuthorizationBridgeMetadataSchema.optional(),
  }),
});

export function sanitizeErrorMessage(error, context) {
  if (!(error instanceof Error)) {
    return `${context}: Unknown error`;
  }

  const sanitizeSingleMessage = (value) => {
    let message = value;

    message = message.replace(
      /\b(apk|sk|pk|key)_[a-zA-Z0-9]{16,}\b/gi,
      "[REDACTED_KEY]",
    );

    message = message.replace(/\b[A-Za-z0-9_-]{32,}\b/g, "[REDACTED_TOKEN]");

    message = message.replace(
      /https?:\/\/[^:]+:[^@]+@[^\s]+/g,
      "[REDACTED_URL]",
    );

    return message;
  };

  const nestedCause = (() => {
    const cause = error.cause;
    if (!cause) {
      return "";
    }
    if (cause instanceof Error && cause.message.trim().length > 0) {
      const causeCode =
        typeof cause.code === "string" ? ` [${String(cause.code)}]` : "";
      return `${sanitizeSingleMessage(cause.message)}${causeCode}`;
    }
    if (typeof cause === "string" && cause.trim().length > 0) {
      return sanitizeSingleMessage(cause.trim());
    }
    if (typeof cause === "object") {
      const causeCode =
        cause &&
        "code" in cause &&
        typeof cause.code === "string"
          ? String(cause.code)
          : "";
      const causeMessage =
        cause &&
        "message" in cause &&
        typeof cause.message === "string"
          ? String(cause.message)
          : "";
      if (causeMessage.trim().length > 0 || causeCode.trim().length > 0) {
        return sanitizeSingleMessage(
          `${causeMessage.trim()}${causeCode.trim().length > 0 ? ` [${causeCode.trim()}]` : ""}`.trim(),
        );
      }
    }
    return "";
  })();

  const baseMessage = sanitizeSingleMessage(error.message);
  return nestedCause.length > 0
    ? `${context}: ${baseMessage} | Cause: ${nestedCause}`
    : `${context}: ${baseMessage}`;
}
