import { z } from "zod";

export type BillingMode = "account" | "session_gas_tank";
export type SettlementMode = "platform" | "direct";

export interface PaymentOptionDescriptor {
  protocol: string;
  chain_id: string;
  symbol: string;
  address: string;
}

export interface AuthorizationBridgeMetadata {
  checkoutUrl: string;
  buyUrl: string;
  checkoutSessionUrl: string;
  checkoutStatusUrlTemplate: string;
  publicResourceUrl: string;
  x402ListingUrl: string;
  mppServiceUrl: string;
  mppLlmsUrl: string;
}

export type PaymentRequiredBridgeDescriptor = AuthorizationBridgeMetadata;

export interface AuthorizationResponse {
  allowed: boolean;
  authorizationId?: string;
  charged?: boolean;
  reason?: string;
  balanceMinor?: number;
  priceMinor?: number;
  billingMode?: BillingMode;
  settlementMode?: SettlementMode;
  recipientWalletAddress?: string;
  recipientNetwork?: string;
  recipientCurrency?: string;
  paymentOptions?: ReadonlyArray<PaymentOptionDescriptor>;
  retryEndpoint?: string;
  resourceKey?: string;
  operation?: string;
  bridge?: AuthorizationBridgeMetadata;
}

export interface AuthorizePaymentRequest {
  requestId: string;
  tokenOrUuid: string;
  operation?: string;
  resourceId?: string;
  priceMinor?: number;
  priceUsd?: string;
}

export type CheckoutChain = "solana" | "base" | "SOLANA" | "BASE";

export interface CreateCheckoutSessionRequest {
  resourceId: string;
  chain?: CheckoutChain;
}

export interface CheckoutSessionRecord {
  paymentId: string;
  status: string;
  expiresAt: string | null;
  network: string;
  selectedNetwork: string;
  availableNetworks: ReadonlyArray<string>;
  currency: string;
  recipientWalletAddress: string;
  amountUsd: string;
  amountMinor: number | string;
  paymentMemo?: string | null;
  checkoutSecret?: null;
  checkoutAccessToken?: string | null;
  solanaReference?: string | null;
  solanaMemo?: string | null;
  solanaPayUrl?: string | null;
  eip681Url?: string | null;
}

export interface CheckoutStatusPendingRecord {
  paymentId: string;
  status: string;
  expiresAt: string | null;
  transactionHash?: string | null;
}

export interface CheckoutStatusConfirmedRecord {
  paymentId: string;
  status: "confirmed";
  accessToken: string;
  deliveryUrl: string;
}

export type CheckoutStatusRecord =
  | CheckoutStatusConfirmedRecord
  | CheckoutStatusPendingRecord;

export interface ConfirmCheckoutPaymentRequest {
  paymentId: string;
  network?: "solana" | "base";
  txHash?: string;
  checkoutSecret?: string;
}

export interface CheckoutConfirmConfirmedRecord {
  paymentId: string;
  status: "confirmed";
  accessToken: string;
  deliveryUrl: string;
}

export interface CheckoutConfirmPendingRecord {
  paymentId: string;
  status: "pending";
}

export type CheckoutConfirmRecord =
  | CheckoutConfirmConfirmedRecord
  | CheckoutConfirmPendingRecord;

export type SessionTankProfile = "DISCRETE" | "AUTO_REFILL";

export interface SessionTankRecord {
  tank_id: string;
  public_key: string;
  allocated_limit_usd: string;
  spent_total_usd: string;
  available_balance_usd: string;
}

export interface CreateSubTankRequest {
  publicKey: string;
  profile?: SessionTankProfile;
  limitUsd?: string;
  refillCapUsd?: string;
}

export interface DelegatedSessionRecord {
  session_id: string;
  session_token: string;
  tank_id: string;
  max_spend_usd: string;
  expires_at: string;
}

export interface DelegateSessionRequest {
  tankId: string;
  sandboxId: string;
  maxSpendUsd: string;
  ttlSeconds: number;
}

export interface SessionBalanceRecord {
  balance: string;
}

export interface IncrementSessionBalanceRequest {
  sessionId: string;
  amountUsd: string;
  idempotencyKey: string;
}

export type PayoutChain = "SOLANA" | "BASE";

export interface PublisherPayoutRecord {
  payout_id: string;
  remaining_credits_usd: string;
  chain: string;
  destination_address: string;
  status: string;
  hold_release_at?: string | null;
}

export interface RequestPublisherPayout {
  amountUsd: string;
  idempotencyKey: string;
  chain?: PayoutChain;
  destinationAddress?: string;
  challengeId?: string;
}

export interface PayoutWalletRecord {
  chain: string;
  currency: string;
  address: string;
  label?: string | null;
}

export interface PayoutWalletStatusRecord {
  wallets: ReadonlyArray<PayoutWalletRecord>;
  setup_complete?: boolean;
  solana_auto_payout_reset?: boolean;
  supported_chains: ReadonlyArray<string>;
  direct_payment_options: ReadonlyArray<{
    protocol?: string;
    chain_id?: string;
    symbol?: string;
    address?: string;
  }>;
}

export interface SavePayoutWalletsRequest {
  wallets: ReadonlyArray<{
    chain: PayoutChain;
    address: string;
    label?: string;
  }>;
  challengeId?: string;
}

export interface PayoutAutomationRecord {
  solana?: {
    enabled?: boolean;
    min_amount_usd?: string;
    interval_days?: number;
  };
  base?: {
    mode?: string;
    guidance?: string;
  };
}

export interface UpdatePayoutAutomationRequest {
  enabled?: boolean;
  minAmountUsd?: string;
  intervalDays?: number;
  challengeId?: string;
}

export interface ApiResponse {
  success: boolean;
  data?: unknown;
  error?: {
    code: string;
    message: string;
  };
}

export interface PaymentRequiredBody {
  success: true;
  data: {
    allowed: false;
    reason: string;
    retryAfterMs: number;
    balanceMinor?: number;
    priceMinor?: number;
    settlementMode?: SettlementMode;
    recipientWalletAddress?: string;
    recipientNetwork?: string;
    recipientCurrency?: string;
    paymentOptions?: ReadonlyArray<PaymentOptionDescriptor>;
    retryEndpoint?: string;
    resourceKey?: string;
    operation?: string;
    bridge?: AuthorizationBridgeMetadata;
  };
}

export declare const RequiredTrimmedStringSchema: z.ZodSchema<string>;
export declare const OptionalStringSchema: z.ZodSchema<string | undefined>;
export declare const GatewayUrlSchema: z.ZodSchema<string>;
export declare const buildApiPathSchema: (name: string) => z.ZodSchema<string>;
export declare const PaymentOptionSchema: z.ZodSchema<PaymentOptionDescriptor>;
export declare const AuthorizationBridgeMetadataSchema: z.ZodSchema<AuthorizationBridgeMetadata>;
export declare const AuthorizationResponseSchema: z.ZodSchema<AuthorizationResponse>;
export declare const AuthorizePaymentRequestSchema: z.ZodSchema<AuthorizePaymentRequest>;
export declare const CheckoutChainSchema: z.ZodSchema<CheckoutChain>;
export declare const CreateCheckoutSessionRequestSchema: z.ZodSchema<CreateCheckoutSessionRequest>;
export declare const CheckoutSessionSchema: z.ZodSchema<CheckoutSessionRecord>;
export declare const CheckoutStatusPendingSchema: z.ZodSchema<CheckoutStatusPendingRecord>;
export declare const CheckoutStatusConfirmedSchema: z.ZodSchema<CheckoutStatusConfirmedRecord>;
export declare const CheckoutStatusSchema: z.ZodSchema<CheckoutStatusRecord>;
export declare const ConfirmCheckoutPaymentRequestSchema: z.ZodSchema<ConfirmCheckoutPaymentRequest>;
export declare const CheckoutConfirmConfirmedSchema: z.ZodSchema<CheckoutConfirmConfirmedRecord>;
export declare const CheckoutConfirmPendingSchema: z.ZodSchema<CheckoutConfirmPendingRecord>;
export declare const CheckoutConfirmSchema: z.ZodSchema<CheckoutConfirmRecord>;
export declare const SessionTankProfileSchema: z.ZodSchema<SessionTankProfile>;
export declare const SessionTankSchema: z.ZodSchema<SessionTankRecord>;
export declare const CreateSubTankRequestSchema: z.ZodSchema<CreateSubTankRequest>;
export declare const DelegatedSessionSchema: z.ZodSchema<DelegatedSessionRecord>;
export declare const DelegateSessionRequestSchema: z.ZodSchema<DelegateSessionRequest>;
export declare const SessionBalanceSchema: z.ZodSchema<SessionBalanceRecord>;
export declare const SessionIncrementSchema: z.ZodSchema<{ success: boolean }>;
export declare const IncrementSessionBalanceRequestSchema: z.ZodSchema<IncrementSessionBalanceRequest>;
export declare const PayoutChainSchema: z.ZodSchema<PayoutChain>;
export declare const PayoutRequestSchema: z.ZodSchema<PublisherPayoutRecord>;
export declare const RequestPublisherPayoutSchema: z.ZodSchema<RequestPublisherPayout>;
export declare const PayoutWalletSchema: z.ZodSchema<PayoutWalletRecord>;
export declare const PayoutWalletStatusSchema: z.ZodSchema<PayoutWalletStatusRecord>;
export declare const SavePayoutWalletsRequestSchema: z.ZodSchema<SavePayoutWalletsRequest>;
export declare const PayoutAutomationSchema: z.ZodSchema<PayoutAutomationRecord>;
export declare const UpdatePayoutAutomationRequestSchema: z.ZodSchema<UpdatePayoutAutomationRequest>;
export declare const ApiResponseSchema: z.ZodSchema<ApiResponse>;
export declare const PaymentRequiredBodySchema: z.ZodSchema<PaymentRequiredBody>;

export declare const TDM_PAYMENT_REQUIRED_HEADERS: Readonly<{
  paymentRequired: "X-TDM-Payment-Required";
  settlementMode: "X-TDM-Settlement-Mode";
  recipient: "X-TDM-Recipient";
  retryEndpoint: "X-TDM-Retry-Endpoint";
  resourceKey: "X-TDM-Resource-Key";
  operation: "X-TDM-Operation";
  checkoutUrl: "X-TDM-Checkout-Url";
  buyUrl: "X-TDM-Buy-Url";
  publicResourceUrl: "X-TDM-Public-Resource-Url";
  x402ListingUrl: "X-TDM-X402-Listing-Url";
  mppServiceUrl: "X-TDM-MPP-Service-Url";
}>;

export declare function sanitizeErrorMessage(
  error: unknown,
  context: string,
): string;
