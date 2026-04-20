import bs58 from "bs58";
import nacl from "tweetnacl";
import { z } from "zod";
import lockfile from "proper-lockfile";
import {
  assertKeyringAvailable,
  buildKeyringRef,
  deleteKeyringSecret,
  getKeyringPassword,
  getKeyringSecret,
  setKeyringSecret,
} from "./keyring.js";
import { GatewayUrlSchema } from "../../runtime/gateway/gateway-schemas.js";
import { normalizeAllowlist } from "../trust/allowlist.js";
import { combineAbortSignals } from "../../abort-signals.js";

export interface LocalLedgerEntry {
  id: string;
  ts: string;
  kind:
    | "fuel"
    | "make_payable"
    | "sweep"
    | "cashout"
    | "stats"
    | "login"
    | "custom";
  status: "ok" | "pending" | "error";
  note?: string;
  amountUsd?: number;
  deltaUsd?: number;
  txId?: string;
}

export type ApiKeySource = "keyring" | "env" | "envfile" | "unknown";

export interface ResolvedApiKey {
  value: string;
  source: ApiKeySource;
}

export type AgentProfile = "DISCRETE" | "AUTO_REFILL";
export type AgentRegistrationStatus = "pending" | "registered";

export interface AgentConfig {
  profile: AgentProfile;
  public_key: string;
  keyring_ref: string;
  tank_id: string | null;
  registration_status: AgentRegistrationStatus;
  bound_storage?: string;
  limit?: number;
  refill_cap?: number;
  refill_source?: "root_vault";
  created_at: string;
  last_session_id?: string | null;
}

export interface RootVaultConfig {
  public_key: string;
  keyring_ref: string;
  tank_id?: string;
  api_key_ref?: string;
  api_key_source?: ApiKeySource;
}

export type ConnectedWalletProvider =
  | "phantom"
  | "solflare"
  | "backpack"
  | "glow"
  | "nightly"
  | "browser_solana"
  | "metamask"
  | "coinbase"
  | "rabby"
  | "brave"
  | "trust"
  | "browser_evm"
  | "privy"
  | "manual";

export interface ConnectedWalletInfo {
  address: string;
  provider: ConnectedWalletProvider;
  connected_at: string;
  funded_mint?: string;
}

export type LinkedWalletNetwork = "solana" | "evm";

export interface LinkedWalletInfo extends ConnectedWalletInfo {
  network: LinkedWalletNetwork;
  is_primary?: boolean;
}

export interface ConnectOnboardingState {
  payout_prompt_opt_out?: boolean;
}

export interface VaultCredentials {
  version: 3 | 4 | 5;
  installation_id?: string;
  root_vault: RootVaultConfig;
  agents: Record<string, AgentConfig>;
  runtime_allowlist?: string[];
  gateway_url?: string;
  api_key_ref?: string;
  api_key_source?: ApiKeySource;
  default_session_id?: string;
  connected_wallet?: ConnectedWalletInfo;
  linked_wallets?: LinkedWalletInfo[];
  connect_onboarding?: ConnectOnboardingState;
  created_at: string;
  updated_at: string;
  ledger: LocalLedgerEntry[];
}

export interface VaultRepairEntry {
  scope: "root_vault" | "agent";
  name?: string;
  keyringRef: string;
  status: "ok" | "repaired" | "error";
  previousPublicKey?: string;
  currentPublicKey?: string;
  message: string;
}

export interface VaultRepairReport {
  repaired: boolean;
  entries: VaultRepairEntry[];
}

export interface LocalVaultOptions {
  credentialsPath?: string;
  vaultName?: string;
  fetchImpl?: typeof fetch;
}

export interface RuntimeCredentialState {
  gatewayUrl?: string;
  apiKey?: string;
  rootId?: string;
  rootPublicKeyHex?: string;
  sessionId?: string;
  sessionToken?: string;
}

export interface ResolveRuntimeCredentialOptions {
  cwd?: string;
  credentialsPath?: string;
  vaultName?: string;
  overrides?: RuntimeCredentialState;
  allowVaultFallback?: boolean;
}

export interface SignatureEnvelope {
  rootId: string;
  signerPublicKeyBase58: string;
  signedAt: string;
  signatureBase58: string;
}

export interface DetachedSignatureEnvelope {
  signerId: string;
  signerPublicKeyBase58: string;
  signedAt: string;
  signatureBase58: string;
}

export interface AgentSummary {
  name: string;
  profile: AgentProfile;
  registrationStatus: AgentRegistrationStatus;
  tankId: string | null;
  boundStorageName: string | null;
  limitUsd: number | null;
  refillCapUsd: number | null;
  publicKeyHex: string;
  publicKeyBase58: string;
  lastSessionId: string | null;
}

export interface AgentLimitSummary {
  name: string;
  profile: AgentProfile;
  registrationStatus: AgentRegistrationStatus;
  tankId: string | null;
  boundStorageName: string | null;
  limitUsd: number | null;
  refillCapUsd: number | null;
}

export interface CreateAgentOptions {
  limit?: number;
  refillCap?: number;
  boundStorageName?: string;
}

export interface BootAgentOptions {
  sandboxId?: string;
  ttlSeconds?: number;
  maxSpend?: number;
}

interface NodeApis {
  fs: typeof import("node:fs/promises");
  path: typeof import("node:path");
  os: typeof import("node:os");
  crypto: typeof import("node:crypto");
  childProcess: typeof import("node:child_process");
}

interface StoredKeypairRecord {
  version: 1;
  publicKeyHex: string;
  secretKeyBase64: string;
  createdAt: string;
}

interface LegacySecretBundle {
  burnerSeedBase58?: string;
  burnerSecretKeyBase58: string;
  apiKey?: string;
}

interface LegacyCredentials {
  version: 1 | 2;
  burnerSeedBase58?: string;
  burnerPublicKeyBase58: string;
  burnerSecretKeyBase58?: string;
  apiKey?: string;
  gatewayUrl?: string;
  defaultSessionId?: string;
  createdAt: string;
  updatedAt: string;
  ledger: LocalLedgerEntry[];
}

const CREDENTIALS_VERSION = 5;
const CREDENTIALS_FILENAME = "credentials.json";
const CREDENTIALS_BACKUP_FILENAME = "credentials.backup.json";
const TDM_HOME_DIRNAME = ".tdm";
const VAULTS_DIRNAME = "vaults";
const ACTIVE_VAULT_FILENAME = "_active";
const LEDGER_LIMIT = 500;
const KEYRING_SERVICE = "tdm";
const ROOT_KEYRING_ACCOUNT = "root";
const API_KEYRING_ACCOUNT = "api-key";
const LEGACY_KEYRING_SERVICE = "tdm-sdk";
const LEGACY_KEYRING_NAMESPACE = "local-vault";
const VAULT_ENV_NAME = "TDM_VAULT";
const VALID_VAULT_NAME_REGEX = /^[a-z0-9][a-z0-9_-]{0,63}$/;

const ENV_KEY_MAP = {
  gatewayUrl: "TDM_GATEWAY_URL",
  apiKey: "TDM_API_KEY",
  rootId: "TDM_ROOT_ID",
  rootPublicKeyHex: "TDM_ROOT_PUBLIC_KEY",
  sessionId: "TDM_SESSION_ID",
  sessionToken: "TDM_SESSION_TOKEN",
  sandboxId: "TDM_SANDBOX_ID",
} as const;

function isNodeRuntime(): boolean {
  return typeof process !== "undefined" && Boolean(process.versions?.node);
}

async function loadNodeApis(): Promise<NodeApis> {
  if (!isNodeRuntime()) {
    throw new Error("LocalVault is only available in Node.js runtime");
  }
  const [fs, path, os, crypto, childProcess] = await Promise.all([
    import("node:fs/promises"),
    import("node:path"),
    import("node:os"),
    import("node:crypto"),
    import("node:child_process"),
  ]);
  return { fs, path, os, crypto, childProcess };
}

const LOCKFILE_RETRY_OPTIONS = {
  retries: 20,
  minTimeout: 200,
  maxTimeout: 1000,
};
const LOCKFILE_STALE_MS = 12_000;
const LOCKFILE_UPDATE_MS = 4_000;
const REQUEST_TIMEOUT_MS = 10_000;
const ATOMIC_RENAME_RETRY_CODES = new Set(["EPERM", "EBUSY", "EACCES"]);
const ATOMIC_RENAME_MAX_ATTEMPTS = 5;

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function renameWithRetry(
  fsApi: typeof import("node:fs/promises"),
  fromPath: string,
  toPath: string,
): Promise<void> {
  for (let attempt = 1; attempt <= ATOMIC_RENAME_MAX_ATTEMPTS; attempt += 1) {
    try {
      await fsApi.rename(fromPath, toPath);
      return;
    } catch (error) {
      const code =
        error && typeof error === "object" && "code" in error
          ? (error as { code?: unknown }).code
          : undefined;
      if (
        attempt >= ATOMIC_RENAME_MAX_ATTEMPTS ||
        typeof code !== "string" ||
        !ATOMIC_RENAME_RETRY_CODES.has(code)
      ) {
        throw error;
      }
      await delay(40 * attempt);
    }
  }
}

function sanitizeLocalVaultError(error: unknown): string {
  if (error instanceof Error && error.message.trim().length > 0) {
    return error.message;
  }
  if (typeof error === "string" && error.trim().length > 0) {
    return error;
  }
  return "Unknown error";
}

function isFsErrorCode(error: unknown, code: string): boolean {
  return Boolean(
    error &&
      typeof error === "object" &&
      "code" in error &&
      (error as { code?: unknown }).code === code,
  );
}

function warnLocalVault(
  message: string,
  _context: Record<string, unknown> = {},
): void {
  console.warn(`[TDM_LOCAL_VAULT_WARN] ${message}`);
}

function isEmptyRecord(value: unknown): value is Record<string, never> {
  return (
    value !== null &&
    typeof value === "object" &&
    !Array.isArray(value) &&
    Object.keys(value).length === 0
  );
}

function shouldSignRootGatewayRequest(
  method: "POST" | "DELETE",
  path: string,
): boolean {
  if (method === "POST" && path === "/v1/tanks/create-sub") {
    return true;
  }
  if (
    method === "DELETE" &&
    (path.startsWith("/v1/tanks/") || path.startsWith("/v1/sessions/"))
  ) {
    return true;
  }
  return false;
}

async function ensureFileExists(pathname: string): Promise<void> {
  const { fs, path } = await loadNodeApis();
  const dir = path.dirname(pathname);
  await fs.mkdir(dir, { recursive: true, mode: 0o700 });
  await applyLocalVaultPathPermissions(dir, "directory");
  try {
    await fs.access(pathname);
  } catch (error) {
    if (!isFsErrorCode(error, "ENOENT")) {
      throw error;
    }
    await fs.writeFile(pathname, "{}\n", { encoding: "utf8", mode: 0o600 });
    await applyLocalVaultPathPermissions(pathname, "file");
  }
}

export async function atomicWriteJson(
  pathname: string,
  data: unknown,
): Promise<void> {
  const { fs, path, crypto } = await loadNodeApis();
  const dir = path.dirname(pathname);
  const tmpPath = `${pathname}.${crypto.randomUUID()}.tmp`;
  const json = `${JSON.stringify(data, null, 2)}\n`;
  let handle: Awaited<ReturnType<typeof fs.open>> | null = null;
  try {
    await fs.mkdir(dir, { recursive: true, mode: 0o700 });
    await applyLocalVaultPathPermissions(dir, "directory");
    handle = await fs.open(tmpPath, "wx", 0o600);
    await handle.writeFile(json, { encoding: "utf8" });
    if (typeof handle.datasync === "function") {
      await handle.datasync();
    } else {
      await handle.sync();
    }
    await handle.close();
    handle = null;

    await renameWithRetry(fs, tmpPath, pathname);
    await applyLocalVaultPathPermissions(pathname, "file");
  } catch (error) {
    if (handle) {
      try {
        await handle.close();
      } catch {
        // Ignore secondary close failures during cleanup.
      }
    }
    try {
      await fs.unlink(tmpPath);
    } catch (cleanupError) {
      if (!isFsErrorCode(cleanupError, "ENOENT")) {
        warnLocalVault("Failed to clean up temporary vault file", {
          path: tmpPath,
          error: sanitizeLocalVaultError(cleanupError),
        });
      }
    }
    throw error;
  }
}

export async function applyLocalVaultPathPermissions(
  pathname: string,
  kind: "file" | "directory",
): Promise<void> {
  if (!isNodeRuntime()) {
    return;
  }

  if (process.platform !== "win32") {
    const { fs } = await loadNodeApis();
    try {
      await fs.chmod(pathname, kind === "directory" ? 0o700 : 0o600);
    } catch (error) {
      if (!isFsErrorCode(error, "ENOENT")) {
        warnLocalVault("POSIX path hardening failed", {
          path: pathname,
          kind,
          error: sanitizeLocalVaultError(error),
        });
      }
    }
    return;
  }

  const hardenToggle = process.env["TDM_WINDOWS_ACL_HARDEN"]
    ?.trim()
    .toLowerCase();
  if (
    hardenToggle === "1" ||
    hardenToggle === "true" ||
    hardenToggle === "on"
  ) {
    // explicitly enabled
  } else if (
    hardenToggle === "0" ||
    hardenToggle === "false" ||
    hardenToggle === "off"
  ) {
    return;
  } else {
    const argv1 =
      typeof process !== "undefined"
        ? (process.argv[1]?.replace(/\\/g, "/").toLowerCase() ?? "")
        : "";
    const cliLike =
      /(?:^|\/)(?:dist\/)?bin\/cli(?:\.[cm]?[jt]s)?$/.test(argv1) ||
      /(?:^|\/)tdm(?:\.[cm]?[jt]s)?$/.test(argv1);
    if (!cliLike) {
      return;
    }
  }

  const username = process.env["USERNAME"]?.trim();
  if (!username) {
    return;
  }

  const { childProcess } = await loadNodeApis();
  const grants =
    kind === "directory"
      ? [
          `${username}:F`,
          `${username}:(OI)(CI)F`,
          "*S-1-5-18:F",
          "*S-1-5-18:(OI)(CI)F",
          "*S-1-5-32-544:F",
          "*S-1-5-32-544:(OI)(CI)F",
        ]
      : [`${username}:F`, "*S-1-5-18:F", "*S-1-5-32-544:F"];
  const grantArgs = [
    pathname,
    "/inheritance:r",
    ...grants.flatMap((grant) => ["/grant:r", grant]),
  ];

  try {
    await new Promise<void>((resolve, reject) => {
      childProcess.execFile("icacls", grantArgs, (error) => {
        if (error) {
          reject(error);
          return;
        }
        resolve();
      });
    });
  } catch (error) {
    warnLocalVault("Windows ACL hardening failed", {
      path: pathname,
      kind,
      error: sanitizeLocalVaultError(error),
    });
  }
}

export interface VaultLockOptions {
  retries?:
    | number
    | { retries?: number; minTimeout?: number; maxTimeout?: number };
  staleMs?: number;
  updateMs?: number;
  lockfilePath?: string;
}

export async function withVaultLock<T>(
  pathname: string,
  operation: () => Promise<T>,
  options: VaultLockOptions = {},
): Promise<T> {
  await ensureFileExists(pathname);
  const staleMs = options.staleMs ?? LOCKFILE_STALE_MS;
  const release = await lockfile.lock(pathname, {
    retries: options.retries ?? LOCKFILE_RETRY_OPTIONS,
    stale: staleMs,
    update:
      options.updateMs ?? Math.min(LOCKFILE_UPDATE_MS, Math.floor(staleMs / 2)),
    lockfilePath: options.lockfilePath ?? `${pathname}.lock`,
    onCompromised: (error) => {
      throw new Error(
        `Local vault lock became compromised for ${pathname}. ` +
          `Retry the command after other TDM processes finish. ` +
          `Original error: ${sanitizeLocalVaultError(error)}`,
      );
    },
  });
  try {
    return await operation();
  } finally {
    await release();
  }
}

async function readJsonOrDefault<T>(pathname: string, fallback: T): Promise<T> {
  const { fs } = await loadNodeApis();
  try {
    return await withVaultLock(pathname, async () => {
      const raw = await fs.readFile(pathname, "utf8");
      const parsed = tryParseJson(raw, { context: pathname, logFailure: true });
      if (parsed !== null && typeof parsed === "object") {
        return parsed as T;
      }
      return fallback;
    });
  } catch (error) {
    if (!isFsErrorCode(error, "ENOENT")) {
      warnLocalVault("Failed to read JSON file, using fallback value", {
        pathname,
        error: sanitizeLocalVaultError(error),
      });
    }
  }
  return fallback;
}

function parseEnvContent(content: string): Record<string, string> {
  const result: Record<string, string> = {};
  const lines = content.split(/\r?\n/);

  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) {
      continue;
    }

    const sepIndex = trimmed.indexOf("=");
    if (sepIndex <= 0) {
      continue;
    }

    const key = trimmed.slice(0, sepIndex).trim();
    const rawValue = trimmed.slice(sepIndex + 1).trim();
    if (!key) {
      continue;
    }

    const quoted =
      (rawValue.startsWith('"') && rawValue.endsWith('"')) ||
      (rawValue.startsWith("'") && rawValue.endsWith("'"));
    const normalized = quoted ? rawValue.slice(1, -1) : rawValue;
    result[key] = normalized.replace(/\\n/g, "\n");
  }

  return result;
}

async function readEnvFile(pathname: string): Promise<Record<string, string>> {
  try {
    const { fs } = await loadNodeApis();
    const content = await fs.readFile(pathname, "utf8");
    return parseEnvContent(content);
  } catch (error) {
    if (!isFsErrorCode(error, "ENOENT")) {
      warnLocalVault("Failed to read env file", {
        pathname,
        error: sanitizeLocalVaultError(error),
      });
    }
    return {};
  }
}

async function resolveEnvApiKey(cwd?: string): Promise<ResolvedApiKey | null> {
  if (typeof process !== "undefined") {
    const envValue = asNonEmpty(process.env[ENV_KEY_MAP.apiKey]);
    if (envValue) {
      return { value: envValue, source: "env" };
    }
  }
  if (!isNodeRuntime()) {
    return null;
  }

  const { path } = await loadNodeApis();
  const root =
    cwd ?? (typeof process !== "undefined" ? process.cwd() : undefined);
  if (!root) {
    return null;
  }

  const envPath = path.join(root, ".env");
  const envLocalPath = path.join(root, ".env.local");
  const [dotenv, dotenvLocal] = await Promise.all([
    readEnvFile(envPath),
    readEnvFile(envLocalPath),
  ]);
  const envFileValue = asNonEmpty(
    dotenvLocal[ENV_KEY_MAP.apiKey] ?? dotenv[ENV_KEY_MAP.apiKey],
  );
  if (!envFileValue) {
    return null;
  }
  return { value: envFileValue, source: "envfile" };
}

function asNonEmpty(value: string | undefined): string | undefined {
  if (!value) {
    return undefined;
  }
  const trimmed = value.trim();
  return trimmed.length > 0 ? trimmed : undefined;
}

function tryParseJson(
  raw: string,
  options: { context?: string; logFailure?: boolean } = {},
): unknown | null {
  try {
    return JSON.parse(raw) as unknown;
  } catch (error) {
    if (options.logFailure) {
      warnLocalVault("Failed to parse JSON payload", {
        context: options.context ?? "unknown",
        error: sanitizeLocalVaultError(error),
      });
    }
    return null;
  }
}

function readObjectVersion(value: unknown): number | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    return undefined;
  }
  const candidate = (value as Record<string, unknown>)["version"];
  return typeof candidate === "number" && Number.isFinite(candidate)
    ? candidate
    : undefined;
}

function buildExistingCredentialsRefusal(
  pathname: string,
  reason: string,
): Error {
  return new Error(
    `[TDM] Existing vault credentials at ${pathname} are not readable by this SDK (${reason}). Refusing to reinitialize automatically.`,
  );
}

const EPOCH_ISO = new Date(0).toISOString();

const RequiredTrimmedStringSchema = z.string().trim().min(1);
const OptionalTrimmedStringSchema = z.preprocess(
  (value) =>
    typeof value === "string" ? value.trim() || undefined : undefined,
  z.string().trim().min(1).optional(),
);
const NullableTrimmedStringSchema = z
  .preprocess((value) => {
    if (value === null) {
      return null;
    }
    if (typeof value !== "string") {
      return undefined;
    }
    const trimmed = value.trim();
    return trimmed.length > 0 ? trimmed : undefined;
  }, z.string().trim().min(1).optional().nullable())
  .transform((value) => value ?? null);
const OptionalFiniteNumberSchema = z.preprocess(
  (value) =>
    typeof value === "number" && Number.isFinite(value) ? value : undefined,
  z.number().optional(),
);
const HexPublicKeySchema = z
  .string()
  .trim()
  .regex(/^[0-9a-f]{64}$/i)
  .transform((value) => value.toLowerCase());
const IsoStringWithEpochDefaultSchema = OptionalTrimmedStringSchema.transform(
  (value) => value ?? EPOCH_ISO,
);
const ApiKeySourceSchema = z.enum(["keyring", "env", "envfile", "unknown"]);
const AgentRegistrationStatusSchema = z
  .preprocess(
    (value) => (typeof value === "string" ? value : undefined),
    z.enum(["pending", "registered"]).optional(),
  )
  .transform((value) => value ?? "registered");

const LocalLedgerEntrySchema: z.ZodType<LocalLedgerEntry> = z.object({
  id: RequiredTrimmedStringSchema,
  ts: RequiredTrimmedStringSchema,
  kind: z.enum([
    "fuel",
    "make_payable",
    "sweep",
    "cashout",
    "stats",
    "login",
    "custom",
  ]),
  status: z.enum(["ok", "pending", "error"]),
  note: OptionalTrimmedStringSchema,
  amountUsd: OptionalFiniteNumberSchema,
  deltaUsd: OptionalFiniteNumberSchema,
  txId: OptionalTrimmedStringSchema,
});

const LedgerEntriesSchema = z
  .preprocess(
    (value) => (Array.isArray(value) ? value : []),
    z.array(z.unknown()),
  )
  .transform((entries) => {
    const parsed: LocalLedgerEntry[] = [];
    for (const entry of entries) {
      const result = LocalLedgerEntrySchema.safeParse(entry);
      if (result.success) {
        parsed.push(result.data);
      }
      if (parsed.length >= LEDGER_LIMIT) {
        break;
      }
    }
    return parsed;
  });

const AgentConfigSchema: z.ZodType<AgentConfig> = z.object({
  profile: z.enum(["DISCRETE", "AUTO_REFILL"]),
  public_key: HexPublicKeySchema,
  keyring_ref: RequiredTrimmedStringSchema,
  tank_id: NullableTrimmedStringSchema,
  registration_status: AgentRegistrationStatusSchema,
  bound_storage: OptionalTrimmedStringSchema,
  limit: OptionalFiniteNumberSchema,
  refill_cap: OptionalFiniteNumberSchema,
  refill_source: z.preprocess(
    (value) => (value === "root_vault" ? value : undefined),
    z.literal("root_vault").optional(),
  ),
  created_at: RequiredTrimmedStringSchema,
  last_session_id: NullableTrimmedStringSchema,
});

const AgentsSchema = z
  .preprocess(
    (value) =>
      value && typeof value === "object" && !Array.isArray(value) ? value : {},
    z.record(z.string(), z.unknown()),
  )
  .transform((entries) => {
    const parsed: Record<string, AgentConfig> = {};
    for (const [key, value] of Object.entries(entries)) {
      const result = AgentConfigSchema.safeParse(value);
      if (result.success) {
        parsed[key] = result.data;
      }
    }
    return parsed;
  });

const ConnectedWalletProviderSchema = z.enum([
  "phantom",
  "solflare",
  "backpack",
  "glow",
  "nightly",
  "browser_solana",
  "metamask",
  "coinbase",
  "rabby",
  "brave",
  "trust",
  "browser_evm",
  "privy",
  "manual",
]);

const ConnectedWalletInfoSchema: z.ZodType<ConnectedWalletInfo> = z.object({
  address: RequiredTrimmedStringSchema,
  provider: ConnectedWalletProviderSchema,
  connected_at: IsoStringWithEpochDefaultSchema,
  funded_mint: OptionalTrimmedStringSchema,
});

const LinkedWalletNetworkSchema = z.enum(["solana", "evm"]);

const LinkedWalletInfoSchema: z.ZodType<LinkedWalletInfo> = z.object({
  address: RequiredTrimmedStringSchema,
  provider: ConnectedWalletProviderSchema,
  connected_at: IsoStringWithEpochDefaultSchema,
  funded_mint: OptionalTrimmedStringSchema,
  network: LinkedWalletNetworkSchema,
  is_primary: z.boolean().optional(),
});

const ConnectedWalletSchema = z
  .preprocess((value) => value, z.unknown())
  .transform((value) => {
    const result = ConnectedWalletInfoSchema.safeParse(value);
    return result.success ? result.data : undefined;
  });

const LinkedWalletsSchema = z
  .array(LinkedWalletInfoSchema)
  .optional()
  .transform((value) => {
    if (!value || value.length === 0) {
      return undefined;
    }
    return value;
  });

const RootVaultSchema = z
  .object({
    public_key: HexPublicKeySchema,
    keyring_ref: RequiredTrimmedStringSchema,
    tank_id: OptionalTrimmedStringSchema,
    api_key_ref: OptionalTrimmedStringSchema,
    api_key_source: ApiKeySourceSchema.optional(),
  })
  .passthrough();

const VaultCredentialsSchema: z.ZodType<VaultCredentials> = z.object({
  version: z.union([z.literal(3), z.literal(4), z.literal(5)]),
  installation_id: z.string().uuid().optional(),
  root_vault: RootVaultSchema,
  agents: AgentsSchema,
  runtime_allowlist: z
    .array(z.string())
    .optional()
    .transform((value) => {
      if (!value) {
        return undefined;
      }
      const normalized = value
        .map((item) => item.trim().toLowerCase())
        .filter((item) => item.length > 0);
      return [...new Set(normalized)];
    }),
  gateway_url: OptionalTrimmedStringSchema,
  api_key_ref: OptionalTrimmedStringSchema,
  api_key_source: ApiKeySourceSchema.optional(),
  default_session_id: OptionalTrimmedStringSchema,
  connected_wallet: ConnectedWalletSchema.optional(),
  linked_wallets: LinkedWalletsSchema,
  connect_onboarding: z
    .object({
      payout_prompt_opt_out: z.boolean().optional(),
    })
    .optional(),
  created_at: IsoStringWithEpochDefaultSchema,
  updated_at: IsoStringWithEpochDefaultSchema,
  ledger: LedgerEntriesSchema,
});

const LegacyCredentialsSchema: z.ZodType<LegacyCredentials> = z.object({
  version: z.union([z.literal(1), z.literal(2)]),
  burnerSeedBase58: OptionalTrimmedStringSchema,
  burnerPublicKeyBase58: RequiredTrimmedStringSchema,
  burnerSecretKeyBase58: OptionalTrimmedStringSchema,
  apiKey: OptionalTrimmedStringSchema,
  gatewayUrl: OptionalTrimmedStringSchema,
  defaultSessionId: OptionalTrimmedStringSchema,
  createdAt: IsoStringWithEpochDefaultSchema,
  updatedAt: IsoStringWithEpochDefaultSchema,
  ledger: LedgerEntriesSchema,
});

const LegacySecretBundleSchema: z.ZodType<LegacySecretBundle> = z.object({
  burnerSeedBase58: OptionalTrimmedStringSchema,
  burnerSecretKeyBase58: RequiredTrimmedStringSchema,
  apiKey: OptionalTrimmedStringSchema,
});

const StoredKeypairRecordSchema: z.ZodType<StoredKeypairRecord> = z.object({
  version: z.literal(1),
  publicKeyHex: HexPublicKeySchema,
  secretKeyBase64: RequiredTrimmedStringSchema,
  createdAt: RequiredTrimmedStringSchema,
});

function inferLinkedWalletNetwork(
  input: Pick<ConnectedWalletInfo, "address" | "provider">,
): LinkedWalletNetwork | null {
  const address = input.address.trim();
  if (/^0x[a-fA-F0-9]{40}$/.test(address)) {
    return "evm";
  }
  if (/^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(address)) {
    return "solana";
  }
  if (
    input.provider === "phantom" ||
    input.provider === "solflare" ||
    input.provider === "backpack" ||
    input.provider === "glow" ||
    input.provider === "nightly" ||
    input.provider === "browser_solana"
  ) {
    return "solana";
  }
  if (
    input.provider === "metamask" ||
    input.provider === "coinbase" ||
    input.provider === "rabby" ||
    input.provider === "brave" ||
    input.provider === "trust" ||
    input.provider === "browser_evm"
  ) {
    return "evm";
  }
  return null;
}

function normalizeLinkedWallets(
  value: VaultCredentials,
): LinkedWalletInfo[] | undefined {
  const byNetwork = new Map<LinkedWalletNetwork, LinkedWalletInfo>();

  const sourceWallets = value.linked_wallets ?? [];
  for (const wallet of sourceWallets) {
    const network = wallet.network ?? inferLinkedWalletNetwork(wallet);
    if (!network) {
      continue;
    }
    if (!byNetwork.has(network)) {
      byNetwork.set(network, {
        address: wallet.address,
        provider: wallet.provider,
        connected_at: wallet.connected_at,
        funded_mint: wallet.funded_mint,
        network,
        is_primary: wallet.is_primary === true,
      });
    }
  }

  if (value.connected_wallet) {
    const primaryNetwork = inferLinkedWalletNetwork(value.connected_wallet);
    if (primaryNetwork) {
      byNetwork.set(primaryNetwork, {
        address: value.connected_wallet.address,
        provider: value.connected_wallet.provider,
        connected_at: value.connected_wallet.connected_at,
        funded_mint: value.connected_wallet.funded_mint,
        network: primaryNetwork,
        is_primary: true,
      });
    }
  }

  const normalized = Array.from(byNetwork.values());
  if (normalized.length === 0) {
    return undefined;
  }

  let primaryAssigned = false;
  for (const wallet of normalized) {
    if (wallet.is_primary && !primaryAssigned) {
      primaryAssigned = true;
      continue;
    }
    wallet.is_primary = false;
  }
  if (!primaryAssigned && normalized.length > 0) {
    normalized[0]!.is_primary = true;
  }

  return normalized;
}

function normalizeVaultCredentials(value: VaultCredentials): VaultCredentials {
  const apiKeyRef = value.root_vault.api_key_ref ?? value.api_key_ref;
  const apiKeySource =
    value.root_vault.api_key_source ??
    value.api_key_source ??
    (apiKeyRef ? "unknown" : undefined);
  const agents: Record<string, AgentConfig> = {};

  for (const [name, agent] of Object.entries(value.agents)) {
    const registration_status = agent.tank_id
      ? agent.registration_status
      : "pending";
    agents[name] = {
      ...agent,
      registration_status,
    };
  }

  const linkedWallets = normalizeLinkedWallets(value);
  const primaryWallet =
    linkedWallets?.find((wallet) => wallet.is_primary) ??
    value.connected_wallet;

  return {
    ...value,
    version: CREDENTIALS_VERSION,
    root_vault: {
      ...value.root_vault,
      api_key_ref: apiKeyRef,
      api_key_source: apiKeySource,
    },
    agents,
    connected_wallet: primaryWallet
      ? {
          address: primaryWallet.address,
          provider: primaryWallet.provider,
          connected_at: primaryWallet.connected_at,
          funded_mint: primaryWallet.funded_mint,
        }
      : undefined,
    linked_wallets: linkedWallets,
    api_key_ref: undefined,
    api_key_source: undefined,
  };
}

function canonicalizeJson(value: unknown): string {
  if (value === null || typeof value !== "object") {
    return JSON.stringify(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalizeJson(item)).join(",")}]`;
  }

  const objectValue = value as Record<string, unknown>;
  const keys = Object.keys(objectValue).sort();
  const pairs = keys.map(
    (key) => `${JSON.stringify(key)}:${canonicalizeJson(objectValue[key])}`,
  );
  return `{${pairs.join(",")}}`;
}

export function warnIfPlaintext(source: ApiKeySource): void {
  if (source === "env" || source === "envfile") {
    console.warn(
      "\n⚠️  Security warning: API key loaded from plaintext source " +
        `(${source}).\n` +
        "   Anyone with access to your environment or files can steal it.\n" +
        "   This is the same attack vector used in the Perplexity hack.\n" +
        "   Secure it now: tdm auth set-key\n",
    );
  }
}

function requireBase58Bytes(
  value: string | undefined,
  expectedLength: number,
  label: string,
): Uint8Array {
  if (!value) {
    throw new Error(`${label} is missing`);
  }
  const bytes = bs58.decode(value);
  if (bytes.byteLength !== expectedLength) {
    throw new Error(`${label} must be ${expectedLength} bytes`);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("hex");
}

function hexToBytes(hex: string, expectedLength?: number): Uint8Array {
  const normalized = hex.trim().toLowerCase();
  if (!/^[0-9a-f]+$/.test(normalized) || normalized.length % 2 !== 0) {
    throw new Error("Invalid hex string");
  }
  const bytes = new Uint8Array(Buffer.from(normalized, "hex"));
  if (expectedLength !== undefined && bytes.length !== expectedLength) {
    throw new Error(`Hex value must be ${expectedLength} bytes`);
  }
  return bytes;
}

function normalizeAgentName(name: string): string {
  const trimmed = name.trim();
  if (!trimmed) {
    throw new Error("Agent name is required");
  }
  if (!/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}$/.test(trimmed)) {
    throw new Error(
      "Agent name must use letters, numbers, dot, underscore, or hyphen",
    );
  }
  return trimmed;
}

function normalizeAgentStorageName(
  value: string | undefined,
): string | undefined {
  const trimmed = value?.trim().toLowerCase();
  if (!trimmed) {
    return undefined;
  }
  if (!/^[a-z0-9][a-z0-9_-]{0,62}$/.test(trimmed)) {
    throw new Error(
      "Storage name must use lowercase letters, numbers, underscore, or hyphen",
    );
  }
  return trimmed;
}

function cloneCredentials(value: VaultCredentials): VaultCredentials {
  return {
    ...value,
    root_vault: { ...value.root_vault },
    agents: Object.fromEntries(
      Object.entries(value.agents).map(([key, agent]) => [key, { ...agent }]),
    ),
    runtime_allowlist: value.runtime_allowlist
      ? [...value.runtime_allowlist]
      : undefined,
    connected_wallet: value.connected_wallet
      ? { ...value.connected_wallet }
      : undefined,
    linked_wallets: value.linked_wallets
      ? value.linked_wallets.map((wallet) => ({ ...wallet }))
      : undefined,
    connect_onboarding: value.connect_onboarding
      ? { ...value.connect_onboarding }
      : undefined,
    ledger: [...value.ledger],
  };
}

export function signStructuredPayload(
  payload: unknown,
  signer: {
    rootId: string;
    burnerPublicKeyBase58: string;
    burnerSecretKeyBase58: string;
  },
  signedAt: string = new Date().toISOString(),
): SignatureEnvelope {
  const secretKey = requireBase58Bytes(
    signer.burnerSecretKeyBase58,
    nacl.sign.secretKeyLength,
    "burnerSecretKeyBase58",
  );
  const publicKey = requireBase58Bytes(
    signer.burnerPublicKeyBase58,
    nacl.sign.publicKeyLength,
    "burnerPublicKeyBase58",
  );

  const signedPayload = `${signedAt}.${canonicalizeJson(payload)}`;
  const encoded = new TextEncoder().encode(signedPayload);
  const signature = nacl.sign.detached(encoded, secretKey);

  return {
    rootId: signer.rootId,
    signerPublicKeyBase58: bs58.encode(publicKey),
    signedAt,
    signatureBase58: bs58.encode(signature),
  };
}

export class LocalVault {
  private readonly credentialsPathOverride?: string;
  private readonly vaultNameOverride?: string;
  private readonly fetchImpl?: typeof fetch;
  private lockQueue: Promise<void> = Promise.resolve();
  private rootGatewaySignerPromise: Promise<{
    keyringRef: string;
    publicKeyHex: string;
    publicKeyBytes: Uint8Array;
    secretKey: Uint8Array;
  }> | null = null;

  constructor(options: LocalVaultOptions = {}) {
    this.credentialsPathOverride = options.credentialsPath;
    const normalizedVault = LocalVault.normalizeVaultNameOptional(
      options.vaultName,
    );
    this.vaultNameOverride =
      normalizedVault === "default" ? undefined : normalizedVault;
    this.fetchImpl = options.fetchImpl;
  }

  public static normalizeVaultName(name: string): string {
    const normalized = name.trim().toLowerCase();
    if (!normalized) {
      throw new Error("Vault name must be non-empty");
    }
    if (normalized === "default") {
      return normalized;
    }
    if (!VALID_VAULT_NAME_REGEX.test(normalized)) {
      throw new Error(
        "Vault name must start with a letter or number and use only lowercase letters, numbers, hyphens, or underscores.",
      );
    }
    return normalized;
  }

  public static normalizeVaultNameOptional(
    name: string | undefined,
  ): string | undefined {
    if (!name) {
      return undefined;
    }
    return this.normalizeVaultName(name);
  }

  private static async resolveHomeDir(): Promise<string> {
    const { os } = await loadNodeApis();
    const envHome =
      asNonEmpty(
        typeof process !== "undefined" ? process.env["HOME"] : undefined,
      ) ??
      asNonEmpty(
        typeof process !== "undefined" ? process.env["USERPROFILE"] : undefined,
      );
    return envHome ?? os.homedir();
  }

  private static async resolveTdmHomeDir(): Promise<string> {
    const { path } = await loadNodeApis();
    return path.join(await this.resolveHomeDir(), TDM_HOME_DIRNAME);
  }

  public static async resolveVaultsDir(): Promise<string> {
    const { path } = await loadNodeApis();
    return path.join(await this.resolveTdmHomeDir(), VAULTS_DIRNAME);
  }

  public static async resolveActiveVaultPath(): Promise<string> {
    const { path } = await loadNodeApis();
    return path.join(await this.resolveVaultsDir(), ACTIVE_VAULT_FILENAME);
  }

  public static async getActiveVaultName(): Promise<string | undefined> {
    if (!isNodeRuntime()) {
      return undefined;
    }

    const envValue = asNonEmpty(
      typeof process !== "undefined" ? process.env[VAULT_ENV_NAME] : undefined,
    );
    if (envValue) {
      return this.normalizeVaultName(envValue);
    }

    const { fs } = await loadNodeApis();
    const pathname = await this.resolveActiveVaultPath();
    try {
      const raw = await fs.readFile(pathname, "utf8");
      return this.normalizeVaultNameOptional(raw.trim());
    } catch (error) {
      if (!isFsErrorCode(error, "ENOENT")) {
        warnLocalVault("Failed to read active vault marker", {
          pathname,
          error: sanitizeLocalVaultError(error),
        });
      }
      return undefined;
    }
  }

  public static async setActiveVaultName(vaultName: string): Promise<void> {
    const normalized = this.normalizeVaultName(vaultName);
    const { fs, path } = await loadNodeApis();
    const pathname = await this.resolveActiveVaultPath();
    await fs.mkdir(path.dirname(pathname), { recursive: true, mode: 0o700 });
    await applyLocalVaultPathPermissions(path.dirname(pathname), "directory");
    await fs.writeFile(pathname, `${normalized}\n`, {
      encoding: "utf8",
      mode: 0o600,
    });
    await applyLocalVaultPathPermissions(pathname, "file");
  }

  public static async clearActiveVaultName(): Promise<void> {
    const { fs } = await loadNodeApis();
    const pathname = await this.resolveActiveVaultPath();
    try {
      await fs.unlink(pathname);
    } catch (error) {
      if (!isFsErrorCode(error, "ENOENT")) {
        throw error;
      }
    }
  }

  public static async listNamedVaults(): Promise<string[]> {
    if (!isNodeRuntime()) {
      return [];
    }
    const { fs } = await loadNodeApis();
    const vaultsDir = await this.resolveVaultsDir();
    try {
      const entries = await fs.readdir(vaultsDir, { withFileTypes: true });
      return entries
        .filter((entry) => entry.isDirectory())
        .map((entry) => entry.name)
        .filter((name) => name !== ACTIVE_VAULT_FILENAME)
        .filter((name) => VALID_VAULT_NAME_REGEX.test(name))
        .sort((a, b) => a.localeCompare(b));
    } catch (error) {
      if (isFsErrorCode(error, "ENOENT")) {
        return [];
      }
      throw error;
    }
  }

  public static async resolveSelectedVaultName(
    vaultName?: string,
  ): Promise<string | undefined> {
    const explicit = this.normalizeVaultNameOptional(vaultName);
    if (explicit) {
      return explicit === "default" ? undefined : explicit;
    }
    const active = await this.getActiveVaultName();
    return active === "default" ? undefined : active;
  }

  public static async resolveCredentialsPath(
    credentialsPath?: string,
    vaultName?: string,
  ): Promise<string> {
    if (credentialsPath) {
      return credentialsPath;
    }

    const { path } = await loadNodeApis();
    const selectedVault = await this.resolveSelectedVaultName(vaultName);
    if (selectedVault) {
      return path.join(
        await this.resolveVaultsDir(),
        selectedVault,
        CREDENTIALS_FILENAME,
      );
    }
    return path.join(await this.resolveTdmHomeDir(), CREDENTIALS_FILENAME);
  }

  public static async resolveCredentialsBackupPath(
    credentialsPath?: string,
    vaultName?: string,
  ): Promise<string> {
    const { path } = await loadNodeApis();
    const primaryPath = await this.resolveCredentialsPath(
      credentialsPath,
      vaultName,
    );
    return path.join(path.dirname(primaryPath), CREDENTIALS_BACKUP_FILENAME);
  }

  private async withVaultLock<T>(operation: () => Promise<T>): Promise<T> {
    const previous = this.lockQueue;
    let releaseQueue: (() => void) | undefined;
    this.lockQueue = new Promise<void>((resolve) => {
      releaseQueue = resolve;
    });

    await previous.catch(() => undefined);
    try {
      const pathname = await this.getCredentialsPath();
      return await withVaultLock(pathname, operation);
    } finally {
      releaseQueue?.();
    }
  }

  public async ensureInitialized(): Promise<VaultCredentials> {
    return this.withVaultLock(async () => this.ensureInitializedUnlocked());
  }

  private async ensureInitializedUnlocked(): Promise<VaultCredentials> {
    await assertKeyringAvailable();
    const current = await this.readCredentials();
    if (current) {
      await this.ensureRootKeypair(current);
      await this.writeCredentials(current);
      return cloneCredentials(current);
    }

    const legacy = await this.readLegacyCredentials();
    if (legacy) {
      const migrated = await this.migrateLegacyCredentials(legacy);
      await this.writeCredentials(migrated);
      return cloneCredentials(migrated);
    }

    const created = await this.createFreshCredentials();
    await this.writeCredentials(created);
    return cloneCredentials(created);
  }

  public async readCredentials(): Promise<VaultCredentials | null> {
    const { fs } = await loadNodeApis();
    const pathname = await this.getCredentialsPath();
    const backupPath = await LocalVault.resolveCredentialsBackupPath(
      this.credentialsPathOverride,
      this.vaultNameOverride,
    );

    const tryReadBackup = async (
      reason: string,
    ): Promise<VaultCredentials | null> => {
      try {
        const backupRaw = await fs.readFile(backupPath, "utf8");
        const backupParsed = tryParseJson(backupRaw, {
          context: backupPath,
          logFailure: true,
        });
        if (!backupParsed || isEmptyRecord(backupParsed)) {
          return null;
        }
        const normalized = VaultCredentialsSchema.parse(backupParsed);
        const restored = normalizeVaultCredentials(normalized);
        try {
          await fs.copyFile(backupPath, pathname);
        } catch (copyError) {
          warnLocalVault(
            "Recovered credentials from backup but failed to restore primary file",
            {
              pathname,
              backupPath,
              error: sanitizeLocalVaultError(copyError),
            },
          );
        }
        warnLocalVault("Recovered vault credentials from quiet backup", {
          pathname,
          backupPath,
          reason,
        });
        return restored;
      } catch {
        return null;
      }
    };

    try {
      const raw = await fs.readFile(pathname, "utf8");
      const parsed = tryParseJson(raw, { context: pathname, logFailure: true });
      if (!parsed) {
        const recovered = await tryReadBackup("invalid JSON");
        if (recovered) {
          return recovered;
        }
        throw buildExistingCredentialsRefusal(pathname, "invalid JSON");
      }
      if (isEmptyRecord(parsed)) {
        return null;
      }
      const version = readObjectVersion(parsed);
      if (version === 1 || version === 2) {
        return null;
      }

      try {
        const normalized = VaultCredentialsSchema.parse(parsed);
        return normalizeVaultCredentials(normalized);
      } catch (error) {
        const recovered = await tryReadBackup(
          "unsupported or malformed schema",
        );
        if (recovered) {
          return recovered;
        }
        throw buildExistingCredentialsRefusal(
          pathname,
          "unsupported or malformed schema",
        );
      }
    } catch (error) {
      if (
        error instanceof Error &&
        error.message.startsWith("[TDM] Existing vault credentials at ")
      ) {
        throw error;
      }
      if (!isFsErrorCode(error, "ENOENT")) {
        warnLocalVault("Failed to read vault credentials", {
          pathname,
          error: sanitizeLocalVaultError(error),
        });
      }
      return null;
    }
  }

  private keyringAccount(account: string): string {
    return this.vaultNameOverride
      ? `vault:${this.vaultNameOverride}:${account}`
      : account;
  }

  private keyringAccountForAgent(agentName: string): string {
    return this.vaultNameOverride
      ? this.keyringAccount(`agent:${agentName}`)
      : agentName;
  }

  private buildVaultKeyringRef(account: string): string {
    return buildKeyringRef(KEYRING_SERVICE, this.keyringAccount(account));
  }

  public async getCredentials(): Promise<VaultCredentials> {
    const current = await this.ensureInitialized();
    return cloneCredentials(current);
  }

  public async getInstallationId(): Promise<string> {
    return this.withVaultLock(async () => {
      const current = await this.ensureInitializedUnlocked();
      if (current.installation_id) {
        return current.installation_id;
      }

      const { crypto } = await loadNodeApis();
      current.installation_id = crypto.randomUUID();
      current.updated_at = new Date().toISOString();
      await this.writeCredentials(current);
      return current.installation_id;
    });
  }

  public async listAgents(): Promise<AgentConfig[]> {
    const current = await this.ensureInitialized();
    return Object.values(current.agents).map((agent) => ({ ...agent }));
  }

  public async getRuntimeAllowlist(): Promise<string[]> {
    const current = await this.ensureInitialized();
    return normalizeAllowlist(current.runtime_allowlist ?? []);
  }

  public async setRuntimeAllowlist(
    domains: readonly string[],
  ): Promise<string[]> {
    return this.withVaultLock(async () => {
      const current = await this.ensureInitializedUnlocked();
      current.runtime_allowlist = normalizeAllowlist(domains);
      current.updated_at = new Date().toISOString();
      await this.writeCredentials(current);
      return [...current.runtime_allowlist];
    });
  }

  public async getRootPrivateKey(): Promise<Uint8Array> {
    const current = await this.ensureInitialized();
    const record = await this.readKeypairRecord(
      current.root_vault.keyring_ref,
      current.root_vault.public_key,
    );
    return new Uint8Array(record.secretKey);
  }

  public async getAgentPrivateKey(name: string): Promise<Uint8Array> {
    const current = await this.ensureInitialized();
    const normalizedName = normalizeAgentName(name);
    const agent = current.agents[normalizedName];
    if (!agent) {
      throw new Error(`Agent "${normalizedName}" not found`);
    }
    if (agent.registration_status === "pending" || !agent.tank_id) {
      throw new Error(
        `Agent "${normalizedName}" is not registered with Gateway.\n` +
          `Run: tdm agent register ${normalizedName}`,
      );
    }
    const record = await this.readKeypairRecord(
      agent.keyring_ref,
      agent.public_key,
    );
    return new Uint8Array(record.secretKey);
  }

  public async createAgent(
    name: string,
    profile: AgentProfile,
    options: CreateAgentOptions = {},
  ): Promise<AgentConfig> {
    const preparation = await this.withVaultLock(async () => {
      const current = await this.ensureInitializedUnlocked();
      const normalizedName = normalizeAgentName(name);
      if (current.agents[normalizedName]) {
        throw new Error(`Agent "${normalizedName}" already exists`);
      }

      const keyringRef = buildKeyringRef(
        KEYRING_SERVICE,
        this.keyringAccountForAgent(normalizedName),
      );
      const existing = await getKeyringSecret(keyringRef);
      if (existing) {
        throw new Error(
          `Keyring entry already exists for agent "${normalizedName}"`,
        );
      }

      const limit = options.limit;
      const refillCap = options.refillCap;
      if (profile === "DISCRETE") {
        if (!limit || !Number.isFinite(limit) || limit <= 0) {
          throw new Error("DISCRETE agent requires a positive --limit value");
        }
      }
      if (profile === "AUTO_REFILL") {
        if (!refillCap || !Number.isFinite(refillCap) || refillCap <= 0) {
          throw new Error("AUTO_REFILL agent requires a positive --cap value");
        }
      }

      const pair = nacl.sign.keyPair();
      const publicKeyHex = bytesToHex(pair.publicKey);
      await this.storeKeypairRecord(keyringRef, publicKeyHex, pair.secretKey);

      const now = new Date().toISOString();
      const agent: AgentConfig = {
        profile,
        public_key: publicKeyHex,
        keyring_ref: keyringRef,
        tank_id: null,
        registration_status: "pending",
        bound_storage: normalizeAgentStorageName(options.boundStorageName),
        limit: profile === "DISCRETE" ? limit : undefined,
        refill_cap: profile === "AUTO_REFILL" ? refillCap : undefined,
        refill_source: profile === "AUTO_REFILL" ? "root_vault" : undefined,
        created_at: now,
        last_session_id: null,
      };

      current.agents[normalizedName] = agent;
      current.updated_at = now;
      await this.writeCredentials(current);

      const payload = this.buildAgentRegistrationPayload(agent, normalizedName);
      return { normalizedName, agent: { ...agent }, payload };
    });

    try {
      const tankId = await this.registerAgentRemote(preparation.payload);
      const registered = await this.updateAgentRegistration(
        preparation.normalizedName,
        tankId,
      );
      return { ...registered };
    } catch (error) {
      console.warn(
        `⚠️  Agent "${preparation.normalizedName}" created locally but Gateway registration failed.\n` +
          `   Run: tdm agent register ${preparation.normalizedName} when Gateway is available.\n` +
          `   Reason: ${sanitizeLocalVaultError(error)}`,
      );
      return { ...preparation.agent };
    }
  }

  public async registerAgent(name: string): Promise<AgentConfig> {
    const preparation = await this.withVaultLock(async () => {
      const current = await this.ensureInitializedUnlocked();
      const normalizedName = normalizeAgentName(name);
      const agent = current.agents[normalizedName];
      if (!agent) {
        throw new Error(`Agent "${normalizedName}" not found`);
      }
      if (agent.registration_status === "registered" && agent.tank_id) {
        return { status: "registered" as const, agent: { ...agent } };
      }
      const payload = this.buildAgentRegistrationPayload(agent, normalizedName);
      return {
        status: "pending" as const,
        agent: { ...agent },
        payload,
        normalizedName,
      };
    });

    if (preparation.status === "registered") {
      return preparation.agent;
    }

    try {
      const tankId = await this.registerAgentRemote(preparation.payload);
      const registered = await this.updateAgentRegistration(
        preparation.normalizedName,
        tankId,
      );
      return { ...registered };
    } catch (error) {
      console.warn(
        `⚠️  Agent "${preparation.normalizedName}" registration failed.\n` +
          `   Run: tdm agent register ${preparation.normalizedName} when Gateway is available.\n` +
          `   Reason: ${sanitizeLocalVaultError(error)}`,
      );
      return { ...preparation.agent };
    }
  }

  private buildAgentRegistrationPayload(
    agent: AgentConfig,
    normalizedName: string,
  ): Record<string, unknown> {
    const gatewayPublicKey = this.agentGatewayPublicKey(agent.public_key);
    const payload: Record<string, unknown> = {
      profile: agent.profile,
      public_key: gatewayPublicKey,
    };
    if (agent.profile === "DISCRETE") {
      if (!agent.limit || !Number.isFinite(agent.limit) || agent.limit <= 0) {
        throw new Error(`Agent "${normalizedName}" has invalid limit`);
      }
      payload["limit"] = this.formatGatewayDecimalAmount(agent.limit);
    } else {
      if (
        !agent.refill_cap ||
        !Number.isFinite(agent.refill_cap) ||
        agent.refill_cap <= 0
      ) {
        throw new Error(`Agent "${normalizedName}" has invalid refill cap`);
      }
      payload["refill_cap"] = this.formatGatewayDecimalAmount(agent.refill_cap);
      payload["refill_source"] = "root_vault";
    }
    return payload;
  }

  private async registerAgentRemote(
    payload: Record<string, unknown>,
  ): Promise<string> {
    const response = await this.requestGatewayJson(
      "POST",
      "/v1/tanks/create-sub",
      payload,
    );
    const tankId = this.readTankId(response);
    if (!tankId) {
      throw new Error("Gateway response did not include tank_id");
    }
    return tankId;
  }

  private async updateAgentRegistration(
    normalizedName: string,
    tankId: string,
  ): Promise<AgentConfig> {
    return this.withVaultLock(async () => {
      const current = await this.ensureInitializedUnlocked();
      const agent = current.agents[normalizedName];
      if (!agent) {
        throw new Error(`Agent "${normalizedName}" not found`);
      }
      if (agent.registration_status === "registered" && agent.tank_id) {
        return { ...agent };
      }
      agent.tank_id = tankId;
      agent.registration_status = "registered";
      current.agents[normalizedName] = agent;
      current.updated_at = new Date().toISOString();
      await this.writeCredentials(current);
      return { ...agent };
    });
  }

  public async revokeAgent(name: string): Promise<void> {
    const snapshot = await this.withVaultLock(async () => {
      const current = await this.ensureInitializedUnlocked();
      const normalizedName = normalizeAgentName(name);
      const agent = current.agents[normalizedName];
      if (!agent) {
        throw new Error(`Agent "${normalizedName}" not found`);
      }
      return { normalizedName, agent: { ...agent } };
    });

    if (
      snapshot.agent.registration_status === "registered" &&
      snapshot.agent.tank_id
    ) {
      if (snapshot.agent.last_session_id) {
        await this.requestGatewayJson(
          "DELETE",
          `/v1/sessions/${encodeURIComponent(snapshot.agent.last_session_id)}`,
          undefined,
          { allowNotFound: true },
        );
      }

      await this.requestGatewayJson(
        "DELETE",
        `/v1/tanks/${encodeURIComponent(snapshot.agent.tank_id)}`,
        undefined,
      );
    }

    await this.withVaultLock(async () => {
      const current = await this.ensureInitializedUnlocked();
      const agent = current.agents[snapshot.normalizedName];
      if (!agent) {
        return;
      }
      await deleteKeyringSecret(agent.keyring_ref);
      delete current.agents[snapshot.normalizedName];
      current.updated_at = new Date().toISOString();
      await this.writeCredentials(current);
    });
  }

  public async bootAgent(
    name: string,
    options: BootAgentOptions = {},
  ): Promise<{ sessionToken: string; expiresAt: Date }> {
    const preparation = await this.withVaultLock(async () => {
      const current = await this.ensureInitializedUnlocked();
      const normalizedName = normalizeAgentName(name);
      const agent = current.agents[normalizedName];
      if (!agent) {
        throw new Error(`Agent "${normalizedName}" not found`);
      }

      const maxSpend =
        options.maxSpend ??
        (agent.profile === "DISCRETE" ? agent.limit : agent.refill_cap);
      if (!maxSpend || !Number.isFinite(maxSpend) || maxSpend <= 0) {
        throw new Error(
          `Agent "${normalizedName}" is missing a valid spend limit`,
        );
      }

      const ttlSeconds = options.ttlSeconds ?? 3600;
      if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) {
        throw new Error("ttlSeconds must be a positive number");
      }

      const sandboxId = await this.resolveSandboxId(options.sandboxId);
      const unsignedPayload: Record<string, unknown> = {
        sandbox_id: sandboxId,
        max_spend: this.formatGatewayDecimalAmount(maxSpend),
        ttl_seconds: ttlSeconds,
        tank_id: agent.tank_id,
      };

      const body = JSON.stringify(unsignedPayload);
      const timestamp = Date.now().toString();
      const nonce = crypto.randomUUID();
      const message = `POST:/v1/sessions/delegate:${timestamp}:${nonce}:${body}`;
      const signatureBase58 = await this.signAgentGatewayPayload(
        message,
        agent,
      );
      const headers = {
        "X-TDM-Nonce": nonce,
        "X-TDM-Timestamp": timestamp,
        "X-TDM-Public-Key": this.agentGatewayPublicKey(agent.public_key),
        "X-TDM-Signature": signatureBase58,
      };

      return {
        normalizedName,
        unsignedPayload,
        headers,
        ttlSeconds,
        sandboxId,
      };
    });

    const response = await this.requestGatewayJson(
      "POST",
      "/v1/sessions/delegate",
      preparation.unsignedPayload,
      { headers: preparation.headers },
    );

    const sessionToken = this.readStringField(
      response,
      "session_token",
      "sessionToken",
      "token",
    );
    const sessionId = this.readStringField(
      response,
      "session_id",
      "sessionId",
      "id",
    );
    const expiresAtRaw = this.readStringField(
      response,
      "expires_at",
      "expiresAt",
    );
    if (!sessionToken || !sessionId) {
      throw new Error("Gateway response missing session token");
    }

    const expiresAt = expiresAtRaw
      ? new Date(expiresAtRaw)
      : new Date(Date.now() + preparation.ttlSeconds * 1000);
    if (Number.isNaN(expiresAt.getTime())) {
      throw new Error("Invalid expires_at value in session response");
    }

    await this.withVaultLock(async () => {
      const current = await this.ensureInitializedUnlocked();
      const agent = current.agents[preparation.normalizedName];
      if (!agent) {
        throw new Error(`Agent "${preparation.normalizedName}" not found`);
      }
      agent.last_session_id = sessionId;
      current.agents[preparation.normalizedName] = agent;
      current.updated_at = new Date().toISOString();
      await this.writeCredentials(current);
    });

    return { sessionToken, expiresAt };
  }

  public async setApiKey(apiKey: string): Promise<VaultCredentials> {
    return this.withVaultLock(async () => {
      const current = await this.ensureInitializedUnlocked();
      const normalized = asNonEmpty(apiKey);
      const apiKeyRef =
        current.root_vault.api_key_ref ??
        current.api_key_ref ??
        this.buildVaultKeyringRef(API_KEYRING_ACCOUNT);
      if (normalized) {
        await setKeyringSecret(apiKeyRef, normalized);
        current.root_vault.api_key_ref = apiKeyRef;
        current.root_vault.api_key_source = "keyring";
      } else if (current.root_vault.api_key_ref || current.api_key_ref) {
        await deleteKeyringSecret(apiKeyRef);
        current.root_vault.api_key_ref = undefined;
        current.root_vault.api_key_source = undefined;
      }
      current.updated_at = new Date().toISOString();
      await this.writeCredentials(current);
      return cloneCredentials(current);
    });
  }

  public async setGatewayUrl(gatewayUrl: string): Promise<VaultCredentials> {
    return this.withVaultLock(async () => {
      const current = await this.ensureInitializedUnlocked();
      current.gateway_url = asNonEmpty(gatewayUrl);
      current.updated_at = new Date().toISOString();
      await this.writeCredentials(current);
      return cloneCredentials(current);
    });
  }

  public async setSessionId(sessionId: string): Promise<VaultCredentials> {
    return this.withVaultLock(async () => {
      const current = await this.ensureInitializedUnlocked();
      current.default_session_id = asNonEmpty(sessionId);
      current.updated_at = new Date().toISOString();
      await this.writeCredentials(current);
      return cloneCredentials(current);
    });
  }

  public async getConnectedWallet(): Promise<ConnectedWalletInfo | null> {
    const current = await this.ensureInitialized();
    return current.connected_wallet ? { ...current.connected_wallet } : null;
  }

  public async getLinkedWallets(): Promise<LinkedWalletInfo[]> {
    const current = await this.ensureInitialized();
    return current.linked_wallets
      ? current.linked_wallets.map((wallet) => ({ ...wallet }))
      : [];
  }

  public async getLinkedWalletByNetwork(
    network: LinkedWalletNetwork,
  ): Promise<LinkedWalletInfo | null> {
    const wallets = await this.getLinkedWallets();
    return wallets.find((wallet) => wallet.network === network) ?? null;
  }

  public async setConnectedWalletOnce(input: {
    address: string;
    provider: ConnectedWalletProvider;
    connectedAt?: string;
    fundedMint?: string;
  }): Promise<VaultCredentials> {
    return this.withVaultLock(async () => {
      const current = await this.ensureInitializedUnlocked();
      if (current.connected_wallet) {
        return cloneCredentials(current);
      }

      const address = asNonEmpty(input.address);
      if (!address) {
        throw new Error("Connected wallet address is required");
      }

      const provider = input.provider;
      if (
        provider !== "phantom" &&
        provider !== "solflare" &&
        provider !== "backpack" &&
        provider !== "glow" &&
        provider !== "nightly" &&
        provider !== "browser_solana" &&
        provider !== "metamask" &&
        provider !== "coinbase" &&
        provider !== "rabby" &&
        provider !== "brave" &&
        provider !== "trust" &&
        provider !== "browser_evm" &&
        provider !== "privy" &&
        provider !== "manual"
      ) {
        throw new Error(
          "Connected wallet provider must be a supported Solana or EVM browser wallet, privy, or manual",
        );
      }

      const connectedWallet = {
        address,
        provider,
        connected_at: input.connectedAt ?? new Date().toISOString(),
        funded_mint: asNonEmpty(input.fundedMint),
      };

      current.connected_wallet = connectedWallet;
      current.linked_wallets = normalizeLinkedWallets({
        ...current,
        connected_wallet: connectedWallet,
      });
      current.updated_at = new Date().toISOString();
      await this.writeCredentials(current);
      return cloneCredentials(current);
    });
  }

  public async linkWallet(input: {
    address: string;
    provider: ConnectedWalletProvider;
    network: LinkedWalletNetwork;
    connectedAt?: string;
    fundedMint?: string;
  }): Promise<VaultCredentials> {
    return this.withVaultLock(async () => {
      const current = await this.ensureInitializedUnlocked();
      const address = asNonEmpty(input.address);
      if (!address) {
        throw new Error("Linked wallet address is required");
      }

      const provider = input.provider;
      if (
        provider !== "phantom" &&
        provider !== "solflare" &&
        provider !== "backpack" &&
        provider !== "glow" &&
        provider !== "nightly" &&
        provider !== "browser_solana" &&
        provider !== "metamask" &&
        provider !== "coinbase" &&
        provider !== "rabby" &&
        provider !== "brave" &&
        provider !== "trust" &&
        provider !== "browser_evm" &&
        provider !== "privy" &&
        provider !== "manual"
      ) {
        throw new Error(
          "Connected wallet provider must be a supported Solana or EVM browser wallet, privy, or manual",
        );
      }

      const linkedWallets = current.linked_wallets
        ? current.linked_wallets.map((wallet) => ({ ...wallet }))
        : [];

      const primaryNetwork = current.connected_wallet
        ? inferLinkedWalletNetwork(current.connected_wallet)
        : null;
      if (
        primaryNetwork === input.network &&
        current.connected_wallet &&
        current.connected_wallet.address !== address
      ) {
        throw new Error(
          "This vault already has a primary wallet for that network. MVP multi-wallet supports one wallet per network.",
        );
      }

      const existingIndex = linkedWallets.findIndex(
        (wallet) => wallet.network === input.network,
      );

      const nextWallet: LinkedWalletInfo = {
        address,
        provider,
        connected_at: input.connectedAt ?? new Date().toISOString(),
        funded_mint: asNonEmpty(input.fundedMint),
        network: input.network,
        is_primary: false,
      };

      if (existingIndex >= 0) {
        const existing = linkedWallets[existingIndex]!;
        if (existing.is_primary) {
          return cloneCredentials(current);
        }
        linkedWallets[existingIndex] = {
          ...existing,
          ...nextWallet,
          is_primary: false,
        };
      } else {
        linkedWallets.push(nextWallet);
      }

      current.linked_wallets = normalizeLinkedWallets({
        ...current,
        linked_wallets: linkedWallets,
      });
      current.updated_at = new Date().toISOString();
      await this.writeCredentials(current);
      return cloneCredentials(current);
    });
  }

  public async clearConnectedWallet(): Promise<VaultCredentials> {
    return this.withVaultLock(async () => {
      const current = await this.ensureInitializedUnlocked();
      if (!current.connected_wallet && !current.linked_wallets?.length) {
        return cloneCredentials(current);
      }
      current.connected_wallet = undefined;
      current.linked_wallets = undefined;
      current.updated_at = new Date().toISOString();
      await this.writeCredentials(current);
      return cloneCredentials(current);
    });
  }

  public async getConnectPayoutPromptOptOut(): Promise<boolean> {
    const current = await this.ensureInitialized();
    return current.connect_onboarding?.payout_prompt_opt_out === true;
  }

  public async setConnectPayoutPromptOptOut(
    optOut: boolean,
  ): Promise<VaultCredentials> {
    return this.withVaultLock(async () => {
      const current = await this.ensureInitializedUnlocked();
      current.connect_onboarding = {
        ...(current.connect_onboarding ?? {}),
        payout_prompt_opt_out: optOut,
      };
      current.updated_at = new Date().toISOString();
      await this.writeCredentials(current);
      return cloneCredentials(current);
    });
  }

  public async signPayload(payload: unknown): Promise<SignatureEnvelope> {
    const current = await this.ensureInitialized();
    const record = await this.readKeypairRecord(
      current.root_vault.keyring_ref,
      current.root_vault.public_key,
    );
    const publicKeyBytes = hexToBytes(
      record.publicKeyHex,
      nacl.sign.publicKeyLength,
    );
    const secretKeyBytes = record.secretKey;
    const rootId = this.computeRootId(publicKeyBytes);

    return signStructuredPayload(payload, {
      rootId,
      burnerPublicKeyBase58: bs58.encode(publicKeyBytes),
      burnerSecretKeyBase58: bs58.encode(secretKeyBytes),
    });
  }

  public async listAgentSummaries(): Promise<AgentSummary[]> {
    const current = await this.ensureInitialized();
    return Object.entries(current.agents)
      .map(([name, agent]) => ({
        name,
        profile: agent.profile,
        registrationStatus: agent.registration_status,
        tankId: agent.tank_id ?? null,
        boundStorageName: agent.bound_storage ?? null,
        limitUsd: agent.limit ?? null,
        refillCapUsd: agent.refill_cap ?? null,
        publicKeyHex: agent.public_key,
        publicKeyBase58: this.agentGatewayPublicKey(agent.public_key),
        lastSessionId: agent.last_session_id ?? null,
      }))
      .sort((left, right) => left.name.localeCompare(right.name));
  }

  public async getAgentLimits(name: string): Promise<AgentLimitSummary> {
    const current = await this.ensureInitialized();
    const normalizedName = normalizeAgentName(name);
    const agent = current.agents[normalizedName];
    if (!agent) {
      throw new Error(`Agent "${normalizedName}" not found`);
    }
    return {
      name: normalizedName,
      profile: agent.profile,
      registrationStatus: agent.registration_status,
      tankId: agent.tank_id ?? null,
      boundStorageName: agent.bound_storage ?? null,
      limitUsd: agent.limit ?? null,
      refillCapUsd: agent.refill_cap ?? null,
    };
  }

  public async bindAgentStorage(
    name: string,
    storageName: string,
  ): Promise<AgentConfig> {
    return this.withVaultLock(async () => {
      const current = await this.ensureInitializedUnlocked();
      const normalizedName = normalizeAgentName(name);
      const agent = current.agents[normalizedName];
      if (!agent) {
        throw new Error(`Agent "${normalizedName}" not found`);
      }
      agent.bound_storage = normalizeAgentStorageName(storageName);
      current.agents[normalizedName] = agent;
      current.updated_at = new Date().toISOString();
      await this.writeCredentials(current);
      return { ...agent };
    });
  }

  public async unbindAgentStorage(name: string): Promise<AgentConfig> {
    return this.withVaultLock(async () => {
      const current = await this.ensureInitializedUnlocked();
      const normalizedName = normalizeAgentName(name);
      const agent = current.agents[normalizedName];
      if (!agent) {
        throw new Error(`Agent "${normalizedName}" not found`);
      }
      agent.bound_storage = undefined;
      current.agents[normalizedName] = agent;
      current.updated_at = new Date().toISOString();
      await this.writeCredentials(current);
      return { ...agent };
    });
  }

  public async signRootBytes(
    payload: Uint8Array,
  ): Promise<DetachedSignatureEnvelope> {
    const current = await this.ensureInitialized();
    const record = await this.readKeypairRecord(
      current.root_vault.keyring_ref,
      current.root_vault.public_key,
    );
    const publicKeyBytes = hexToBytes(
      record.publicKeyHex,
      nacl.sign.publicKeyLength,
    );
    const signatureBytes = nacl.sign.detached(payload, record.secretKey);
    return {
      signerId: this.computeRootId(publicKeyBytes),
      signerPublicKeyBase58: bs58.encode(publicKeyBytes),
      signedAt: new Date().toISOString(),
      signatureBase58: bs58.encode(signatureBytes),
    };
  }

  public async signAgentBytes(
    name: string,
    payload: Uint8Array,
  ): Promise<DetachedSignatureEnvelope> {
    const current = await this.ensureInitialized();
    const normalizedName = normalizeAgentName(name);
    const agent = current.agents[normalizedName];
    if (!agent) {
      throw new Error(`Agent "${normalizedName}" not found`);
    }
    const record = await this.readKeypairRecord(
      agent.keyring_ref,
      agent.public_key,
    );
    const publicKeyBytes = hexToBytes(
      record.publicKeyHex,
      nacl.sign.publicKeyLength,
    );
    const signatureBytes = nacl.sign.detached(payload, record.secretKey);
    return {
      signerId: `agent:${normalizedName}`,
      signerPublicKeyBase58: bs58.encode(publicKeyBytes),
      signedAt: new Date().toISOString(),
      signatureBase58: bs58.encode(signatureBytes),
    };
  }

  public async buildGatewayAuthHeaders(
    body: string,
    options: { method: string; path: string },
  ): Promise<Record<string, string>> {
    const signer = await this.getRootGatewaySigner();
    const timestamp = Date.now().toString();
    const { crypto } = await loadNodeApis();
    const nonce = crypto.randomUUID();
    const message = [
      options.method.toUpperCase(),
      options.path,
      timestamp,
      nonce,
      body,
    ].join(":");
    const signatureBytes = nacl.sign.detached(
      new TextEncoder().encode(message),
      signer.secretKey,
    );

    return {
      "X-TDM-Nonce": nonce,
      "X-TDM-Timestamp": timestamp,
      "X-TDM-Public-Key": bs58.encode(signer.publicKeyBytes),
      "X-TDM-Signature": bs58.encode(signatureBytes),
    };
  }

  private async getRootGatewaySigner(): Promise<{
    keyringRef: string;
    publicKeyHex: string;
    publicKeyBytes: Uint8Array;
    secretKey: Uint8Array;
  }> {
    if (!this.rootGatewaySignerPromise) {
      this.rootGatewaySignerPromise = (async () => {
        const current = await this.ensureInitialized();
        const record = await this.readKeypairRecord(
          current.root_vault.keyring_ref,
          current.root_vault.public_key,
        );
        return {
          keyringRef: current.root_vault.keyring_ref,
          publicKeyHex: record.publicKeyHex,
          publicKeyBytes: hexToBytes(
            record.publicKeyHex,
            nacl.sign.publicKeyLength,
          ),
          secretKey: record.secretKey,
        };
      })().catch((error) => {
        this.rootGatewaySignerPromise = null;
        throw error;
      });
    }

    return await this.rootGatewaySignerPromise;
  }

  public async appendLedgerEntry(
    entry: Omit<LocalLedgerEntry, "id" | "ts"> & { ts?: string; id?: string },
  ): Promise<void> {
    await this.withVaultLock(async () => {
      const current = await this.ensureInitializedUnlocked();
      const generatedId = entry.id ?? (await this.createLedgerEntryId());
      const row: LocalLedgerEntry = {
        id: generatedId,
        ts: entry.ts ?? new Date().toISOString(),
        kind: entry.kind,
        status: entry.status,
        note: entry.note,
        amountUsd: entry.amountUsd,
        deltaUsd: entry.deltaUsd,
        txId: entry.txId,
      };

      if (current.ledger.length >= LEDGER_LIMIT) {
        const { path } = await loadNodeApis();
        const credentialsPath = await this.getCredentialsPath();
        const ledgerDir = path.dirname(credentialsPath);
        const month = new Date().toISOString().slice(0, 7);
        const archivePath = path.join(
          ledgerDir,
          `ledger_archive_${month}.json`,
        );
        const archive = await readJsonOrDefault(archivePath, {
          entries: [] as LocalLedgerEntry[],
        });
        const archiveEntries = Array.isArray(archive.entries)
          ? archive.entries
          : [];
        const totalEntries = current.ledger.length;
        await atomicWriteJson(archivePath, {
          entries: [...archiveEntries, ...current.ledger],
        });
        current.ledger = [];
        console.log(
          `Ledger archived to ${archivePath} (${totalEntries} entries)`,
        );
      }

      current.ledger.unshift(row);
      current.updated_at = new Date().toISOString();
      await this.writeCredentials(current);
    });
  }

  public async getLedgerEntries(limit = 50): Promise<LocalLedgerEntry[]> {
    const current = await this.ensureInitialized();
    return current.ledger.slice(0, Math.max(1, limit));
  }

  public async resolveApiKey(
    options: { cwd?: string } = {},
  ): Promise<ResolvedApiKey> {
    return this.withVaultLock(async () => {
      const current = await this.readCredentials();
      const resolved = await this.resolveApiKeyInternal(current, options);
      if (!resolved) {
        throw new Error("API key not found. Run: tdm auth set-key");
      }
      return resolved;
    });
  }

  public async getRuntimeCredentials(): Promise<RuntimeCredentialState> {
    return this.withVaultLock(async () => this.getRuntimeCredentialsUnlocked());
  }

  private async getRuntimeCredentialsUnlocked(): Promise<RuntimeCredentialState> {
    const current = await this.ensureInitializedUnlocked();
    const apiKeyResolved = await this.resolveApiKeyInternal(current);
    const envCredentials = await LocalVault.readEnvCredentials();
    return {
      gatewayUrl: current.gateway_url ?? envCredentials.gatewayUrl,
      apiKey: apiKeyResolved?.value,
      rootId: this.computeRootId(
        hexToBytes(current.root_vault.public_key, nacl.sign.publicKeyLength),
      ),
      rootPublicKeyHex: current.root_vault.public_key,
      sessionId: current.default_session_id,
      sessionToken: asNonEmpty(
        typeof process !== "undefined"
          ? process.env[ENV_KEY_MAP.sessionToken]
          : undefined,
      ),
    };
  }

  private async resolveApiKeyInternal(
    current: VaultCredentials | null,
    options: { cwd?: string } = {},
  ): Promise<ResolvedApiKey | null> {
    const apiKeyRef =
      current?.root_vault?.api_key_ref ??
      current?.api_key_ref ??
      this.buildVaultKeyringRef(API_KEYRING_ACCOUNT);
    let keyringValue: string | null = null;
    let keyringError: unknown = null;
    try {
      keyringValue = await getKeyringSecret(apiKeyRef);
    } catch (error) {
      keyringError = error;
    }
    if (keyringValue) {
      await this.updateApiKeySource(current, "keyring", apiKeyRef);
      return { value: keyringValue, source: "keyring" };
    }

    const envResolved = await resolveEnvApiKey(options.cwd);
    if (envResolved) {
      if (keyringError) {
        warnLocalVault(
          "Keyring lookup failed, falling back to environment API key",
          {
            apiKeyRef,
            error: sanitizeLocalVaultError(keyringError),
            source: envResolved.source,
          },
        );
      }
      await this.updateApiKeySource(current, envResolved.source, apiKeyRef);
      return envResolved;
    }

    if (keyringError) {
      throw keyringError;
    }
    return null;
  }

  private async updateApiKeySource(
    current: VaultCredentials | null,
    source: ApiKeySource,
    apiKeyRef?: string,
  ): Promise<void> {
    if (!current) {
      return;
    }
    let changed = false;
    if (
      source === "keyring" &&
      apiKeyRef &&
      current.root_vault.api_key_ref !== apiKeyRef
    ) {
      current.root_vault.api_key_ref = apiKeyRef;
      changed = true;
    }
    if (current.root_vault.api_key_source !== source) {
      current.root_vault.api_key_source = source;
      changed = true;
    }
    if (changed) {
      current.updated_at = new Date().toISOString();
      await this.writeCredentials(current);
    }
  }

  public static async resolveRuntimeCredentials(
    options: ResolveRuntimeCredentialOptions = {},
  ): Promise<RuntimeCredentialState> {
    const resolved: RuntimeCredentialState = {
      ...options.overrides,
    };

    const envCredentials = await this.readEnvCredentials(options.cwd);
    resolved.gatewayUrl = resolved.gatewayUrl ?? envCredentials.gatewayUrl;
    resolved.apiKey = resolved.apiKey ?? envCredentials.apiKey;
    resolved.rootId = resolved.rootId ?? envCredentials.rootId;
    resolved.rootPublicKeyHex =
      resolved.rootPublicKeyHex ?? envCredentials.rootPublicKeyHex;
    resolved.sessionId = resolved.sessionId ?? envCredentials.sessionId;
    resolved.sessionToken =
      resolved.sessionToken ?? envCredentials.sessionToken;

    const allowVaultFallback = options.allowVaultFallback ?? true;
    const needsVault =
      allowVaultFallback &&
      (!resolved.gatewayUrl ||
        (!resolved.apiKey && !resolved.sessionToken) ||
        Boolean(options.credentialsPath) ||
        Boolean(options.vaultName));

    if (needsVault && isNodeRuntime()) {
      const vault = new LocalVault({
        credentialsPath: options.credentialsPath,
        vaultName: options.vaultName,
      });
      const fallback = await vault.getRuntimeCredentials();

      resolved.gatewayUrl = resolved.gatewayUrl ?? fallback.gatewayUrl;
      resolved.apiKey = resolved.apiKey ?? fallback.apiKey;
      resolved.rootId = resolved.rootId ?? fallback.rootId;
      resolved.rootPublicKeyHex =
        resolved.rootPublicKeyHex ?? fallback.rootPublicKeyHex;
      resolved.sessionId = resolved.sessionId ?? fallback.sessionId;
      resolved.sessionToken = resolved.sessionToken ?? fallback.sessionToken;
    }

    return resolved;
  }

  public static async peekRuntimeCredentials(
    options: ResolveRuntimeCredentialOptions = {},
  ): Promise<RuntimeCredentialState> {
    const resolved: RuntimeCredentialState = {
      ...options.overrides,
    };

    const envCredentials = await this.readEnvCredentials(options.cwd);
    resolved.gatewayUrl = resolved.gatewayUrl ?? envCredentials.gatewayUrl;
    resolved.apiKey = resolved.apiKey ?? envCredentials.apiKey;
    resolved.rootId = resolved.rootId ?? envCredentials.rootId;
    resolved.rootPublicKeyHex =
      resolved.rootPublicKeyHex ?? envCredentials.rootPublicKeyHex;
    resolved.sessionId = resolved.sessionId ?? envCredentials.sessionId;
    resolved.sessionToken =
      resolved.sessionToken ?? envCredentials.sessionToken;

    if (isNodeRuntime()) {
      const vault = new LocalVault({
        credentialsPath: options.credentialsPath,
        vaultName: options.vaultName,
      });
      const fallback = await vault.readCredentials();
      if (fallback) {
        resolved.gatewayUrl = resolved.gatewayUrl ?? fallback.gateway_url;
        resolved.rootPublicKeyHex =
          resolved.rootPublicKeyHex ?? fallback.root_vault.public_key;
        resolved.rootId =
          resolved.rootId ??
          vault.computeRootId(
            hexToBytes(
              fallback.root_vault.public_key,
              nacl.sign.publicKeyLength,
            ),
          );
        resolved.sessionId = resolved.sessionId ?? fallback.default_session_id;
        const apiKey = await vault.readApiKeyFromCredentials(fallback);
        resolved.apiKey = resolved.apiKey ?? apiKey;
      }
    }

    return resolved;
  }

  private static async readEnvCredentials(
    cwd?: string,
  ): Promise<RuntimeCredentialState> {
    const fromProcessEnv = (
      key: keyof typeof ENV_KEY_MAP,
    ): string | undefined => {
      if (typeof process === "undefined") {
        return undefined;
      }
      return asNonEmpty(process.env[ENV_KEY_MAP[key]]);
    };

    if (!isNodeRuntime()) {
      return {
        gatewayUrl: fromProcessEnv("gatewayUrl"),
        apiKey: fromProcessEnv("apiKey"),
        rootId: fromProcessEnv("rootId"),
        rootPublicKeyHex: fromProcessEnv("rootPublicKeyHex"),
        sessionId: fromProcessEnv("sessionId"),
        sessionToken: fromProcessEnv("sessionToken"),
      };
    }

    const { path } = await loadNodeApis();
    const root = cwd ?? process.cwd();
    const envPath = path.join(root, ".env");
    const envLocalPath = path.join(root, ".env.local");

    const [dotenv, dotenvLocal] = await Promise.all([
      readEnvFile(envPath),
      readEnvFile(envLocalPath),
    ]);

    const merged = {
      ...dotenv,
      ...dotenvLocal,
      ...(typeof process !== "undefined" ? process.env : {}),
    } as Record<string, string | undefined>;

    return {
      gatewayUrl: asNonEmpty(merged[ENV_KEY_MAP.gatewayUrl]),
      apiKey: asNonEmpty(merged[ENV_KEY_MAP.apiKey]),
      rootId: asNonEmpty(merged[ENV_KEY_MAP.rootId]),
      rootPublicKeyHex: asNonEmpty(merged[ENV_KEY_MAP.rootPublicKeyHex]),
      sessionId: asNonEmpty(merged[ENV_KEY_MAP.sessionId]),
      sessionToken: asNonEmpty(merged[ENV_KEY_MAP.sessionToken]),
    };
  }

  private async getCredentialsPath(): Promise<string> {
    return LocalVault.resolveCredentialsPath(
      this.credentialsPathOverride,
      this.vaultNameOverride,
    );
  }

  public getVaultName(): string | undefined {
    return this.vaultNameOverride;
  }

  private async readLegacyCredentials(): Promise<LegacyCredentials | null> {
    const { fs } = await loadNodeApis();
    const pathname = await this.getCredentialsPath();
    try {
      const raw = await fs.readFile(pathname, "utf8");
      const parsed = tryParseJson(raw, { context: pathname, logFailure: true });
      if (!parsed) {
        return null;
      }
      if (isEmptyRecord(parsed)) {
        return null;
      }
      const version = readObjectVersion(parsed);
      if (version !== 1 && version !== 2) {
        return null;
      }
      return LegacyCredentialsSchema.parse(parsed);
    } catch (error) {
      if (!isFsErrorCode(error, "ENOENT")) {
        warnLocalVault("Failed to read legacy vault credentials", {
          pathname,
          error: sanitizeLocalVaultError(error),
        });
      }
      return null;
    }
  }

  private async migrateLegacyCredentials(
    legacy: LegacyCredentials,
  ): Promise<VaultCredentials> {
    const { crypto } = await loadNodeApis();
    const legacySecret =
      legacy.version === 2 ? await this.readLegacySecretBundle() : null;
    const secretKeyBase58 =
      legacy.burnerSecretKeyBase58 ?? legacySecret?.burnerSecretKeyBase58;
    if (!secretKeyBase58) {
      throw new Error(
        "Legacy credentials missing secret key. Re-run tdm login to reinitialize.",
      );
    }

    const secretKey = bs58.decode(secretKeyBase58);
    if (secretKey.byteLength !== nacl.sign.secretKeyLength) {
      throw new Error("Legacy secret key has invalid length");
    }

    const pair = nacl.sign.keyPair.fromSecretKey(secretKey);
    const publicKeyHex = bytesToHex(pair.publicKey);
    const rootKeyringRef = this.buildVaultKeyringRef(ROOT_KEYRING_ACCOUNT);
    await this.storeKeypairRecord(rootKeyringRef, publicKeyHex, pair.secretKey);

    const apiKey = legacy.apiKey ?? legacySecret?.apiKey;
    const apiKeyRef = apiKey
      ? this.buildVaultKeyringRef(API_KEYRING_ACCOUNT)
      : undefined;
    const apiKeySource: ApiKeySource | undefined = apiKey
      ? "keyring"
      : undefined;
    if (apiKey && apiKeyRef) {
      await setKeyringSecret(apiKeyRef, apiKey);
    }

    const now = new Date().toISOString();
    return {
      version: CREDENTIALS_VERSION,
      installation_id: crypto.randomUUID(),
      root_vault: {
        public_key: publicKeyHex,
        keyring_ref: rootKeyringRef,
        api_key_ref: apiKeyRef,
        api_key_source: apiKeySource,
      },
      agents: {},
      runtime_allowlist: [],
      gateway_url: legacy.gatewayUrl,
      default_session_id: legacy.defaultSessionId,
      linked_wallets: undefined,
      connect_onboarding: {},
      created_at: legacy.createdAt ?? now,
      updated_at: now,
      ledger: legacy.ledger,
    };
  }

  private async readLegacySecretBundle(): Promise<LegacySecretBundle | null> {
    const { crypto, path } = await loadNodeApis();
    const pathname = await this.getCredentialsPath();
    const key = crypto
      .createHash("sha256")
      .update(path.resolve(pathname))
      .digest("hex");
    const account = `${LEGACY_KEYRING_NAMESPACE}:${key}`;
    const raw = await getKeyringPassword(LEGACY_KEYRING_SERVICE, account);
    if (!raw) {
      return null;
    }
    const parsed = tryParseJson(raw);
    if (!parsed) {
      return null;
    }
    const result = LegacySecretBundleSchema.safeParse(parsed);
    if (!result.success) {
      return null;
    }
    return result.data;
  }

  private async createFreshCredentials(): Promise<VaultCredentials> {
    const pair = nacl.sign.keyPair();
    const publicKeyHex = bytesToHex(pair.publicKey);
    const rootKeyringRef = this.buildVaultKeyringRef(ROOT_KEYRING_ACCOUNT);
    await this.storeKeypairRecord(rootKeyringRef, publicKeyHex, pair.secretKey);
    const now = new Date().toISOString();

    return {
      version: CREDENTIALS_VERSION,
      installation_id: crypto.randomUUID(),
      root_vault: {
        public_key: publicKeyHex,
        keyring_ref: rootKeyringRef,
      },
      agents: {},
      runtime_allowlist: [],
      linked_wallets: undefined,
      connect_onboarding: {},
      created_at: now,
      updated_at: now,
      ledger: [],
    };
  }

  private async ensureRootKeypair(
    credentials: VaultCredentials,
  ): Promise<void> {
    const result = await this.repairRootKeypairMetadata(credentials);
    if (result.status === "error") {
      throw new Error(result.message);
    }
  }

  public async repairKeyMetadata(): Promise<VaultRepairReport> {
    return this.withVaultLock(async () => {
      const current = await this.ensureInitializedUnlocked();
      const entries: VaultRepairEntry[] = [];

      const rootResult = await this.repairRootKeypairMetadata(current);
      entries.push(rootResult);

      for (const [name, agent] of Object.entries(current.agents)) {
        entries.push(
          await this.repairAgentKeypairMetadata(current, name, agent),
        );
      }

      const repaired = entries.some((entry) => entry.status === "repaired");
      const hasRootFailure = entries.some(
        (entry) => entry.scope === "root_vault" && entry.status === "error",
      );

      if (repaired) {
        current.updated_at = new Date().toISOString();
        await this.writeCredentials(current);
      }

      if (hasRootFailure) {
        const rootFailure = entries.find(
          (entry) => entry.scope === "root_vault" && entry.status === "error",
        );
        throw new Error(rootFailure?.message ?? "Root vault repair failed");
      }

      return {
        repaired,
        entries,
      };
    });
  }

  private async writeCredentials(value: VaultCredentials): Promise<void> {
    const { fs, path } = await loadNodeApis();
    const pathname = await this.getCredentialsPath();
    const backupPath = await LocalVault.resolveCredentialsBackupPath(
      this.credentialsPathOverride,
      this.vaultNameOverride,
    );
    const dir = path.dirname(pathname);
    await fs.mkdir(dir, { recursive: true, mode: 0o700 });
    const persisted = {
      version: CREDENTIALS_VERSION,
      installation_id: value.installation_id,
      root_vault: value.root_vault,
      agents: value.agents,
      runtime_allowlist: value.runtime_allowlist ?? [],
      gateway_url: value.gateway_url,
      default_session_id: value.default_session_id,
      connected_wallet: value.connected_wallet,
      linked_wallets: value.linked_wallets,
      connect_onboarding: value.connect_onboarding,
      created_at: value.created_at,
      updated_at: value.updated_at,
      ledger: value.ledger,
    };
    await atomicWriteJson(pathname, persisted);
    try {
      await fs.copyFile(pathname, backupPath);
    } catch (error) {
      warnLocalVault("Failed to refresh quiet credentials backup", {
        pathname: backupPath,
        error: sanitizeLocalVaultError(error),
      });
    }
  }

  private async readApiKeyFromCredentials(
    value: VaultCredentials,
  ): Promise<string | undefined> {
    const apiKeyRef = value.root_vault.api_key_ref ?? value.api_key_ref;
    if (!apiKeyRef) {
      return undefined;
    }
    const raw = await getKeyringSecret(apiKeyRef);
    return asNonEmpty(raw ?? undefined);
  }

  private computeRootId(publicKey: Uint8Array): string {
    const bytes = bs58.encode(publicKey);
    return `root_${bytes.slice(0, 24)}`;
  }

  private async createLedgerEntryId(): Promise<string> {
    const { crypto } = await loadNodeApis();
    return `ledger_${crypto.randomUUID()}`;
  }

  private async resolveSandboxId(explicit?: string): Promise<string> {
    const candidate =
      asNonEmpty(explicit) ?? asNonEmpty(process.env[ENV_KEY_MAP.sandboxId]);
    if (candidate) {
      return candidate;
    }
    const { crypto } = await loadNodeApis();
    return `sandbox_${crypto.randomUUID()}`;
  }

  private async storeKeypairRecord(
    ref: string,
    publicKeyHex: string,
    secretKey: Uint8Array,
  ): Promise<void> {
    const record: StoredKeypairRecord = {
      version: 1,
      publicKeyHex: publicKeyHex.toLowerCase(),
      secretKeyBase64: Buffer.from(secretKey).toString("base64"),
      createdAt: new Date().toISOString(),
    };
    await setKeyringSecret(ref, JSON.stringify(record));
  }

  private async readKeypairRecord(
    ref: string,
    expectedPublicKeyHex?: string,
  ): Promise<{
    publicKeyHex: string;
    secretKey: Uint8Array;
  }> {
    const raw = await getKeyringSecret(ref);
    if (!raw) {
      throw new Error(`Missing key material in OS keyring for ${ref}`);
    }
    const parsed = tryParseJson(raw);
    if (!parsed) {
      throw new Error(`Keyring entry for ${ref} is corrupted`);
    }
    const record = StoredKeypairRecordSchema.parse(parsed);
    if (
      expectedPublicKeyHex &&
      record.publicKeyHex !== expectedPublicKeyHex.toLowerCase()
    ) {
      throw new Error(
        `Keyring entry for ${ref} does not match credentials public key`,
      );
    }
    const secretKey = new Uint8Array(
      Buffer.from(record.secretKeyBase64, "base64"),
    );
    if (secretKey.byteLength !== nacl.sign.secretKeyLength) {
      throw new Error(`Keyring entry for ${ref} has invalid secret key length`);
    }
    return { publicKeyHex: record.publicKeyHex, secretKey };
  }

  private async repairRootKeypairMetadata(
    credentials: VaultCredentials,
  ): Promise<VaultRepairEntry> {
    const previousPublicKey = credentials.root_vault.public_key.toLowerCase();
    try {
      const record = await this.readKeypairRecord(
        credentials.root_vault.keyring_ref,
      );
      if (record.publicKeyHex !== previousPublicKey) {
        credentials.root_vault.public_key = record.publicKeyHex;
        return {
          scope: "root_vault",
          keyringRef: credentials.root_vault.keyring_ref,
          status: "repaired",
          previousPublicKey,
          currentPublicKey: record.publicKeyHex,
          message: `Repaired stale root vault metadata from ${previousPublicKey} to ${record.publicKeyHex}.`,
        };
      }
      return {
        scope: "root_vault",
        keyringRef: credentials.root_vault.keyring_ref,
        status: "ok",
        previousPublicKey,
        currentPublicKey: record.publicKeyHex,
        message: "Root vault metadata is in sync.",
      };
    } catch (error) {
      return {
        scope: "root_vault",
        keyringRef: credentials.root_vault.keyring_ref,
        status: "error",
        previousPublicKey,
        message: sanitizeLocalVaultError(error),
      };
    }
  }

  private async repairAgentKeypairMetadata(
    credentials: VaultCredentials,
    agentName: string,
    agent: AgentConfig,
  ): Promise<VaultRepairEntry> {
    const previousPublicKey = agent.public_key.toLowerCase();
    try {
      const record = await this.readKeypairRecord(agent.keyring_ref);
      if (record.publicKeyHex !== previousPublicKey) {
        agent.public_key = record.publicKeyHex;
        return {
          scope: "agent",
          name: agentName,
          keyringRef: agent.keyring_ref,
          status: "repaired",
          previousPublicKey,
          currentPublicKey: record.publicKeyHex,
          message: `Repaired agent "${agentName}" metadata from ${previousPublicKey} to ${record.publicKeyHex}.`,
        };
      }
      return {
        scope: "agent",
        name: agentName,
        keyringRef: agent.keyring_ref,
        status: "ok",
        previousPublicKey,
        currentPublicKey: record.publicKeyHex,
        message: `Agent "${agentName}" metadata is in sync.`,
      };
    } catch (error) {
      return {
        scope: "agent",
        name: agentName,
        keyringRef: agent.keyring_ref,
        status: "error",
        previousPublicKey,
        message: sanitizeLocalVaultError(error),
      };
    }
  }

  private async requestGatewayJson(
    method: "POST" | "DELETE",
    path: string,
    payload?: Record<string, unknown>,
    options?: {
      headers?: Record<string, string>;
      allowNotFound?: boolean;
      signal?: AbortSignal;
    },
  ): Promise<unknown> {
    const runtime = await this.getRuntimeCredentialsUnlocked();
    if (!runtime.gatewayUrl) {
      throw new Error(
        "TDM Gateway URL is required. Set via TDM_GATEWAY_URL or tdm login.",
      );
    }

    const baseUrl = GatewayUrlSchema.parse(runtime.gatewayUrl);
    const url = new URL(path, baseUrl).toString();
    const headers: Record<string, string> = {
      "Content-Type": "application/json",
      ...(options?.headers ?? {}),
    };
    if (runtime.apiKey) {
      headers["X-API-Key"] = runtime.apiKey;
    }
    if (runtime.rootId) {
      headers["X-TDM-Root-Id"] = runtime.rootId;
    }
    if (
      shouldSignRootGatewayRequest(method, path) &&
      !headers["X-TDM-Public-Key"] &&
      !headers["X-TDM-Signature"]
    ) {
      const authHeaders = await this.buildGatewayAuthHeaders(
        payload ? JSON.stringify(payload) : "",
        { method, path },
      );
      Object.assign(headers, authHeaders);
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
    if (typeof timeout.unref === "function") {
      timeout.unref();
    }
    const combined = combineAbortSignals(controller.signal, options?.signal);

    let response: Response;
    try {
      response = await (this.fetchImpl ?? fetch)(url, {
        method,
        headers,
        body: payload ? JSON.stringify(payload) : undefined,
        signal: combined.signal,
      });
    } finally {
      combined.cleanup();
      clearTimeout(timeout);
    }

    const text = await response.text();
    const parsed = text ? (tryParseJson(text) ?? text) : null;

    if (!response.ok) {
      if (options?.allowNotFound && response.status === 404) {
        return parsed;
      }
      const reason = this.readPayloadError(parsed);
      throw new Error(
        `Gateway request failed (HTTP ${response.status}): ${reason}`,
      );
    }

    return parsed;
  }

  private readPayloadError(payload: unknown): string {
    if (typeof payload === "string" && payload.trim().length > 0) {
      return payload.trim();
    }
    if (payload && typeof payload === "object") {
      const map = payload as Record<string, unknown>;
      const directError = map["error"];
      if (typeof directError === "string" && directError.trim().length > 0) {
        return directError;
      }
      const nested =
        directError && typeof directError === "object"
          ? (directError as Record<string, unknown>)
          : null;
      if (nested) {
        const nestedMessage = nested["message"];
        if (
          typeof nestedMessage === "string" &&
          nestedMessage.trim().length > 0
        ) {
          return nestedMessage;
        }
        const nestedCode = nested["code"];
        if (typeof nestedCode === "string" && nestedCode.trim().length > 0) {
          return nestedCode;
        }
      }
      const directMessage = map["message"];
      if (
        typeof directMessage === "string" &&
        directMessage.trim().length > 0
      ) {
        return directMessage;
      }
    }
    return "Unknown gateway error";
  }

  private readStringField(
    payload: unknown,
    ...keys: string[]
  ): string | undefined {
    if (!payload || typeof payload !== "object") {
      return undefined;
    }
    const map = payload as Record<string, unknown>;
    for (const key of keys) {
      const value = map[key];
      if (typeof value === "string" && value.trim().length > 0) {
        return value.trim();
      }
    }
    const nested = map["data"];
    if (nested && typeof nested === "object") {
      const nestedMap = nested as Record<string, unknown>;
      for (const key of keys) {
        const value = nestedMap[key];
        if (typeof value === "string" && value.trim().length > 0) {
          return value.trim();
        }
      }
    }
    return undefined;
  }

  private readTankId(payload: unknown): string | undefined {
    const direct = this.readStringField(payload, "tank_id", "tankId", "id");
    if (direct) {
      return direct;
    }
    if (payload && typeof payload === "object") {
      const map = payload as Record<string, unknown>;
      const tank = map["tank"];
      if (tank && typeof tank === "object") {
        return this.readStringField(tank, "id", "tank_id", "tankId");
      }
      const nested = map["data"];
      if (nested && typeof nested === "object") {
        const nestedMap = nested as Record<string, unknown>;
        const nestedTank = nestedMap["tank"];
        if (nestedTank && typeof nestedTank === "object") {
          return this.readStringField(nestedTank, "id", "tank_id", "tankId");
        }
      }
    }
    return undefined;
  }

  private formatGatewayDecimalAmount(value: number): string {
    if (!Number.isFinite(value) || value <= 0) {
      throw new Error("Amount must be a positive finite number");
    }
    return value.toFixed(8).replace(/\.?0+$/, "");
  }

  private agentGatewayPublicKey(publicKeyHex: string): string {
    return bs58.encode(hexToBytes(publicKeyHex, nacl.sign.publicKeyLength));
  }

  private async signAgentGatewayPayload(
    message: string,
    agent: AgentConfig,
  ): Promise<string> {
    const record = await this.readKeypairRecord(
      agent.keyring_ref,
      agent.public_key,
    );
    const bytes = new TextEncoder().encode(message);
    const signature = nacl.sign.detached(bytes, record.secretKey);
    return bs58.encode(signature);
  }
}
