const emittedWarnings = new Set<string>();

export interface BackendRuntimeLike {
  gatewayUrl?: string | null;
}

export interface FutureBackendNotice {
  feature: string;
  reason?: string;
  futureRelease?: string;
}

function normalizeReason(reason: string | undefined): string {
  return typeof reason === "string" ? reason.trim() : "";
}

function normalizeFeature(feature: string): string {
  const normalized = feature.trim();
  return normalized.length > 0 ? normalized : "Live TDM feature";
}

function buildNoticeMessage(input: FutureBackendNotice): string {
  const feature = normalizeFeature(input.feature);
  const reason = normalizeReason(input.reason);

  return (
    `[TDM SDK] ${feature} is running in local compatibility mode.` +
    (reason ? ` Reason: ${reason}.` : "") +
    ` Configure TDM_GATEWAY_URL or run 'tdm connect' to enable Live TDM API access.`
  );
}

export function hasConfiguredBackend(
  runtime: BackendRuntimeLike | null | undefined,
): boolean {
  return typeof runtime?.gatewayUrl === "string" && runtime.gatewayUrl.trim().length > 0;
}

export function backendSyncEnabled(
  runtime?: BackendRuntimeLike | null | undefined,
): boolean {
  return hasConfiguredBackend(runtime);
}

export function shouldUseFutureBackendFeature(
  runtime?: BackendRuntimeLike | null | undefined,
): boolean {
  return !hasConfiguredBackend(runtime);
}

/**
 * Emits a one-time warning that a feature is intentionally operating
 * in local compatibility mode.
 */
export function warnBackendless(feature: string, reason?: string): void {
  const normalizedFeature = normalizeFeature(feature);
  const normalizedReason = normalizeReason(reason);
  const key = `${normalizedFeature}::${normalizedReason}`;

  if (emittedWarnings.has(key)) {
    return;
  }
  emittedWarnings.add(key);

  if (typeof console !== "undefined" && typeof console.warn === "function") {
    console.warn(
      buildNoticeMessage({
        feature: normalizedFeature,
        reason: normalizedReason,
      }),
    );
  }
}

/**
 * Emits a stronger warning intended for code paths that are currently falling
 * back to local compatibility mode instead of using the configured TDM API.
 */
export function warnFutureBackendFeature(
  feature: string,
  reason?: string,
  futureRelease?: string,
): void {
  const normalizedFeature = normalizeFeature(feature);
  const normalizedReason = normalizeReason(reason);
  const normalizedFutureRelease = typeof futureRelease === "string" ? futureRelease.trim() : "";
  const key = `compat::${normalizedFeature}::${normalizedReason}::${normalizedFutureRelease}`;

  if (emittedWarnings.has(key)) {
    return;
  }
  emittedWarnings.add(key);

  if (typeof console !== "undefined" && typeof console.warn === "function") {
    console.warn(
      buildNoticeMessage({
        feature: normalizedFeature,
        reason: normalizedReason,
        futureRelease: normalizedFutureRelease || undefined,
      }),
    );
  }
}

export function createFutureOnlyResult<T extends Record<string, unknown>>(
  feature: string,
  extra: T,
): T & {
  backendSyncEnabled: false;
  futureBackendFeature: true;
  mode: "no-backend";
  feature: string;
} {
  return {
    ...extra,
    backendSyncEnabled: false,
    futureBackendFeature: true,
    mode: "no-backend",
    feature: normalizeFeature(feature),
  };
}

export function createOfflineAuthorizationId(requestId: string): string {
  const normalized = requestId.replace(/[^a-zA-Z0-9_-]/g, "_");
  return `offline_${normalized}`;
}

/**
 * Throws an explicit error for code paths that must never execute in the
 * current local-first package.
 */
export function assertBackendUnavailable(
  feature: string,
  reason?: string,
): never {
  const normalizedFeature = normalizeFeature(feature);
  const normalizedReason = normalizeReason(reason);
  throw new Error(
    `${normalizedFeature} is not available in this TDM SDK build.` +
      (normalizedReason ? ` ${normalizedReason}` : "") +
      ` Configure a Live TDM URL to enable this capability.`,
  );
}
