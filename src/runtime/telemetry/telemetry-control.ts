const DISABLED_ENV_VALUES = new Set(["1", "true", "yes", "on"]);

let telemetryEnabled = !DISABLED_ENV_VALUES.has(
  (typeof process !== "undefined" ? process.env["TDM_DISABLE_TELEMETRY"] : undefined)
    ?.trim()
    .toLowerCase() ?? "",
);

export function isTelemetryEnabled(): boolean {
  return telemetryEnabled;
}

export function setTelemetryEnabled(enabled: boolean): void {
  telemetryEnabled = Boolean(enabled);
}

export function disableTelemetry(): void {
  telemetryEnabled = false;
}

export function enableTelemetry(): void {
  telemetryEnabled = true;
}
