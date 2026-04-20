export interface TdmTelemetryContext {
  readonly scope?: string;
  readonly attributes: Record<string, unknown>;
  child(attributes?: Record<string, unknown>): TdmTelemetryContext;
  event(name: string, attributes?: Record<string, unknown>): Record<string, unknown>;
  toMetadata(attributes?: Record<string, unknown>): Record<string, unknown>;
}

export interface CreateTelemetryContextOptions {
  scope?: string;
  attributes?: Record<string, unknown>;
}

function compactMetadata(input: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(input).filter(([, value]) => value !== undefined),
  );
}

export function createTelemetryContext(
  options: CreateTelemetryContextOptions = {},
): TdmTelemetryContext {
  const baseScope = options.scope?.trim() || undefined;
  const baseAttributes = compactMetadata({ ...(options.attributes ?? {}) });

  const createChild = (
    scope: string | undefined,
    attributes: Record<string, unknown>,
  ): TdmTelemetryContext => ({
    scope,
    attributes,
    child(childAttributes = {}) {
      return createChild(scope, compactMetadata({ ...attributes, ...childAttributes }));
    },
    event(name, eventAttributes = {}) {
      return compactMetadata({
        ...(scope ? { telemetry_scope: scope } : {}),
        telemetry_event: name,
        ...attributes,
        ...eventAttributes,
      });
    },
    toMetadata(extraAttributes = {}) {
      return compactMetadata({
        ...(scope ? { telemetry_scope: scope } : {}),
        ...attributes,
        ...extraAttributes,
      });
    },
  });

  return createChild(baseScope, baseAttributes);
}
