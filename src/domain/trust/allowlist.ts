const DOMAIN_PATTERN = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/i;

export interface EndpointAllowlistVerdict {
  endpoint: string;
  hostname?: string;
  allowed: boolean;
  matchedDomain?: string;
}

export function normalizeDomain(domain: string): string | undefined {
  const normalized = domain.trim().toLowerCase();
  if (!normalized) {
    return undefined;
  }
  if (!DOMAIN_PATTERN.test(normalized)) {
    return undefined;
  }
  return normalized;
}

export function normalizeAllowlist(domains: readonly string[]): string[] {
  const deduped = new Set<string>();
  for (const domain of domains) {
    const normalized = normalizeDomain(domain);
    if (normalized) {
      deduped.add(normalized);
    }
  }
  return [...deduped];
}

export function mergeAllowlists(
  systemAllowlist: readonly string[],
  localAllowlist: readonly string[],
): string[] {
  const deduped = new Set<string>();

  for (const domain of normalizeAllowlist(systemAllowlist)) {
    deduped.add(domain);
  }
  for (const domain of normalizeAllowlist(localAllowlist)) {
    deduped.add(domain);
  }

  return [...deduped];
}

function matchDomain(hostname: string, domain: string): boolean {
  return hostname === domain;
}

export function evaluateEndpointAllowlist(
  endpoint: string,
  allowlist: readonly string[],
): EndpointAllowlistVerdict {
  let parsed: URL;
  try {
    parsed = new URL(endpoint);
  } catch {
    return {
      endpoint,
      allowed: false,
    };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      endpoint,
      hostname: parsed.hostname.toLowerCase(),
      allowed: false,
    };
  }

  const hostname = parsed.hostname.toLowerCase();
  const normalizedAllowlist = normalizeAllowlist(allowlist);
  const matchedDomain = normalizedAllowlist.find((domain) => matchDomain(hostname, domain));

  return {
    endpoint,
    hostname,
    allowed: matchedDomain !== undefined,
    matchedDomain,
  };
}

export function tryExtractHttpEndpoint(value: string): string | undefined {
  try {
    const parsed = new URL(value);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return undefined;
    }
    return parsed.toString();
  } catch {
    return undefined;
  }
}
