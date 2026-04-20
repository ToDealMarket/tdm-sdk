export interface CombinedAbortSignal {
  signal: AbortSignal;
  cleanup(): void;
}

function buildNoopResult(signal: AbortSignal): CombinedAbortSignal {
  return {
    signal,
    cleanup() {
      // no-op
    },
  };
}

export function combineAbortSignals(
  primary: AbortSignal,
  secondary?: AbortSignal,
): CombinedAbortSignal {
  if (!secondary) {
    return buildNoopResult(primary);
  }
  if (primary.aborted) {
    return buildNoopResult(primary);
  }
  if (secondary.aborted) {
    return buildNoopResult(secondary);
  }

  const abortSignalAny = (AbortSignal as typeof AbortSignal & {
    any?: (signals: AbortSignal[]) => AbortSignal;
  }).any;
  if (typeof abortSignalAny === 'function') {
    return buildNoopResult(abortSignalAny([primary, secondary]));
  }

  const controller = new AbortController();
  const abort = () => {
    controller.abort();
  };

  primary.addEventListener('abort', abort, { once: true });
  secondary.addEventListener('abort', abort, { once: true });

  return {
    signal: controller.signal,
    cleanup() {
      primary.removeEventListener('abort', abort);
      secondary.removeEventListener('abort', abort);
    },
  };
}
