export const sdkEntries = {
  index: "src/index.ts",
  authorize: "src/runtime/session/authorize.ts",
  checkout: "src/domain/payments/checkout.ts",
  crypto: "src/crypto.ts",
  "local-402-circuit": "src/runtime/session/local-402-circuit.ts",
  "local-vault": "src/domain/vault/local-vault.ts",
  "make-payable": "src/domain/payments/make-payable.ts",
  "fetch-hook-client": "src/runtime/gateway/fetch-hook-client.ts",
  "framework-mode": "src/runtime/modes/framework-mode.ts",
  "gateway-auth": "src/runtime/gateway/gateway-auth.ts",
  "gateway-clients": "src/runtime/gateway/gateway-clients.ts",
  "gateway-transport": "src/runtime/gateway/gateway-transport.ts",
  "session-tanks": "src/runtime/session/session-tanks.ts",
  timeout: "src/runtime/session/timeout.ts",
} as const;

export function jsOutExtension(format: "esm" | "cjs"): { js: ".mjs" | ".cjs" } {
  return {
    js: format === "esm" ? ".mjs" : ".cjs",
  };
}
