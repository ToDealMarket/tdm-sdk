import { defineConfig } from "tsup";
import { sdkEntries } from "./tsup.shared";

export default defineConfig({
  entry: sdkEntries,
  clean: false,
  dts: {
    only: true,
  },
  format: ["esm", "cjs"],
  target: "es2022",
  sourcemap: false,
  minify: false,
  treeshake: true,
  splitting: false,
  outDir: "dist",
});
