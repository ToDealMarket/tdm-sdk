import { defineConfig } from "tsup";
import { jsOutExtension, sdkEntries } from "./tsup.shared";

export default defineConfig({
  entry: sdkEntries,
  clean: false,
  dts: false,
  format: ["esm", "cjs"],
  target: "es2022",
  sourcemap: false,
  minify: false,
  treeshake: true,
  splitting: false,
  outDir: "dist",
  outExtension({ format }) {
    return jsOutExtension(format);
  },
});
