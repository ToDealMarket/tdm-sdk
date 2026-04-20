import { existsSync, readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const repoRoot = dirname(
  fileURLToPath(new URL("../package.json", import.meta.url)),
);
const packageJsonPath = join(repoRoot, "package.json");
const packageLockPath = join(repoRoot, "package-lock.json");

function fail(message) {
  console.error(`[TDM SDK release] ${message}`);
  process.exit(1);
}

function readJson(pathname) {
  return JSON.parse(readFileSync(pathname, "utf8"));
}

function normalizePackPath(pathname) {
  return pathname.replace(/\\/g, "/");
}

const pkg = readJson(packageJsonPath);
const lock = readJson(packageLockPath);
const isPublicRepo = pkg.tdmPublicRepo === true;

if (
  pkg.version !== lock.version ||
  pkg.version !== lock.packages?.[""]?.version
) {
  fail("package.json and package-lock.json versions are out of sync.");
}

const requiredDiskFiles = [
  "README.md",
  "LICENSE",
  "dist/index.mjs",
  "dist/index.cjs",
  "dist/index.d.ts",
  ...(
    isPublicRepo
      ? []
      : [
          "dist/ui-public/index.html",
          "dist/ui-public/assets/phantom.svg",
          "dist/ui-public/assets/metamask.svg",
          "dist/ui-public/assets/coinbase.svg",
          "dist/ui-public/assets/brave.svg",
          "dist/ui-public/assets/backpack.svg",
          "dist/ui-public/assets/glow.svg",
          "dist/ui-public/assets/rabby.svg",
          "dist/ui-public/assets/solflare.svg",
          "dist/ui-public/assets/nightly.svg",
          "dist/ui-public/assets/trust.svg",
          "dist/ui-public/assets/solana.svg",
          "dist/ui-public/assets/base.svg",
        ]
  ),
];

for (const relativePath of requiredDiskFiles) {
  if (!existsSync(join(repoRoot, relativePath))) {
    fail(
      `Missing required build artifact on disk: ${relativePath}. Run \`npm run build\` first.`,
    );
  }
}

const exportTargets = new Set();
for (const value of Object.values(pkg.exports ?? {})) {
  if (value && typeof value === "object") {
    for (const target of Object.values(value)) {
      if (typeof target === "string") {
        exportTargets.add(target.replace(/^\.\//, ""));
      }
    }
  }
}

if (pkg.bin?.tdm) {
  exportTargets.add(String(pkg.bin.tdm).replace(/^\.\//, ""));
}

for (const target of exportTargets) {
  if (!existsSync(join(repoRoot, target))) {
    fail(`Export target is missing on disk: ${target}`);
  }
}

const packResult = spawnSync("npm", ["pack", "--json", "--dry-run"], {
  cwd: repoRoot,
  encoding: "utf8",
  shell: process.platform === "win32",
});

if (packResult.status !== 0) {
  fail(
    packResult.stderr.trim() ||
      packResult.stdout.trim() ||
      "npm pack --dry-run failed.",
  );
}

let packEntries;
try {
  packEntries = JSON.parse(packResult.stdout);
} catch (error) {
  fail(
    `Could not parse npm pack output: ${error instanceof Error ? error.message : String(error)}`,
  );
}

const summary = Array.isArray(packEntries) ? packEntries[0] : null;
if (!summary || !Array.isArray(summary.files)) {
  fail("npm pack did not return a file list.");
}

const packedFiles = new Set(
  summary.files.map((entry) => normalizePackPath(entry.path)),
);

const requiredPackedFiles = [
  "package.json",
  "README.md",
  "LICENSE",
  "examples/README.md",
  "dist/index.mjs",
  "dist/index.cjs",
  "dist/index.d.ts",
  ...(
    isPublicRepo
      ? []
      : [
          "dist/ui-public/index.html",
          "dist/ui-public/assets/phantom.svg",
          "dist/ui-public/assets/metamask.svg",
          "dist/ui-public/assets/coinbase.svg",
          "dist/ui-public/assets/brave.svg",
          "dist/ui-public/assets/backpack.svg",
          "dist/ui-public/assets/glow.svg",
          "dist/ui-public/assets/rabby.svg",
          "dist/ui-public/assets/solflare.svg",
          "dist/ui-public/assets/nightly.svg",
          "dist/ui-public/assets/trust.svg",
          "dist/ui-public/assets/solana.svg",
          "dist/ui-public/assets/base.svg",
        ]
  ),
];

for (const relativePath of requiredPackedFiles) {
  if (!packedFiles.has(relativePath)) {
    fail(`Packed artifact is missing required file: ${relativePath}`);
  }
}

for (const target of exportTargets) {
  if (!packedFiles.has(normalizePackPath(target))) {
    fail(`Packed artifact is missing export target: ${target}`);
  }
}

console.log(
  JSON.stringify(
    {
      ok: true,
      package: pkg.name,
      version: pkg.version,
      packedFileCount: summary.files.length,
      unpackedSize: summary.unpackedSize ?? null,
      tarballName: summary.filename ?? null,
    },
    null,
    2,
  ),
);
