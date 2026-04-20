# Releasing `tdm-sdk`

## Principles

- npm publication is immutable by version
- rollback should prefer `dist-tag` correction and deprecation, not unpublish
- publish only from a clean, verified build
- keep `beta` and `latest` as separate release channels until the stable surface is intentional

## Default release channel

Current default channel:

- `beta`

Do not move to `latest` until you deliberately want broad stable installs.

## Pre-release checklist

From `mvp/tdm-sdk`:

```bash
npm ci
npm run release:check
```

What that covers:

- `typecheck`
- `build`
- CLI smoke
- tests
- `npm pack --dry-run` verification against the built exports

## Produce the tarball and release manifest

```bash
npm pack
node scripts/write-release-manifest.mjs --artifact tdm-sdk-<version>.tgz --tag beta
```

This writes a JSON manifest into `release-manifests/` with:

- package version
- dist-tag
- git commit when available
- tarball hash and size

## Publish

Manual npm publish:

```bash
npm publish tdm-sdk-<version>.tgz --tag beta --access public
```

Or use the GitHub Actions workflow:

- `.github/workflows/release-sdk.yml`

## Recommended versioning flow

Examples:

```bash
npm version prerelease --preid=beta
npm version patch
npm version minor
```

After bumping the version:

- commit the version change
- tag the commit
- run `npm run release:check`
- pack and publish

## Rollback model

There is no Cloudflare-style version rollback for npm packages.

Preferred rollback tools:

1. move the dist-tag back to the last good version
2. deprecate the bad version
3. publish a fixed follow-up version

Examples:

```bash
npm dist-tag add tdm-sdk@0.0.1-beta beta
npm deprecate tdm-sdk@0.0.2-beta "Use 0.0.1-beta while 0.0.2-beta is being corrected."
```

Do not treat `npm unpublish` as the normal rollback path.

## Release journal

For each publish, record:

- version
- dist-tag
- git commit
- date
- checks performed
- notable changes
- rollback target

Keep the short human summary in `CHANGELOG.md`.
