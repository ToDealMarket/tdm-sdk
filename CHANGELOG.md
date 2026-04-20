# Changelog

All notable changes to `tdm-sdk` should be recorded here.

This project follows a simple release rule:

- every published npm version gets a short entry
- breaking changes must be called out explicitly
- rollback guidance should prefer `dist-tag` moves or a follow-up fix release, not unpublish

## Unreleased

- release-hardening for npm publication:
  - pack verification
  - release manifest generation
  - dedicated publish workflow
  - documented rollback rules

## 0.0.2-beta

- added friendly gateway facade clients:
  - `tdm-sdk/authorize`
  - `tdm-sdk/session-tanks`
  - `tdm-sdk/checkout`
- added route-first payable helpers:
  - `chargeFetchHandler(...)`
  - `chargeExpressHandler(...)`
  - `chargeNextHandler(...)`
- added shared gateway helpers:
  - `createGatewayTransport(...)`
  - `createGatewayAuthContext(...)`
  - `createGatewayClients(...)`
- updated docs and examples to match the current public payment contract
