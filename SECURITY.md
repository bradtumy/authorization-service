# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability, please email **opensource@bradtumy.com** with details.

We will investigate and respond as quickly as possible. Please do not publicly disclose the issue until we have addressed it.

## Supported Versions

Security fixes are applied to the latest main branch. Please upgrade to the newest release to ensure you have the latest patches.

## Token Verification

The service validates all JWTs against the following rules:

- `iss` and `aud` must match configured values.
- `exp` and `nbf` are enforced with a ±60s clock skew tolerance.
- Signing keys are loaded from the issuer's JWKS endpoint, cached by `kid`, and refreshed in the background with jitter to avoid thundering herds.
- Tokens or claims are never logged.

