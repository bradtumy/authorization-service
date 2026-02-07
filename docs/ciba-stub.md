# CIBA Consent Escalation (Stub)

## Status
CIBA is not implemented in this repository yet. This document defines the intended contract for a future implementation.

## Intended Endpoints
- `POST /backchannel/authentication` to create a backchannel authentication request.
- `POST /token` with `grant_type=urn:openid:params:grant-type:ciba` to poll for tokens.

## MVP Stub Expectations
- Authentication of CIBA clients using the same client registry as `/token`.
- Local/dev approval simulation via a simple approval store or in-memory map.
- Audit log entries on request creation, approval, and token issuance.

## Deferred Items
- Binding between auth request and token (nonce, jti).
- Push mode and callback delivery.
