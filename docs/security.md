# Security Considerations

## Token Issuance
- Rotate `TOKEN_SIGNING_KEY` regularly and store it securely (KMS/secret manager).
- Restrict `TOKEN_AUDIENCE` and `TOKEN_ISSUER` to trusted values.
- Set short TTLs for agent tokens; override with policy hooks only when necessary.

## Policy Hooks
- Use `POLICY_HOOKS_ALLOWED_HOSTS` to prevent SSRF.
- Enforce timeouts and fail-closed behavior for sensitive grants.
- Do not log PII or secret claims returned by the PDP.

## Delegation
- Use `act` claims to represent actor-subject relationships.
- Ensure delegated tokens have reduced TTLs and narrowed scopes.

## CIBA (Deferred)
- Bind auth requests to token issuance using nonces and audit logs.
- Rate limit polling and protect against phishing attacks.
