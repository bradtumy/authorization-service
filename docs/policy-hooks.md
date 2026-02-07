# Policy Hooks

## Overview
Policy hooks let the authorization service consult an external PDP before issuing tokens. The hook can deny issuance, narrow scopes, and add bounded claims.

## Configuration
Set environment variables:

| Variable | Description |
| --- | --- |
| `POLICY_HOOKS_ENABLED` | Enable pre-issue hook (`true`/`false`). |
| `POLICY_HOOKS_ENDPOINT` | PDP HTTP endpoint for pre-issue decisions. |
| `POLICY_HOOKS_TIMEOUT` | Request timeout (e.g. `3s`). |
| `POLICY_HOOKS_ALLOWED_HOSTS` | Comma-separated host allowlist for SSRF protection. |
| `POLICY_HOOKS_FAIL_CLOSED` | Fail issuance on hook error (`true` default). |

## Request Contract
The service posts JSON to the PDP:

```json
{
  "grant_type": "client_credentials",
  "client_id": "agent-client",
  "subject": "agent-client",
  "requested_scopes": ["read"],
  "audience": "authorization-service",
  "tenant_id": "acme",
  "requested_ttl_seconds": 3600
}
```

## Response Contract
The PDP responds with:

```json
{
  "allow": true,
  "scopes_to_issue": ["read"],
  "claims_to_embed": {"act": {"sub": "agent"}},
  "ttl_override_seconds": 900,
  "deny_reason": "policy"
}
```

## Notes
- Decision outcomes and detailed reasoning remain in the PDP/AAAP layer.
- Hook failures are fail-closed by default; set `POLICY_HOOKS_FAIL_CLOSED=false` for dev-only fail-open behavior.
