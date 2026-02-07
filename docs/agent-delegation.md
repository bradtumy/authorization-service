# Agent Delegation via OAuth

## Overview
This repo now supports issuing OAuth tokens for agents via the `client_credentials` grant. Delegation semantics (actor vs subject) are embedded using the `act` claim when provided by policy hooks.

## Token Issuance
Use the `/token` endpoint with client credentials and a tenant identifier:

```sh
curl -s -X POST http://localhost:8080/token \
  -u "$CLIENT_ID:$CLIENT_SECRET" \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -d 'grant_type=client_credentials&tenant_id=acme&scope=read'
```

## Delegation Claims
Policy hooks can embed delegation metadata using the `act` claim, for example:

```json
{"act": {"sub": "agent"}}
```

## Notes
- Token exchange (RFC 8693) is deferred; this MVP focuses on agent tokens minted directly for client credentials.
- Keep delegated token TTLs short and scopes narrowly scoped using policy hooks.
