# API Reference

## POST /authorize [Not Yet Available]

Evaluate an authorization decision using a Verifiable Credential and request context including consent status.

### Request Body

```json
{
  "credential": { /* Verifiable Credential */ },
  "context": {
    "action": "read",
    "resource": "document:123",
    "environment": {
      "tenantID": "default"
    },
    "consent": "granted"
  }
}
```

### Response

Returns an authorization decision from the policy engine.
