# API Reference

## POST /authorize

Evaluate an authorization decision using a Verifiable Credential and request context.

### Request Body

```json
{
  "credential": { /* Verifiable Credential */ },
  "context": {
    "action": "read",
    "resource": "document:123",
    "environment": {
      "tenantID": "default"
    }
  }
}
```

### Response

Returns an authorization decision from the policy engine.
