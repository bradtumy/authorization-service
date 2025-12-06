# Authorization SDKs

This directory contains lightweight SDK clients for the authorization service in Node.js, Go, and Python. All SDKs align with the API routes exposed by the service and mirror the behavior of the `authzctl` terminal utility (e.g., `/check-access`, `/simulate`, `/compile`, `/validate-policy`).

## Node.js

### Configuration

- `AUTHZ_ADDR`/`AUTHZCTL_ADDR` (optional): Base URL for the service. Defaults to `http://localhost:8080`.
- `AUTHZ_TOKEN`/`AUTHZCTL_TOKEN` (optional): Bearer token to include on requests.

### Usage

```javascript
const AuthorizationSDK = require('./AuthorizationSDK');
const sdk = new AuthorizationSDK({ baseUrl: 'http://localhost:8080', token: 'my-token' });

const decision = await sdk.checkAccess({
  tenantID: 't1',
  subject: 'user',
  resource: 'file',
  action: 'read',
  conditions: { ip: '127.0.0.1' },
});

const simulation = await sdk.simulateAccess({
  tenantID: 't1',
  subject: 'user',
  resource: 'file',
  action: 'read',
  context: { environment: 'dev' },
});

const compiled = await sdk.compileRule('t1', 'allow subject where true');
const validation = await sdk.validatePolicy('t1', 'policy: allow');
```

### Tests

Run `node --test sdk/AuthorizationSDK.test.js`.

## Go

```go
client := sdk.NewClient("http://localhost:8080")

// Check access
result, err := client.CheckAccess(sdk.AccessRequest{
    TenantID: "t1",
    Subject:  "user",
    Resource: "file",
    Action:   "read",
})

// Simulate with explicit context
simulation, err := client.SimulateAccess(sdk.SimulationRequest{
    TenantID: "t1",
    Subject:  "user",
    Resource: "file",
    Action:   "read",
    Context:  map[string]string{"environment": "dev"},
})

// Compile and validate policies
compiled, err := client.CompileRule("t1", "allow subject where true")
err = client.ValidatePolicy("t1", "policy: allow")
```

Run `go test ./sdk/go` to execute the Go SDK tests.

## Python

```python
from sdk.python.authorization import Client

client = Client('http://localhost:8080', token='my-token')

# Check and simulate
client.check_access('t1', 'user', 'file', 'read', {'ip': '127.0.0.1'})
client.simulate_access('t1', 'user', 'file', 'read', {'environment': 'dev'})

# Compile and validate
client.compile_rule('t1', 'allow subject where true')
client.validate_policy('t1', 'policy: allow')
```

Run `python -m pytest sdk/python/test_authorization.py` to exercise the Python SDK.
