# Authorization Service

[![CI](https://github.com/bradtumy/authorization-service/actions/workflows/ci.yml/badge.svg)](https://github.com/bradtumy/authorization-service/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/bradtumy/authorization-service)](https://goreportcard.com/report/github.com/bradtumy/authorization-service)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Authorization-Service is an open-source, multi-tenant, context-aware, risk-adaptive authorization engine for modern applications.

## Quickstart

```sh
git clone https://github.com/bradtumy/authorization-service.git
cd authorization-service
cp .env.example .env
# edit as needed
```

`.env` should contain:

```
CLIENT_ID=my-client-id
CLIENT_SECRET=my-client-secret
PORT=8080
OIDC_ISSUERS=http://localhost:8081/realms/master
OIDC_AUDIENCES=authorization-service
OIDC_TENANT_CLAIM=tenantID
```

Example configuration file (`configs/default/config.yaml`):

```yaml
identity:
  issuer: "https://idp.example.com/realms/main"
  jwks_url: "https://idp.example.com/realms/main/protocol/openid-connect/certs"
  audience: "authorization-service"
  claims:
    subject: "sub"
    username: "preferred_username"
    tenant: "tenant"
    roles:
      - "realm_access.roles"
      - "resource_access.authorization-service.roles"
    strip_prefix: ""
server:
  addr: ":8080"
  log_level: "info"
```

Tokens are verified against the issuer's JWKS and must include `sub`, `aud`, `exp` and the `tenantID` claim (or the name specified by `OIDC_TENANT_CLAIM`). A typical payload looks like:

```json
{
  "iss": "https://idp.example.com/",
  "sub": "alice",
  "aud": "authorization-service",
  "exp": 1700000000,
  "tenantID": "acme",
  "email": "alice@example.com",
  "roles": ["TenantAdmin"]
}
```

Any OpenID Connect–compliant provider (Keycloak, Auth0, Azure AD, Okta, etc.) can issue tokens for the service.

Start the service:

```sh
docker compose up --build
```

### RBAC Quickstart

Define tenant‑scoped roles and permissions in `configs/default/policy.yaml`:

```yaml
tenants:
  default:
    roles:
      admin:
        permissions: ["user:list","user:create","policy:read"]
      viewer:
        permissions: ["user:list"]
```

Load the policy and check access in Go:

```go
store, _ := policy.NewFileStore("configs/default/policy.yaml")
authz := authz.NewRBAC(store, time.Minute)
allowed, _ := authz.IsAllowed(ctx, principal, policy.Permission("user:list"), nil)
```

Load the sample policy:

```sh
cp examples/rbac.yaml configs/policies.yaml
curl -X POST http://localhost:8080/reload -d '{"tenantID":"default"}'
```

Expected:

```text
policies reloaded
```

Check access:

```sh
curl -s -X POST http://localhost:8080/check-access \
  -H 'Content-Type: application/json' \
  -d '{"tenantID":"default","subject":"alice","resource":"file1","action":"read"}'
```

Expected response:

```json
{"allow":true}
```

Troubleshooting: if the service fails to start, ensure `.env` exists and the port in use is free.

### Policy as Code Quickstart

The service can source policies from a Git repository so that they can be versioned and tested like application code.

1. Clone the [customer-policies](https://github.com/your-org/customer-policies) template.
2. Write YAML policies under `policies/` and add tests under `tests/`.
3. Run the following commands locally:

   ```bash
   authzctl policy validate policies/rbac.yaml   # lint
   authzctl test tests/                          # run tests
   authzctl simulate --bundle policies/          # dry‑run
   authzctl apply-bundle policies/               # deploy
   ```

4. CI/CD executes the same lint → test → simulate → deploy workflow via `.github/workflows/deploy.yaml`.
5. After deployment, verify the active policy version:

   ```bash
   curl -s http://localhost:8080/policies/version
   ```

The returned commit SHA is also echoed in `/check-access` responses under the `commit` field of the decision.

## Feature Highlights

- **RBAC** – role-based access control policies.
- **ABAC** – attribute-based rules.
- **Graph** – relationship graphs for complex hierarchies.
- **Delegation** – temporary privileges with delegation chains.
- **Context & Risk** – adapt decisions to runtime signals.
- **Simulation** – dry-run policy evaluation.
- **OIDC** – identity tokens via OpenID Connect.
- **Observability** – metrics, logs and traces for every decision.

## Getting Started Example

`examples/rbac.yaml`:

```yaml
roles:
  - name: admin
    policies:
      - allow-read-all
users:
  - username: alice
    roles: [admin]
policies:
  - id: allow-read-all
    subjects:
      - role: admin
    resources:
      - "*"
    actions:
      - read
    effect: allow
```

Run a check:

```sh
curl -s -X POST http://localhost:8080/check-access \
  -H 'Content-Type: application/json' \
  -d '{"tenantID":"default","subject":"alice","resource":"file1","action":"read"}'
```

## Documentation

- [Quickstart](docs/quickstart.md)
- [Local End-to-End Testing](docs/local-testing.md)
- [Tenants](docs/tenants.md)
- [Policies](docs/policies.md)
- [Graph](docs/graph.md)
- [Delegation](docs/delegation.md)
- [Context & Risk](docs/context.md)
- [Remediation](docs/remediation.md)
- [Simulation](docs/simulation.md)
- [OIDC](docs/oidc.md)
- [Observability](docs/observability.md)
- [Deployment](docs/deployment.md)
- [Contributing](docs/contributing.md)
- [Architecture](docs/architecture.md) · [Flows](docs/flows.md)

Examples live in [`examples/`](examples) and the Postman collection in [`postman/`](postman).

## Managing Users Dynamically via API

Users and their roles can be managed at runtime using the User Management API. All requests require a bearer token from a user with either the `TenantAdmin` or `PolicyAdmin` role.

Create a user:

```sh
curl -X POST http://localhost:8080/user/create \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <token>' \
  -d '{"tenantID":"default","username":"bob"}'
```

List users:

```sh
curl -H 'Authorization: Bearer <token>' \
  'http://localhost:8080/user/list?tenantID=default'
```

Additional endpoints support assigning roles, deleting users and fetching a single user. See [docs/users.md](docs/users.md) for details.

## License

Apache 2.0 licensed. See [LICENSE](LICENSE).
