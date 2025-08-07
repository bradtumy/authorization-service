# Configuration

A sample configuration lives in `configs/default/config.yaml`:

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

## Fields

| Path                                   | Type     | Default | Description                                      |
|----------------------------------------|----------|---------|--------------------------------------------------|
| `identity.issuer`                      | string   | —       | Expected `iss` claim.                            |
| `identity.jwks_url`                    | string   | —       | JWKS endpoint for verifying tokens.             |
| `identity.audience`                    | string   | —       | Expected `aud` claim.                            |
| `identity.claims.subject`              | string   | `sub`   | Claim path for the subject identifier.          |
| `identity.claims.username`             | string   | `preferred_username` | Claim path for the username.          |
| `identity.claims.tenant`               | string   | `tenant`| Claim path for the tenant (optional).           |
| `identity.claims.roles`                | []string | shown   | Claim paths evaluated for roles.                |
| `identity.claims.strip_prefix`         | string   | ``      | Prefix removed from roles before normalization. |
| `server.addr`                          | string   | `:8080` | Listen address.                                  |
| `server.log_level`                     | string   | `info`  | Log level.                                       |

