# Policy Schema

Policies are expressed in YAML and define role-to-permission mappings scoped by tenant.

```yaml
# configs/default/policy.yaml
tenants:
  default:
    roles:
      admin:
        permissions:
          - user:list
          - user:create
          - policy:read
      viewer:
        permissions:
          - user:list
```

## Schema

- `tenants` – map of tenant identifiers.
- `roles` – map of role names within a tenant.
- `permissions` – list of allowed actions for the role.

Tenants without an explicit entry fall back to `default` only when the principal
omits a tenant value. Unknown tenants or roles are denied by default.

## Example

```yaml
tenants:
  acme:
    roles:
      editor:
        permissions:
          - doc:write
  default:
    roles:
      viewer:
        permissions:
          - user:list
```

