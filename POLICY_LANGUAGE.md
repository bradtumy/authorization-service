# Policy Language

Policies are written in YAML and loaded from `./policies/*.yaml`. Each file contains a list of rules.

## Rule Fields

- `id` – unique identifier for the rule.
- `effect` – `allow` or `deny`.
- `roles` – list of required roles (RBAC).
- `actions` – operations the rule applies to. `*` matches any action.
- `resources` – protected resources. `*` matches any resource.
- `conditions` – key/value attributes evaluated against VC and environment facts (ABAC).
- `advice` – optional message returned when a deny rule matches.

## Example

```yaml
- id: admin-read
  effect: allow
  roles: ["admin"]
  actions: ["read"]
  resources: ["*"]

- id: sales-view
  effect: allow
  actions: ["view"]
  resources: ["report"]
  conditions:
    department: sales
```

