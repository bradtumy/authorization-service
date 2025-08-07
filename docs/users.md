# Users

## Overview
Users encapsulate principals within a tenant and hold zero or more roles. The service exposes endpoints for managing users dynamically at runtime.

## Keycloak Integration
Set the environment variable `IDENTITY_BACKEND=keycloak` to use Keycloak for identity management. The provider reads the following configuration from the environment:

- `KEYCLOAK_BASE_URL` – base URL of the Keycloak server
- `KEYCLOAK_CLIENT_ID` – client ID with access to the Admin API
- `KEYCLOAK_CLIENT_SECRET` – client secret for the client above

Each tenant maps to a Keycloak realm. Users and roles are managed via the Keycloak Admin REST API.

## API Usage
Create a user:
```sh
curl -X POST http://localhost:8080/user/create \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <token>' \
  -d '{"tenantID":"acme","username":"alice","roles":["TenantAdmin"]}'
```
Assign roles:
```sh
curl -X POST http://localhost:8080/user/assign-role \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <token>' \
  -d '{"tenantID":"acme","username":"alice","roles":["PolicyAdmin"]}'
```
Delete a user:
```sh
curl -X POST http://localhost:8080/user/delete \
  -H 'Content-Type: application/json' \
  -H 'Authorization: Bearer <token>' \
  -d '{"tenantID":"acme","username":"alice"}'
```
List users for a tenant:
```sh
curl -H 'Authorization: Bearer <token>' \
  'http://localhost:8080/user/list?tenantID=acme'
```
Get a specific user:
```sh
curl -H 'Authorization: Bearer <token>' \
  'http://localhost:8080/user/get?tenantID=acme&username=alice'
```

## Authorization
All endpoints require an `Authorization: Bearer <token>` header. Only callers with the `TenantAdmin` or `PolicyAdmin` role within the target tenant may invoke these APIs.

## CLI Usage
No dedicated CLI commands exist yet; use the API examples above or integrate via the SDK.

## Persistence
Run the server with `--persist-users` to store users under `configs/<tenantID>/users.yaml`.
