# Testing

Run unit tests:

```sh
make test
```

To test locally against a custom JWKS, start an HTTP server that serves a `jwks.json` file and point `identity.jwks_url` to it in the configuration.

For end-to-end tests or manual API calls, include a valid JWT in the `Authorization` header:

```sh
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/healthz
```
