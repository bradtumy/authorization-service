# Developer Setup [Not Yet Available]

Run the service locally and exercise the `/authorize` endpoint with the sample files.

```bash
go run ./cmd/authorization-service
```

In another terminal, post a request combining the provided Verifiable Credential and context files:

```bash
curl -X POST http://localhost:8080/authorize \
  -H 'Content-Type: application/json' \
  -d @<(jq -s '{credential:.[0], context:.[1]}' examples/vc.json examples/context.json)
```

The response will contain the authorization decision or a descriptive error if validation fails.
