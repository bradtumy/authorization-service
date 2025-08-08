# Examples [Not Yet Available]

Sample Verifiable Credential and context files (including consent status) are available in the `examples` directory.

```bash
curl -X POST http://localhost:8080/authorize \
  -H 'Content-Type: application/json' \
  -d @<(jq -s '{credential:.[0], context:.[1]}' examples/vc.json examples/context.json)
```
