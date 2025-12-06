const http = require('http');
const test = require('node:test');
const assert = require('node:assert');
const { once } = require('events');
const AuthorizationSDK = require('./AuthorizationSDK');

const responses = {
  '/check-access': { status: 200, body: JSON.stringify({ allow: true, policyID: 'p1', reason: 'ok' }) },
  '/simulate': { status: 200, body: JSON.stringify({ allow: false, reason: 'simulated' }) },
  '/compile': { status: 200, body: 'compiled policy' },
  '/validate-policy': { status: 200, body: 'policy valid' },
};

const server = http.createServer((req, res) => {
  const response = responses[req.url];
  if (!response) {
    res.writeHead(404).end();
    return;
  }
  res.writeHead(response.status, { 'Content-Type': 'application/json' });
  res.end(response.body);
});

let baseUrl;

const ready = (async () => {
  server.listen(0);
  await once(server, 'listening');
  const { port } = server.address();
  baseUrl = `http://localhost:${port}`;
})();

test.before(async () => {
  await ready;
});

test('checkAccess returns decision payload', async () => {
  const sdk = new AuthorizationSDK({ baseUrl, token: 'abc' });
  const decision = await sdk.checkAccess({ tenantID: 't', subject: 's', resource: 'r', action: 'a' });
  assert.strictEqual(decision.allow, true);
});

test('simulateAccess returns simulated decision', async () => {
  const sdk = new AuthorizationSDK({ baseUrl });
  const decision = await sdk.simulateAccess({ tenantID: 't', subject: 's', resource: 'r', action: 'a', context: { k: 'v' } });
  assert.strictEqual(decision.reason, 'simulated');
});

test('compileRule returns raw response', async () => {
  const sdk = new AuthorizationSDK({ baseUrl });
  const compiled = await sdk.compileRule('tenant', 'rule');
  assert.strictEqual(compiled, 'compiled policy');
});

test('validatePolicy returns raw response', async () => {
  const sdk = new AuthorizationSDK({ baseUrl });
  const result = await sdk.validatePolicy('tenant', 'policy');
  assert.strictEqual(result, 'policy valid');
});

test.after(() => {
  server.close();
});
