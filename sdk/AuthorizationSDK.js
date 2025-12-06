const http = require('http');
const https = require('https');
const { URL } = require('url');

class AuthorizationSDK {
  constructor(options = {}) {
    const envBase = process.env.AUTHZ_ADDR || process.env.AUTHZCTL_ADDR || 'http://localhost:8080';
    this.baseUrl = (options.baseUrl || envBase).replace(/\/?$/, '/');
    this.token = options.token || process.env.AUTHZ_TOKEN || process.env.AUTHZCTL_TOKEN || '';
  }

  async checkAccess({ tenantID, subject, resource, action, conditions = {} }) {
    return this.#postJson('check-access', { tenantID, subject, resource, action, conditions });
  }

  async simulateAccess({ tenantID, subject, resource, action, context = {} }) {
    return this.#postJson('simulate', { tenantID, subject, resource, action, context });
  }

  async compileRule(tenantID, rule) {
    const response = await this.#postJson('compile', { tenantID, rule }, false);
    return response;
  }

  async validatePolicy(tenantID, policy) {
    const response = await this.#postJson('validate-policy', { tenantID, policy }, false);
    return response;
  }

  async #postJson(path, payload, parseJson = true) {
    const url = new URL(path.replace(/^\//, ''), this.baseUrl);
    const body = JSON.stringify(payload ?? {});
    const headers = { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) };
    if (this.token) {
      headers.Authorization = `Bearer ${this.token}`;
    }

    const isHttps = url.protocol === 'https:';
    const client = isHttps ? https : http;

    return new Promise((resolve, reject) => {
      const req = client.request(
        url,
        { method: 'POST', headers },
        (res) => {
          const chunks = [];
          res.on('data', (chunk) => chunks.push(chunk));
          res.on('end', () => {
            const responseText = Buffer.concat(chunks).toString('utf-8');
            if (res.statusCode !== 200) {
              reject(new Error(`unexpected status ${res.statusCode}: ${responseText}`));
              return;
            }
            if (!parseJson) {
              resolve(responseText);
              return;
            }
            try {
              resolve(JSON.parse(responseText));
            } catch (err) {
              reject(err);
            }
          });
        }
      );

      req.on('error', reject);
      req.write(body);
      req.end();
    });
  }
}

module.exports = AuthorizationSDK;
