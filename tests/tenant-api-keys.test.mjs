import test from 'node:test';
import assert from 'node:assert/strict';
import { startRidServer } from '../apps/id/dist/server.js';
import { IdentityDatabase } from '../apps/id/dist/storage/sqlite.js';
import { createTenantApiKeyService } from '../apps/id/dist/services/tenant-api-keys.js';

test('TenantApiKeyService stores SHA-256 hash only, verifies scopes, updates last_used_at, and enforces expiry/revocation/isolation', () => {
  const db = new IdentityDatabase(':memory:');
  try {
    const service = createTenantApiKeyService(db);
    const t0 = 1_700_000_000_000;

    const createdA = service.createKey({
      tenantId: 'tenant-alpha',
      name: 'ci-runner',
      scopes: ['api:read', 'ci:trigger', 'api:read'],
      expiresInDays: 7,
      nowMs: t0,
    });

    assert.match(createdA.apiKey, /^mw_k_[0-9a-f]{12}_[A-Za-z0-9_-]+$/);
    assert.equal(createdA.key.tenantId, 'tenant-alpha');
    assert.equal(createdA.key.name, 'ci-runner');
    assert.deepEqual(createdA.key.scopes, ['api:read', 'ci:trigger']);
    assert.equal(createdA.key.status, 'active');
    assert.equal(createdA.key.lastUsedAt, null);
    assert.equal('secret_hash' in createdA.key, false);

    // Plaintext key MUST NOT be stored anywhere in SQLite
    const rawRow = db.findTenantApiKeyById(createdA.key.id);
    assert.ok(rawRow);
    assert.notEqual(rawRow.secret_hash, createdA.apiKey);
    assert.equal(rawRow.secret_hash.length, 64);
    assert.equal(JSON.stringify(db.listOutboxEvents(false)).includes(createdA.apiKey), false);

    // Second tenant key for isolation
    const createdB = service.createKey({
      tenantId: 'tenant-beta',
      name: 'billing-worker',
      scopes: ['billing:write'],
      nowMs: t0,
    });

    const listAlpha = service.listKeys('tenant-alpha');
    assert.equal(listAlpha.length, 1);
    assert.equal(listAlpha[0].id, createdA.key.id);
    assert.equal('secret_hash' in listAlpha[0], false);

    const listBeta = service.listKeys('tenant-beta');
    assert.equal(listBeta.length, 1);
    assert.equal(listBeta[0].id, createdB.key.id);

    // Verify valid key updates last_used_at
    const tVerify = t0 + 60_000;
    const verified = service.verifyKey(createdA.apiKey, tVerify);
    assert.deepEqual(verified, {
      valid: true,
      id: createdA.key.id,
      tenantId: 'tenant-alpha',
      name: 'ci-runner',
      keyPrefix: createdA.key.keyPrefix,
      scopes: ['api:read', 'ci:trigger'],
    });

    const afterUse = db.findTenantApiKeyById(createdA.key.id);
    assert.equal(afterUse.last_used_at, new Date(tVerify).toISOString());

    // Expired key rejected
    const expired = service.verifyKey(createdA.apiKey, t0 + 7 * 86_400_000 + 1);
    assert.deepEqual(expired, { valid: false, reason: 'expired' });

    // Invalid format & unknown key rejected
    assert.deepEqual(service.verifyKey('not_a_key'), { valid: false, reason: 'invalid_format' });
    assert.deepEqual(
      service.verifyKey('mw_k_001122334455_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'),
      { valid: false, reason: 'not_found' },
    );

    // Tenant-scoped revocation prevents cross-tenant revoke
    assert.equal(service.revokeKey(createdA.key.id, 'tenant-beta'), false);
    assert.equal(service.revokeKey(createdA.key.id, 'tenant-alpha'), true);
    assert.equal(service.revokeKey(createdA.key.id, 'tenant-alpha'), false);

    // Revoked key rejected
    assert.deepEqual(service.verifyKey(createdA.apiKey, t0 + 120_000), {
      valid: false,
      reason: 'revoked',
    });
  } finally {
    db.close();
  }
});

test('startRidServer tenant API key CRUD, verification, and revocation endpoints work end-to-end', async () => {
  const running = await startRidServer({
    port: 0,
    host: '127.0.0.1',
    dbPath: ':memory:',
    nodeEnv: 'test',
    signingKeyOptions: { nodeEnv: 'test', allowEphemeralKeys: true },
  });

  try {
    // 1. Create key for tenant-01
    const createResp = await fetch(`${running.url}/api/tenants/tenant-01/api-keys`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        name: 'deploy-token',
        scopes: ['paas:deploy', 'paas:read'],
        expiresInDays: 30,
      }),
    });
    assert.equal(createResp.status, 201);
    const createdBody = await createResp.json();
    assert.ok(createdBody.apiKey.startsWith('mw_k_'));
    assert.equal(createdBody.key.tenantId, 'tenant-01');
    assert.equal(createdBody.key.status, 'active');

    // 2. List keys for tenant-01 and tenant-02
    const listResp = await fetch(`${running.url}/api/tenants/tenant-01/api-keys`);
    assert.equal(listResp.status, 200);
    const listBody = await listResp.json();
    assert.equal(listBody.tenantId, 'tenant-01');
    assert.equal(listBody.keys.length, 1);
    assert.equal(listBody.keys[0].id, createdBody.key.id);
    assert.equal('secret_hash' in listBody.keys[0], false);

    const otherListResp = await fetch(`${running.url}/api/tenants/tenant-02/api-keys`);
    assert.equal(otherListResp.status, 200);
    const otherListBody = await otherListResp.json();
    assert.equal(otherListBody.keys.length, 0);

    // 3. Verify key via JSON body
    const verifyResp = await fetch(`${running.url}/api/api-keys/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ apiKey: createdBody.apiKey }),
    });
    assert.equal(verifyResp.status, 200);
    const verifyBody = await verifyResp.json();
    assert.equal(verifyBody.valid, true);
    assert.equal(verifyBody.tenantId, 'tenant-01');
    assert.deepEqual(verifyBody.scopes, ['paas:deploy', 'paas:read']);

    // 4. Verify key via Authorization: Bearer header
    const bearerResp = await fetch(`${running.url}/api/api-keys/verify`, {
      method: 'POST',
      headers: { authorization: `Bearer ${createdBody.apiKey}` },
    });
    assert.equal(bearerResp.status, 200);

    // 5. Revoke key
    const revokeResp = await fetch(`${running.url}/api/api-keys/${createdBody.key.id}/revoke`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ tenantId: 'tenant-01' }),
    });
    assert.equal(revokeResp.status, 200);
    const revokeBody = await revokeResp.json();
    assert.equal(revokeBody.revoked, true);

    // 6. Verify after revocation returns 401
    const postRevokeVerify = await fetch(`${running.url}/api/api-keys/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ apiKey: createdBody.apiKey }),
    });
    assert.equal(postRevokeVerify.status, 401);
    const postRevokeBody = await postRevokeVerify.json();
    assert.equal(postRevokeBody.valid, false);
    assert.equal(postRevokeBody.reason, 'revoked');
  } finally {
    await running.close();
  }
});
