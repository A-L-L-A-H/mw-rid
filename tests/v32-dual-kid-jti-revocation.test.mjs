import test from 'node:test';
import assert from 'node:assert/strict';
import { decodeJwt, decodeProtectedHeader } from 'jose';
import { startRidServer } from '../apps/id/dist/server.js';
import { createSigningKeyManager } from '../apps/id/dist/crypto/keys.js';
import { IdentityDatabase } from '../apps/id/dist/storage/sqlite.js';
import { createJtiRevocationService } from '../apps/id/dist/services/jti-revocation.js';
import {
  checkJtiRevoked,
  clearJwksCache,
  createRevocationSyncClient,
  verifyAccessToken,
} from '../packages/rid-sdk/dist/index.js';

const AUDIENCE = 'urn:moonwitness:api';

async function issueClientCredentialsToken(issuer, clientId, clientSecret) {
  const basicAuth = Buffer.from(`${clientId}:${clientSecret}`).toString('base64');
  const response = await fetch(`${issuer}/token`, {
    method: 'POST',
    headers: {
      authorization: `Basic ${basicAuth}`,
      'content-type': 'application/x-www-form-urlencoded',
    },
    body: new URLSearchParams({
      grant_type: 'client_credentials',
      scope: 'api:read',
      resource: AUDIENCE,
    }),
  });
  assert.equal(response.status, 200);
  const body = await response.json();
  assert.ok(typeof body.access_token === 'string' && body.access_token.length > 0);
  return body.access_token;
}

test('SigningKeyManager supports dual-kid overlapping RS256 rotation and grace expiration without leaking private fields', async () => {
  const t0 = 1_700_000_000_000;
  const manager = await createSigningKeyManager({
    nodeEnv: 'test',
    allowEphemeralKeys: true,
    graceWindowSeconds: 120,
    nowMs: t0,
  });

  const initialKid = manager.getActiveKid();
  assert.ok(initialKid.length > 0);
  assert.equal(manager.getPreviousKid(t0), null);
  assert.equal(manager.getPublicJwks(t0).keys.length, 1);

  const rotated = await manager.rotateKey({
    graceWindowSeconds: 120,
    nowMs: t0 + 10_000,
  });

  assert.notEqual(rotated.activeKid, initialKid);
  assert.equal(rotated.previousKid, initialKid);
  assert.deepEqual(rotated.kids, [rotated.activeKid, initialKid]);

  const duringGraceJwks = manager.getPublicJwks(t0 + 60_000);
  assert.equal(duringGraceJwks.keys.length, 2);
  assert.equal(duringGraceJwks.keys[0].kid, rotated.activeKid);
  assert.equal(duringGraceJwks.keys[1].kid, initialKid);

  for (const jwk of duringGraceJwks.keys) {
    assert.equal(jwk.kty, 'RSA');
    assert.equal(jwk.alg, 'RS256');
    assert.equal(jwk.use, 'sig');
    assert.equal(jwk.d, undefined);
    assert.equal(jwk.p, undefined);
    assert.equal(jwk.q, undefined);
    assert.equal(jwk.dp, undefined);
    assert.equal(jwk.dq, undefined);
    assert.equal(jwk.qi, undefined);
  }

  // After grace window expires (t0 + 10_000 + 120_000 + 1), previous key is pruned
  const afterGraceJwks = manager.getPublicJwks(t0 + 130_001);
  assert.equal(afterGraceJwks.keys.length, 1);
  assert.equal(afterGraceJwks.keys[0].kid, rotated.activeKid);
  assert.equal(manager.getPreviousKid(t0 + 130_001), null);
});

test('JtiRevocationService persists revocations in SQLite, is idempotent, supports cursor delta sync, and prunes expired entries', () => {
  const db = new IdentityDatabase(':memory:');
  try {
    const service = createJtiRevocationService(db);
    const nowEpoch = 1_800_000_000;

    const first = service.revoke({
      jti: 'jti-alpha-001',
      kid: 'kid-v1',
      sub: 'sp_worker_1',
      reason: 'compromised_worker',
      expiresAt: nowEpoch + 600,
    });
    assert.equal(first.created, true);
    assert.equal(first.revocation.seq, 1);
    assert.equal(first.revocation.jti, 'jti-alpha-001');
    assert.equal(first.revocation.kid, 'kid-v1');

    // Idempotent duplicate revoke returns existing record without creating a duplicate
    const duplicate = service.revoke({
      jti: 'jti-alpha-001',
      reason: 'retry_call',
    });
    assert.equal(duplicate.created, false);
    assert.equal(duplicate.revocation.seq, 1);

    const second = service.revoke({
      jti: 'jti-beta-002',
      kid: 'kid-v2',
      sub: 'sp_worker_2',
      reason: 'rotation_audit',
      expiresAt: nowEpoch - 10,
    });
    assert.equal(second.created, true);
    assert.equal(second.revocation.seq, 2);

    assert.equal(service.isRevoked('jti-alpha-001'), true);
    assert.equal(service.isRevoked('jti-beta-002'), true);
    assert.equal(service.isRevoked('jti-unknown'), false);

    // Sync active (non-expired) vs includeExpired
    const activeSync = service.sync({ nowEpochSeconds: nowEpoch });
    assert.equal(activeSync.revocations.length, 1);
    assert.equal(activeSync.revocations[0].jti, 'jti-alpha-001');
    assert.equal(activeSync.cursor, 1);

    const fullSync = service.sync({ includeExpired: true, nowEpochSeconds: nowEpoch });
    assert.equal(fullSync.revocations.length, 2);
    assert.equal(fullSync.cursor, 2);

    const deltaSync = service.sync({
      since: 1,
      includeExpired: true,
      nowEpochSeconds: nowEpoch,
    });
    assert.equal(deltaSync.revocations.length, 1);
    assert.equal(deltaSync.revocations[0].jti, 'jti-beta-002');
    assert.equal(deltaSync.cursor, 2);

    // Prune expired
    const prunedCount = service.pruneExpired(nowEpoch);
    assert.equal(prunedCount, 1);
    assert.equal(service.isRevoked('jti-beta-002'), false);
    assert.equal(service.isRevoked('jti-alpha-001'), true);
  } finally {
    db.close();
  }
});

test('End-to-end V32: dual-kid overlapping JWKS key rotation + SQLite jti revocation sync/check across active and previous kid', async () => {
  clearJwksCache();
  const running = await startRidServer({
    port: 0,
    host: '127.0.0.1',
    dbPath: ':memory:',
    nodeEnv: 'test',
    defaultAudience: AUDIENCE,
    signingKeyOptions: {
      nodeEnv: 'test',
      allowEphemeralKeys: true,
      graceWindowSeconds: 300,
    },
  });

  try {
    const issuer = running.url;
    const jwksUri = `${issuer}/jwks`;
    const revocationsUri = `${issuer}/api/revocations`;
    const revocationCheckUri = `${issuer}/api/revocations/check`;

    // 1. Register service principal
    const spResp = await fetch(`${issuer}/api/service-principals`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        name: 'v32-rotation-service',
        scopes: ['api:read', 'api:write'],
      }),
    });
    assert.equal(spResp.status, 201);
    const sp = await spResp.json();

    // 2. Inspect initial /jwks and /api/keys (single active kid_1)
    const keysBeforeResp = await fetch(`${issuer}/api/keys`);
    assert.equal(keysBeforeResp.status, 200);
    const keysBefore = await keysBeforeResp.json();
    const kid1 = keysBefore.activeKid;
    assert.ok(typeof kid1 === 'string' && kid1.length > 0);
    assert.equal(keysBefore.previousKid, null);
    assert.deepEqual(keysBefore.kids, [kid1]);

    // 3. Issue Token A1 and Token A2 signed with kid_1
    const tokenA1 = await issueClientCredentialsToken(issuer, sp.client_id, sp.client_secret);
    const tokenA2 = await issueClientCredentialsToken(issuer, sp.client_id, sp.client_secret);
    assert.equal(decodeProtectedHeader(tokenA1).kid, kid1);
    assert.equal(decodeProtectedHeader(tokenA2).kid, kid1);
    const jtiA1 = decodeJwt(tokenA1).jti;
    const jtiA2 = decodeJwt(tokenA2).jti;
    assert.ok(typeof jtiA1 === 'string' && typeof jtiA2 === 'string');
    assert.notEqual(jtiA1, jtiA2);

    // 4. Rotate RS256 signing key via HTTP endpoint with 300s grace overlap
    const rotateResp = await fetch(`${issuer}/api/keys/rotate`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ graceWindowSeconds: 300 }),
    });
    assert.equal(rotateResp.status, 200);
    const rotateBody = await rotateResp.json();
    assert.equal(rotateBody.rotated, true);
    const kid2 = rotateBody.activeKid;
    assert.notEqual(kid2, kid1);
    assert.equal(rotateBody.previousKid, kid1);
    assert.deepEqual(rotateBody.kids, [kid2, kid1]);

    // 5. Verify /jwks now publishes both kid_2 (active) and kid_1 (previous grace key)
    const jwksOverlapResp = await fetch(jwksUri);
    assert.equal(jwksOverlapResp.status, 200);
    const jwksOverlap = await jwksOverlapResp.json();
    assert.equal(jwksOverlap.keys.length, 2);
    assert.deepEqual(
      jwksOverlap.keys.map((k) => k.kid),
      [kid2, kid1],
    );

    // 6. Issue Token B1 and Token B2 after rotation -> signed with new active kid_2
    const tokenB1 = await issueClientCredentialsToken(issuer, sp.client_id, sp.client_secret);
    const tokenB2 = await issueClientCredentialsToken(issuer, sp.client_id, sp.client_secret);
    assert.equal(decodeProtectedHeader(tokenB1).kid, kid2);
    assert.equal(decodeProtectedHeader(tokenB2).kid, kid2);
    const jtiB1 = decodeJwt(tokenB1).jti;
    const jtiB2 = decodeJwt(tokenB2).jti;
    assert.ok(typeof jtiB1 === 'string' && typeof jtiB2 === 'string');

    // 7. During overlap window, tokens signed with BOTH kid_1 and kid_2 verify via rid-sdk
    const verifiedA1 = await verifyAccessToken({
      token: tokenA1,
      issuer,
      audience: AUDIENCE,
      jwksUri,
      forceJwksRefresh: true,
    });
    assert.equal(verifiedA1.header.kid, kid1);
    assert.equal(verifiedA1.payload.jti, jtiA1);

    const verifiedB1 = await verifyAccessToken({
      token: tokenB1,
      issuer,
      audience: AUDIENCE,
      jwksUri,
    });
    assert.equal(verifiedB1.header.kid, kid2);
    assert.equal(verifiedB1.payload.jti, jtiB1);

    // 8. Revoke Token A1 (previous kid_1) by raw JWT token and Token B1 (active kid_2) by jti
    const revokeA1Resp = await fetch(revocationsUri, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        token: tokenA1,
        reason: 'revoke_previous_kid_token',
      }),
    });
    assert.equal(revokeA1Resp.status, 201);
    const revokeA1Body = await revokeA1Resp.json();
    assert.equal(revokeA1Body.revoked, true);
    assert.equal(revokeA1Body.created, true);
    assert.equal(revokeA1Body.revocation.jti, jtiA1);
    assert.equal(revokeA1Body.revocation.kid, kid1);

    const revokeB1Resp = await fetch(revocationsUri, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jti: jtiB1,
        kid: kid2,
        sub: sp.client_id,
        reason: 'revoke_active_kid_token',
      }),
    });
    assert.equal(revokeB1Resp.status, 201);
    const revokeB1Body = await revokeB1Resp.json();
    assert.equal(revokeB1Body.revoked, true);
    assert.equal(revokeB1Body.revocation.jti, jtiB1);
    assert.equal(revokeB1Body.revocation.kid, kid2);

    // 9. Verify revocation check endpoint & SDK checkJtiRevoked helper across both kids
    const checkA1 = await checkJtiRevoked({ jti: jtiA1, revocationCheckUri });
    assert.equal(checkA1.revoked, true);
    assert.equal(checkA1.revocation.kid, kid1);

    const checkB1 = await checkJtiRevoked({ jti: jtiB1, revocationCheckUri });
    assert.equal(checkB1.revoked, true);
    assert.equal(checkB1.revocation.kid, kid2);

    const checkA2GetResp = await fetch(
      `${revocationCheckUri}?jti=${encodeURIComponent(jtiA2)}`,
    );
    assert.equal(checkA2GetResp.status, 200);
    const checkA2GetBody = await checkA2GetResp.json();
    assert.equal(checkA2GetBody.revoked, false);

    // 10. Sync revocations into RevocationSyncClient and reject revoked JTIs across active/previous kid
    const syncClient = createRevocationSyncClient({ revocationsUri });
    const syncResult1 = await syncClient.sync();
    assert.equal(syncResult1.added, 2);
    assert.equal(syncResult1.total, 2);
    assert.equal(syncResult1.cursor, 2);
    assert.equal(syncClient.isRevoked(jtiA1), true);
    assert.equal(syncClient.isRevoked(jtiB1), true);
    assert.equal(syncClient.isRevoked(jtiA2), false);
    assert.equal(syncClient.isRevoked(jtiB2), false);

    // Delta sync with no new revocations adds 0
    const syncResult2 = await syncClient.sync();
    assert.equal(syncResult2.added, 0);
    assert.equal(syncResult2.cursor, 2);

    // verifyAccessToken with revocationSync rejects revoked tokens on both kid_1 and kid_2
    await assert.rejects(
      () =>
        verifyAccessToken({
          token: tokenA1,
          issuer,
          audience: AUDIENCE,
          jwksUri,
          revocationSync: syncClient,
        }),
      /Access token jti is revoked/,
    );

    await assert.rejects(
      () =>
        verifyAccessToken({
          token: tokenB1,
          issuer,
          audience: AUDIENCE,
          jwksUri,
          revocationSync: syncClient,
        }),
      /Access token jti is revoked/,
    );

    // verifyAccessToken with revocationCheckUri also rejects revoked tokens
    await assert.rejects(
      () =>
        verifyAccessToken({
          token: tokenA1,
          issuer,
          audience: AUDIENCE,
          jwksUri,
          revocationCheckUri,
        }),
      /Access token jti is revoked/,
    );

    // Unrevoked tokens on BOTH kid_1 (Token A2) and kid_2 (Token B2) still pass!
    const verifiedA2 = await verifyAccessToken({
      token: tokenA2,
      issuer,
      audience: AUDIENCE,
      jwksUri,
      revocationSync: syncClient,
      revocationCheckUri,
    });
    assert.equal(verifiedA2.header.kid, kid1);

    const verifiedB2 = await verifyAccessToken({
      token: tokenB2,
      issuer,
      audience: AUDIENCE,
      jwksUri,
      revocationSync: syncClient,
      revocationCheckUri,
    });
    assert.equal(verifiedB2.header.kid, kid2);

    // 11. Expire the previous grace key (kid_1) and verify /jwks drops kid_1 and rejects Token A2 while Token B2 still passes
    const expireResp = await fetch(`${issuer}/api/keys/expire-grace`, {
      method: 'POST',
    });
    assert.equal(expireResp.status, 200);
    const expireBody = await expireResp.json();
    assert.equal(expireBody.expired, true);
    assert.equal(expireBody.activeKid, kid2);
    assert.equal(expireBody.previousKid, null);
    assert.deepEqual(expireBody.kids, [kid2]);

    await assert.rejects(
      () =>
        verifyAccessToken({
          token: tokenA2,
          issuer,
          audience: AUDIENCE,
          jwksUri,
          forceJwksRefresh: true,
        }),
      /key|kid|signing/i,
    );

    const verifiedB2AfterGrace = await verifyAccessToken({
      token: tokenB2,
      issuer,
      audience: AUDIENCE,
      jwksUri,
      revocationSync: syncClient,
    });
    assert.equal(verifiedB2AfterGrace.header.kid, kid2);
  } finally {
    await running.close();
  }
});
