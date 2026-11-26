import test from 'node:test';
import assert from 'node:assert/strict';
import { startRidServer } from '../apps/id/dist/server.js';
import { loadSigningKeys } from '../apps/id/dist/crypto/keys.js';
import {
  buildAuthorizationUrl,
  createPkcePair,
  verifyAccessToken,
} from '../packages/rid-sdk/dist/index.js';

function mergeCookies(existing, setCookieHeaders) {
  const jar = new Map(existing);
  for (const headerValue of setCookieHeaders) {
    const firstPart = headerValue.split(';')[0];
    const eqIndex = firstPart.indexOf('=');
    if (eqIndex > 0) {
      const cookieName = firstPart.slice(0, eqIndex).trim();
      const cookieValue = firstPart.slice(eqIndex + 1).trim();
      if (cookieValue === '') {
        jar.delete(cookieName);
      } else {
        jar.set(cookieName, cookieValue);
      }
    }
  }
  return jar;
}

function formatCookieHeader(jar) {
  return Array.from(jar.entries())
    .map(([name, value]) => `${name}=${value}`)
    .join('; ');
}

test('loadSigningKeys fails closed in production without PEM key', async () => {
  await assert.rejects(
    () => loadSigningKeys({ nodeEnv: 'production', signingKeyPem: '', signingKeyPath: '' }),
    /Fail-closed/,
  );
});

test('mw-rid full OIDC, PKCE S256, bootstrap, service principal, SDK verification, and outbox flow', async () => {
  const audience = 'urn:moonwitness:api';
  const running = await startRidServer({
    port: 0,
    host: '127.0.0.1',
    dbPath: ':memory:',
    defaultAudience: audience,
    signingKeyOptions: { nodeEnv: 'test', allowEphemeralKeys: true },
  });

  try {
    const issuer = running.url;
    const jwksUri = `${issuer}/jwks`;

    // 1. OIDC Discovery & JWKS (kid present, zero private key params)
    const discoveryResp = await fetch(`${issuer}/.well-known/openid-configuration`);
    assert.equal(discoveryResp.status, 200);
    const discovery = await discoveryResp.json();
    assert.equal(discovery.issuer, issuer);
    assert.ok(discovery.authorization_endpoint.endsWith('/auth'));
    assert.ok(discovery.token_endpoint.endsWith('/token'));
    assert.ok(discovery.jwks_uri.endsWith('/jwks'));

    const jwksResp = await fetch(jwksUri);
    assert.equal(jwksResp.status, 200);
    const jwksBody = await jwksResp.json();
    assert.ok(Array.isArray(jwksBody.keys) && jwksBody.keys.length >= 1);
    for (const jwk of jwksBody.keys) {
      assert.ok(typeof jwk.kid === 'string' && jwk.kid.length > 0);
      assert.equal(jwk.d, undefined);
      assert.equal(jwk.p, undefined);
      assert.equal(jwk.q, undefined);
      assert.equal(jwk.dp, undefined);
      assert.equal(jwk.dq, undefined);
      assert.equal(jwk.qi, undefined);
    }

    // 2. One-time atomic bootstrap (second call MUST fail)
    const bootstrapFirst = await fetch(`${issuer}/api/bootstrap`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        setupSecret: running.bootstrapSecret,
        username: 'founder',
        password: 'StrongPassword!123',
        email: 'founder@moonwitness.local',
      }),
    });
    assert.equal(bootstrapFirst.status, 201);
    const owner = await bootstrapFirst.json();
    assert.ok(owner.sub.startsWith('rid_'));
    assert.equal(owner.role, 'platform_owner');

    const bootstrapSecond = await fetch(`${issuer}/api/bootstrap`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        setupSecret: running.bootstrapSecret,
        username: 'founder2',
        password: 'StrongPassword!456',
      }),
    });
    assert.equal(bootstrapSecond.status, 409);

    // 3. Auth Code + PKCE S256 full exchange + rid-sdk verification
    const pkce = createPkcePair();
    const state = 'state-pkce-test-001';
    const redirectUri = 'http://127.0.0.1:3000/auth/callback';
    const authUrl = buildAuthorizationUrl({
      authorizationEndpoint: discovery.authorization_endpoint,
      clientId: 'mw-board',
      redirectUri,
      scope: 'openid profile email',
      state,
      codeChallenge: pkce.codeChallenge,
      resource: audience,
    });

    let cookieJar = new Map();

    // Step 3a: GET /auth -> redirects to /interaction/:uid
    const authResp = await fetch(authUrl, { redirect: 'manual' });
    assert.equal(authResp.status, 303);
    cookieJar = mergeCookies(cookieJar, authResp.headers.getSetCookie());
    const interactionLocation = authResp.headers.get('location');
    assert.ok(interactionLocation && interactionLocation.startsWith('/interaction/'));

    // Step 3b: POST /interaction/:uid/login -> redirects back to /auth/:uid
    const loginResp = await fetch(`${issuer}${interactionLocation}/login`, {
      method: 'POST',
      redirect: 'manual',
      headers: {
        'content-type': 'application/json',
        cookie: formatCookieHeader(cookieJar),
      },
      body: JSON.stringify({
        username: 'founder',
        password: 'StrongPassword!123',
      }),
    });
    assert.equal(loginResp.status, 303);
    cookieJar = mergeCookies(cookieJar, loginResp.headers.getSetCookie());
    const resumeLocation = loginResp.headers.get('location');
    assert.ok(resumeLocation);

    // Step 3c: GET /auth/:uid -> redirects to redirectUri with ?code=...&state=...
    const resumeUrl = resumeLocation.startsWith('http')
      ? resumeLocation
      : `${issuer}${resumeLocation}`;
    const callbackResp = await fetch(resumeUrl, {
      redirect: 'manual',
      headers: { cookie: formatCookieHeader(cookieJar) },
    });
    assert.equal(callbackResp.status, 303);
    const callbackLocation = callbackResp.headers.get('location');
    assert.ok(callbackLocation && callbackLocation.startsWith(redirectUri));

    const callbackUrl = new URL(callbackLocation);
    assert.equal(callbackUrl.searchParams.get('state'), state);
    const authCode = callbackUrl.searchParams.get('code');
    assert.ok(authCode);

    // Step 3d: POST /token -> exchange code + code_verifier
    const tokenResp = await fetch(discovery.token_endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: 'mw-board',
        code: authCode,
        redirect_uri: redirectUri,
        code_verifier: pkce.codeVerifier,
        resource: audience,
      }),
    });
    assert.equal(tokenResp.status, 200);
    const tokenPayload = await tokenResp.json();
    assert.ok(tokenPayload.access_token);
    assert.ok(tokenPayload.id_token);

    // Verify valid access token via @moonwitness/rid-sdk
    const verified = await verifyAccessToken({
      token: tokenPayload.access_token,
      issuer,
      audience,
      jwksUri,
    });
    assert.equal(verified.payload.sub, owner.sub);
    assert.equal(verified.header.alg, 'RS256');

    // Reject wrong audience
    await assert.rejects(() =>
      verifyAccessToken({
        token: tokenPayload.access_token,
        issuer,
        audience: 'urn:moonwitness:wrong-api',
        jwksUri,
      }),
    );

    // Reject wrong issuer
    await assert.rejects(() =>
      verifyAccessToken({
        token: tokenPayload.access_token,
        issuer: 'http://127.0.0.1:9999',
        audience,
        jwksUri,
      }),
    );

    // Reject OIDC ID token
    await assert.rejects(() =>
      verifyAccessToken({
        token: tokenPayload.id_token,
        issuer,
        audience: 'mw-board',
        jwksUri,
      }),
    );

    // 4. Client Credentials machine token + identity_outbox
    const spResp = await fetch(`${issuer}/api/service-principals`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        name: 'mw-api-worker',
        scopes: ['api:read', 'api:write'],
      }),
    });
    assert.equal(spResp.status, 201);
    const spBody = await spResp.json();
    assert.ok(spBody.client_id.startsWith('sp_'));
    assert.ok(spBody.client_secret.startsWith('spsec_'));

    const basicAuth = Buffer.from(`${spBody.client_id}:${spBody.client_secret}`).toString('base64');
    const ccResp = await fetch(discovery.token_endpoint, {
      method: 'POST',
      headers: {
        authorization: `Basic ${basicAuth}`,
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        grant_type: 'client_credentials',
        scope: 'api:read',
        resource: audience,
      }),
    });
    assert.equal(ccResp.status, 200);
    const ccToken = await ccResp.json();
    assert.ok(ccToken.access_token);

    const verifiedMachine = await verifyAccessToken({
      token: ccToken.access_token,
      issuer,
      audience,
      jwksUri,
    });
    assert.equal(verifiedMachine.payload.sub, spBody.client_id);

    // Verify identity_outbox events and ack
    const outboxResp = await fetch(`${issuer}/api/outbox`);
    assert.equal(outboxResp.status, 200);
    const outboxBody = await outboxResp.json();
    assert.ok(outboxBody.events.length >= 2);
    assert.ok(outboxBody.events.some((evt) => evt.event_type === 'account.created' && evt.subject === owner.sub));
    assert.ok(outboxBody.events.some((evt) => evt.event_type === 'account.created' && evt.subject === spBody.client_id));

    const firstEventId = outboxBody.events[0].id;
    const ackResp = await fetch(`${issuer}/api/outbox/${firstEventId}/ack`, { method: 'POST' });
    assert.equal(ackResp.status, 200);

    const outboxAfterAckResp = await fetch(`${issuer}/api/outbox`);
    const outboxAfterAck = await outboxAfterAckResp.json();
    assert.equal(outboxAfterAck.events.some((evt) => evt.id === firstEventId), false);
  } finally {
    await running.close();
  }
});
