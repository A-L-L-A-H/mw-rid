import test from 'node:test';
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import {
  SignJWT,
  calculateJwkThumbprint,
  exportJWK,
  generateKeyPair,
} from 'jose';
import { startRidServer } from '../apps/id/dist/server.js';
import {
  buildAuthorizationUrl,
  createPkcePair,
  verifyAccessToken,
} from '../packages/rid-sdk/dist/index.js';

const ISSUER = 'https://issuer.moonwitness.test';
const AUDIENCE = 'urn:moonwitness:api';
const WRONG_ISSUER = 'https://evil.moonwitness.test';
const WRONG_AUDIENCE = 'urn:moonwitness:wrong-api';

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

function base64UrlJson(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function buildAlgNoneToken(payload) {
  return `${base64UrlJson({ alg: 'none', typ: 'at+jwt' })}.${base64UrlJson(payload)}.`;
}

async function startJwksServer(keys) {
  const server = createServer((request, response) => {
    if (request.url === '/jwks') {
      response.statusCode = 200;
      response.setHeader('content-type', 'application/json');
      response.end(JSON.stringify({ keys }));
      return;
    }
    response.statusCode = 404;
    response.end();
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  return {
    url: `http://127.0.0.1:${address.port}`,
    close: () => new Promise((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    }),
  };
}

async function createSigningFixture() {
  const { privateKey } = await generateKeyPair('RS256', { extractable: true });
  const privateJwk = await exportJWK(privateKey);
  const kid = await calculateJwkThumbprint(privateJwk, 'sha256');
  const publicJwk = await exportJWK(privateKey);
  delete publicJwk.d;
  delete publicJwk.p;
  delete publicJwk.q;
  delete publicJwk.dp;
  delete publicJwk.dq;
  delete publicJwk.qi;
  return {
    privateKey,
    publicJwk: { ...publicJwk, alg: 'RS256', use: 'sig', kid },
    kid,
  };
}

async function issueAccessToken(privateKey, kid, overrides = {}) {
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    sub: 'rid_negative_contract',
    scope: 'api:read',
    client_id: 'mw-board',
    iss: ISSUER,
    aud: AUDIENCE,
    iat: now,
    exp: now + 900,
    ...overrides,
  };
  return new SignJWT(payload)
    .setProtectedHeader({ alg: 'RS256', typ: 'at+jwt', kid })
    .sign(privateKey);
}

async function obtainAuthorizationCode(running) {
  const discoveryResponse = await fetch(`${running.url}/.well-known/openid-configuration`);
  assert.equal(discoveryResponse.status, 200);
  const discovery = await discoveryResponse.json();

  const bootstrapResponse = await fetch(`${running.url}/api/bootstrap`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      setupSecret: running.bootstrapSecret,
      username: 'negative-contract-owner',
      password: 'StrongPassword!123',
      email: 'negative-contract@moonwitness.local',
    }),
  });
  assert.equal(bootstrapResponse.status, 201);

  const pkce = createPkcePair();
  const state = 'negative-contract-state';
  const redirectUri = 'http://127.0.0.1:3000/auth/callback';
  const authorizationUrl = buildAuthorizationUrl({
    authorizationEndpoint: discovery.authorization_endpoint,
    clientId: 'mw-board',
    redirectUri,
    scope: 'openid profile email',
    state,
    codeChallenge: pkce.codeChallenge,
    resource: AUDIENCE,
  });

  let cookieJar = new Map();
  const authResponse = await fetch(authorizationUrl, { redirect: 'manual' });
  assert.equal(authResponse.status, 303);
  cookieJar = mergeCookies(cookieJar, authResponse.headers.getSetCookie());
  const interactionLocation = authResponse.headers.get('location');
  assert.ok(interactionLocation && interactionLocation.startsWith('/interaction/'));

  const loginResponse = await fetch(`${running.url}${interactionLocation}/login`, {
    method: 'POST',
    redirect: 'manual',
    headers: {
      'content-type': 'application/json',
      cookie: formatCookieHeader(cookieJar),
    },
    body: JSON.stringify({
      username: 'negative-contract-owner',
      password: 'StrongPassword!123',
    }),
  });
  assert.equal(loginResponse.status, 303);
  cookieJar = mergeCookies(cookieJar, loginResponse.headers.getSetCookie());
  const resumeLocation = loginResponse.headers.get('location');
  assert.ok(resumeLocation);

  const resumeUrl = resumeLocation.startsWith('http')
    ? resumeLocation
    : `${running.url}${resumeLocation}`;
  const callbackResponse = await fetch(resumeUrl, {
    redirect: 'manual',
    headers: { cookie: formatCookieHeader(cookieJar) },
  });
  assert.equal(callbackResponse.status, 303);
  const callbackUrl = new URL(callbackResponse.headers.get('location'));
  assert.equal(callbackUrl.searchParams.get('state'), state);
  const code = callbackUrl.searchParams.get('code');
  assert.ok(code);

  return { code, redirectUri, codeVerifier: pkce.codeVerifier, tokenEndpoint: discovery.token_endpoint };
}

async function exchangeAuthorizationCode(tokenEndpoint, grant) {
  return fetch(tokenEndpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      client_id: 'mw-board',
      code: grant.code,
      redirect_uri: grant.redirectUri,
      code_verifier: grant.codeVerifier,
      resource: AUDIENCE,
    }),
  });
}

test('verifyAccessToken rejects alg:none, wrong issuer, wrong audience, expired exp, and unknown kid through real JWKS retrieval', async () => {
  const fixture = await createSigningFixture();
  const jwksServer = await startJwksServer([fixture.publicJwk]);
  const jwksUri = `${jwksServer.url}/jwks`;
  const verifyOptions = {
    issuer: ISSUER,
    audience: AUDIENCE,
    jwksUri,
  };

  try {
    const now = Math.floor(Date.now() / 1000);
    const cases = [
      {
        name: 'alg:none',
        token: buildAlgNoneToken({
          sub: 'alg-none-attacker',
          iss: ISSUER,
          aud: AUDIENCE,
          iat: now,
          exp: now + 900,
        }),
        reason: /algorithm|signature|JWS/i,
      },
      {
        name: 'wrong-iss',
        token: await issueAccessToken(fixture.privateKey, fixture.kid, { iss: WRONG_ISSUER }),
        reason: /unexpected "iss" claim value/i,
      },
      {
        name: 'wrong-aud',
        token: await issueAccessToken(fixture.privateKey, fixture.kid, { aud: WRONG_AUDIENCE }),
        reason: /unexpected "aud" claim value/i,
      },
      {
        name: 'expired-exp',
        token: await issueAccessToken(fixture.privateKey, fixture.kid, {
          iat: now - 3600,
          exp: now - 1800,
        }),
        reason: /exp|expired/i,
      },
      {
        name: 'unknown-kid',
        token: await new SignJWT({
          sub: 'unknown-kid-attacker',
          iss: ISSUER,
          aud: AUDIENCE,
          iat: now,
          exp: now + 900,
        })
          .setProtectedHeader({ alg: 'RS256', typ: 'at+jwt', kid: 'kid-not-in-jwks' })
          .sign(fixture.privateKey),
        reason: /key|kid|signing/i,
      },
    ];

    assert.equal(cases.length, 5);
    for (const contractCase of cases) {
      await assert.rejects(
        () => verifyAccessToken({ ...verifyOptions, token: contractCase.token }),
        contractCase.reason,
        contractCase.name,
      );
    }

    const validToken = await issueAccessToken(fixture.privateKey, fixture.kid);
    const verified = await verifyAccessToken({ ...verifyOptions, token: validToken });
    assert.equal(verified.header.kid, fixture.kid);
    assert.equal(verified.payload.iss, ISSUER);
  } finally {
    await jwksServer.close();
  }
});

test('token endpoint rejects PKCE verifier failure while the correct verifier succeeds', async () => {
  const running = await startRidServer({
    port: 0,
    host: '127.0.0.1',
    dbPath: ':memory:',
    defaultAudience: AUDIENCE,
    signingKeyOptions: { nodeEnv: 'test', allowEphemeralKeys: true },
  });

  try {
    const grant = await obtainAuthorizationCode(running);

    const invalidVerifierResponse = await fetch(grant.tokenEndpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        client_id: 'mw-board',
        code: grant.code,
        redirect_uri: grant.redirectUri,
        code_verifier: `${grant.codeVerifier}invalid`,
        resource: AUDIENCE,
      }),
    });
    assert.equal(invalidVerifierResponse.status, 400);
    const invalidBody = await invalidVerifierResponse.json();
    assert.equal(invalidBody.error, 'invalid_grant');

    const validResponse = await exchangeAuthorizationCode(grant.tokenEndpoint, grant);
    assert.equal(validResponse.status, 200);
    const validBody = await validResponse.json();
    assert.ok(validBody.access_token);

    const verified = await verifyAccessToken({
      token: validBody.access_token,
      issuer: running.url,
      audience: AUDIENCE,
      jwksUri: `${running.url}/jwks`,
    });
    assert.equal(verified.payload.sub.startsWith('rid_'), true);
  } finally {
    await running.close();
  }
});
