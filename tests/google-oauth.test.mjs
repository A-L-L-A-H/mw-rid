import test from 'node:test';
import assert from 'node:assert/strict';
import { startRidServer } from '../apps/id/dist/server.js';
import { IdentityDatabase } from '../apps/id/dist/storage/sqlite.js';
import {
  createGoogleOAuthService,
  DEFAULT_GOOGLE_STATE_TTL_MS,
  GoogleOAuthError,
} from '../apps/id/dist/services/google-oauth.js';

test('GoogleOAuthService fails closed in production if configured without stateSecret', () => {
  const prevSecret = process.env.MW_RID_GOOGLE_STATE_SECRET;
  delete process.env.MW_RID_GOOGLE_STATE_SECRET;
  try {
    assert.throws(
      () =>
        createGoogleOAuthService({
          nodeEnv: 'production',
          clientId: 'client-123',
          clientSecret: 'secret-123',
          redirectUri: 'https://id.moonwitness.local/api/auth/google/callback',
          stateSecret: '',
        }),
      /Fail-closed/,
    );
  } finally {
    if (prevSecret !== undefined) {
      process.env.MW_RID_GOOGLE_STATE_SECRET = prevSecret;
    }
  }
});

test('GoogleOAuthService builds authorization URL and verifies HMAC state with expiry', () => {
  const service = createGoogleOAuthService({
    nodeEnv: 'test',
    clientId: 'google-client-id',
    clientSecret: 'google-client-secret',
    redirectUri: 'http://127.0.0.1:4480/api/auth/google/callback',
    stateSecret: 'google-state-secret-01',
    allowedHostedDomain: 'MoonWitness.com',
  });

  assert.equal(service.isConfigured(), true);

  const t0 = 1_700_000_000_000;
  const { url, state, expiresAt } = service.buildAuthorizationUrl({
    nonce: 'nonce-abc',
    loginHint: 'user@moonwitness.com',
    nowMs: t0,
  });

  assert.equal(expiresAt, new Date(t0 + DEFAULT_GOOGLE_STATE_TTL_MS).toISOString());

  const parsed = new URL(url);
  assert.equal(parsed.origin + parsed.pathname, 'https://accounts.google.com/o/oauth2/v2/auth');
  assert.equal(parsed.searchParams.get('client_id'), 'google-client-id');
  assert.equal(parsed.searchParams.get('redirect_uri'), 'http://127.0.0.1:4480/api/auth/google/callback');
  assert.equal(parsed.searchParams.get('response_type'), 'code');
  assert.equal(parsed.searchParams.get('scope'), 'openid email profile');
  assert.equal(parsed.searchParams.get('access_type'), 'offline');
  assert.equal(parsed.searchParams.get('prompt'), 'select_account');
  assert.equal(parsed.searchParams.get('login_hint'), 'user@moonwitness.com');
  assert.equal(parsed.searchParams.get('hd'), 'moonwitness.com');
  assert.equal(parsed.searchParams.get('state'), state);

  assert.deepEqual(service.verifyState(state, t0 + DEFAULT_GOOGLE_STATE_TTL_MS), {
    valid: true,
    nonce: 'nonce-abc',
    exp: t0 + DEFAULT_GOOGLE_STATE_TTL_MS,
  });

  assert.deepEqual(service.verifyState(state, t0 + DEFAULT_GOOGLE_STATE_TTL_MS + 1), {
    valid: false,
    reason: 'expired',
  });

  const parts = state.split('.');
  const tampered = `${parts[0]}.${parts[1]}.AAAA${parts[2].slice(4)}`;
  assert.deepEqual(service.verifyState(tampered, t0 + 1000), {
    valid: false,
    reason: 'invalid_signature',
  });

  assert.deepEqual(service.verifyState('not-a-valid-state', t0 + 1000), {
    valid: false,
    reason: 'invalid_state',
  });
});

test('GoogleOAuthService rejects unverified emails and hosted-domain mismatches, and upserts/links accounts', async () => {
  const db = new IdentityDatabase(':memory:');
  try {
    // Pre-create an account with matching email to test account linking
    const existing = db.createAccount({
      username: 'existing_alice',
      password: 'Password!1234',
      email: 'alice@moonwitness.com',
    });

    let mockProfile = {
      sub: 'google-sub-alice',
      email: 'Alice@MoonWitness.com',
      email_verified: true,
      name: 'Alice',
      hd: 'moonwitness.com',
    };

    const service = createGoogleOAuthService({
      nodeEnv: 'test',
      clientId: 'google-client-id',
      clientSecret: 'google-client-secret',
      redirectUri: 'http://127.0.0.1:4480/api/auth/google/callback',
      stateSecret: 'google-state-secret-02',
      allowedHostedDomain: 'moonwitness.com',
      fetchImpl: async (url, init) => {
        if (String(url).includes('oauth2.googleapis.com/token')) {
          assert.equal(init.method, 'POST');
          return new Response(JSON.stringify({ access_token: 'g_access_01' }), { status: 200 });
        }
        return new Response(JSON.stringify(mockProfile), { status: 200 });
      },
    });

    const t0 = 1_700_000_000_000;
    const { state } = service.buildAuthorizationUrl({ nowMs: t0 });

    // 1. Links existing account by email
    const first = await service.authenticateCallback({
      code: 'auth-code-1',
      state,
      identityDb: db,
      nowMs: t0 + 1000,
    });
    assert.equal(first.account.sub, existing.sub);
    assert.equal(first.created, false);
    assert.equal(first.linked, true);

    // 2. Subsequent login reuses federated link
    const second = await service.authenticateCallback({
      code: 'auth-code-2',
      state,
      identityDb: db,
      nowMs: t0 + 2000,
    });
    assert.equal(second.account.sub, existing.sub);
    assert.equal(second.created, false);
    assert.equal(second.linked, false);

    // 3. Brand new user creates new account
    mockProfile = {
      sub: 'google-sub-bob',
      email: 'bob@moonwitness.com',
      email_verified: true,
      name: 'Bob',
      hd: 'moonwitness.com',
    };
    const third = await service.authenticateCallback({
      code: 'auth-code-3',
      state,
      identityDb: db,
      nowMs: t0 + 3000,
    });
    assert.notEqual(third.account.sub, existing.sub);
    assert.equal(third.account.email, 'bob@moonwitness.com');
    assert.equal(third.account.role, 'member');
    assert.equal(third.created, true);
    assert.equal(third.linked, true);

    // 4. Rejects unverified email
    mockProfile = {
      sub: 'google-sub-unverified',
      email: 'unverified@moonwitness.com',
      email_verified: false,
      hd: 'moonwitness.com',
    };
    await assert.rejects(
      () =>
        service.authenticateCallback({
          code: 'auth-code-4',
          state,
          identityDb: db,
          nowMs: t0 + 4000,
        }),
      (err) => err instanceof GoogleOAuthError && err.code === 'email_not_verified',
    );

    // 5. Rejects wrong hosted domain
    mockProfile = {
      sub: 'google-sub-outsider',
      email: 'outsider@gmail.com',
      email_verified: true,
      hd: 'gmail.com',
    };
    await assert.rejects(
      () =>
        service.authenticateCallback({
          code: 'auth-code-5',
          state,
          identityDb: db,
          nowMs: t0 + 5000,
        }),
      (err) => err instanceof GoogleOAuthError && err.code === 'hosted_domain_forbidden',
    );
  } finally {
    db.close();
  }
});

test('startRidServer returns 503 when Google OAuth is unconfigured and handles full start/callback when configured', async () => {
  const unconfigured = await startRidServer({
    port: 0,
    host: '127.0.0.1',
    dbPath: ':memory:',
    nodeEnv: 'test',
    signingKeyOptions: { nodeEnv: 'test', allowEphemeralKeys: true },
    googleOAuthOptions: {
      clientId: '',
      clientSecret: '',
      redirectUri: '',
    },
  });

  try {
    const startResp = await fetch(`${unconfigured.url}/api/auth/google/start`);
    assert.equal(startResp.status, 503);
    const cbResp = await fetch(`${unconfigured.url}/api/auth/google/callback?code=c&state=s`);
    assert.equal(cbResp.status, 503);
  } finally {
    await unconfigured.close();
  }

  const configured = await startRidServer({
    port: 0,
    host: '127.0.0.1',
    dbPath: ':memory:',
    nodeEnv: 'test',
    signingKeyOptions: { nodeEnv: 'test', allowEphemeralKeys: true },
    googleOAuthOptions: {
      clientId: 'cid-http',
      clientSecret: 'csec-http',
      redirectUri: 'http://127.0.0.1/callback',
      stateSecret: 'http-state-secret',
      fetchImpl: async (url) => {
        if (String(url).includes('oauth2.googleapis.com/token')) {
          return new Response(JSON.stringify({ access_token: 'tok-http' }), { status: 200 });
        }
        return new Response(
          JSON.stringify({
            sub: 'g-http-1',
            email: 'carol@moonwitness.local',
            email_verified: true,
            name: 'Carol',
          }),
          { status: 200 },
        );
      },
    },
  });

  try {
    const startResp = await fetch(`${configured.url}/api/auth/google/start?login_hint=carol@moonwitness.local`);
    assert.equal(startResp.status, 200);
    const startBody = await startResp.json();
    assert.ok(startBody.url.startsWith('https://accounts.google.com/o/oauth2/v2/auth'));
    assert.ok(startBody.state);

    const cbResp = await fetch(
      `${configured.url}/api/auth/google/callback?code=good-code&state=${encodeURIComponent(startBody.state)}`,
    );
    assert.equal(cbResp.status, 200);
    const cbBody = await cbResp.json();
    assert.equal(cbBody.authenticated, true);
    assert.equal(cbBody.created, true);
    assert.equal(cbBody.account.email, 'carol@moonwitness.local');
    assert.ok(cbBody.account.sub.startsWith('rid_'));

    const badStateResp = await fetch(
      `${configured.url}/api/auth/google/callback?code=good-code&state=tampered.state.sig`,
    );
    assert.equal(badStateResp.status, 401);
  } finally {
    await configured.close();
  }
});
