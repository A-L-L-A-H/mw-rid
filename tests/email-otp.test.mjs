import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import { startRidServer } from '../apps/id/dist/server.js';
import { verifyPassword } from '../apps/id/dist/crypto/passwords.js';
import { createEmailOtpService, OTP_TTL_MS } from '../apps/id/dist/services/email-otp.js';

test('EmailOtpService fails closed in production without secret', () => {
  const prevSecret = process.env.MW_RID_OTP_SECRET;
  delete process.env.MW_RID_OTP_SECRET;
  try {
    assert.throws(
      () => createEmailOtpService({ nodeEnv: 'production', secret: '' }),
      /Fail-closed/,
    );
  } finally {
    if (prevSecret !== undefined) {
      process.env.MW_RID_OTP_SECRET = prevSecret;
    }
  }
});

test('EmailOtpService console fallback logs structured entry and verifies within 5-min TTL', async () => {
  const logs = [];
  const service = createEmailOtpService({
    nodeEnv: 'test',
    secret: 'test-otp-secret-01',
    resendApiKey: '',
    logger: (entry) => logs.push(entry),
  });

  const t0 = 1_700_000_000_000;
  const sent = await service.sendOtp({
    email: '  Alice@MoonWitness.Local ',
    purpose: 'login_otp',
    nowMs: t0,
  });

  assert.equal(sent.delivery, 'console');
  assert.match(sent.previewCode, /^\d{6}$/);
  assert.equal(sent.expiresAt, new Date(t0 + OTP_TTL_MS).toISOString());
  assert.equal(logs.length, 1);
  assert.equal(logs[0].event, 'email_otp.console_fallback');
  assert.equal(logs[0].email, 'alice@moonwitness.local');
  assert.equal(logs[0].purpose, 'login_otp');
  assert.equal(logs[0].code, sent.previewCode);

  // Valid exactly at 5-min boundary
  const verified = service.verifyOtp({
    email: 'alice@moonwitness.local',
    code: sent.previewCode,
    token: sent.token,
    purpose: 'login_otp',
    nowMs: t0 + OTP_TTL_MS,
  });
  assert.deepEqual(verified, {
    valid: true,
    email: 'alice@moonwitness.local',
    purpose: 'login_otp',
  });

  // Single-use replay MUST be rejected
  const replay = service.verifyOtp({
    email: 'alice@moonwitness.local',
    code: sent.previewCode,
    token: sent.token,
    purpose: 'login_otp',
    nowMs: t0 + 1000,
  });
  assert.deepEqual(replay, { valid: false, reason: 'already_used' });
});

test('EmailOtpService rejects expired, tampered, wrong code, wrong email, and wrong purpose', async () => {
  const service = createEmailOtpService({
    nodeEnv: 'test',
    secret: 'test-otp-secret-02',
    resendApiKey: '',
    logger: () => {},
  });

  const t0 = 1_700_000_000_000;
  const sent = await service.sendOtp({
    email: 'bob@moonwitness.local',
    purpose: 'email_verify',
    nowMs: t0,
  });

  // Expired (> 5 min)
  assert.deepEqual(
    service.verifyOtp({
      email: 'bob@moonwitness.local',
      code: sent.previewCode,
      token: sent.token,
      purpose: 'email_verify',
      nowMs: t0 + OTP_TTL_MS + 1,
    }),
    { valid: false, reason: 'expired' },
  );

  // Tampered signature
  const parts = sent.token.split('.');
  const tamperedSigToken = `${parts[0]}.${parts[1]}.AAAA${parts[2].slice(4)}`;
  assert.deepEqual(
    service.verifyOtp({
      email: 'bob@moonwitness.local',
      code: sent.previewCode,
      token: tamperedSigToken,
      purpose: 'email_verify',
      nowMs: t0 + 1000,
    }),
    { valid: false, reason: 'invalid_signature' },
  );

  // Wrong email
  assert.deepEqual(
    service.verifyOtp({
      email: 'eve@moonwitness.local',
      code: sent.previewCode,
      token: sent.token,
      purpose: 'email_verify',
      nowMs: t0 + 1000,
    }),
    { valid: false, reason: 'email_mismatch' },
  );

  // Wrong purpose
  assert.deepEqual(
    service.verifyOtp({
      email: 'bob@moonwitness.local',
      code: sent.previewCode,
      token: sent.token,
      purpose: 'password_reset',
      nowMs: t0 + 1000,
    }),
    { valid: false, reason: 'purpose_mismatch' },
  );

  // Wrong code
  const wrongCode = sent.previewCode === '123456' ? '654321' : '123456';
  assert.deepEqual(
    service.verifyOtp({
      email: 'bob@moonwitness.local',
      code: wrongCode,
      token: sent.token,
      purpose: 'email_verify',
      nowMs: t0 + 1000,
    }),
    { valid: false, reason: 'invalid_code' },
  );

  // Original token still works after failed verification attempts
  assert.deepEqual(
    service.verifyOtp({
      email: 'bob@moonwitness.local',
      code: sent.previewCode,
      token: sent.token,
      purpose: 'email_verify',
      nowMs: t0 + 2000,
    }),
    { valid: true, email: 'bob@moonwitness.local', purpose: 'email_verify' },
  );
});

test('EmailOtpService sends via Resend API when API key is configured and propagates failures', async () => {
  const capturedRequests = [];
  const service = createEmailOtpService({
    nodeEnv: 'production',
    secret: 'prod-otp-secret',
    resendApiKey: 're_test_12345',
    resendFrom: 'RID <auth@moonwitness.id>',
    fetchImpl: async (url, init) => {
      capturedRequests.push({ url, init });
      return new Response(JSON.stringify({ id: 'email_msg_001' }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      });
    },
  });

  const sent = await service.sendOtp({
    email: 'carol@moonwitness.local',
    purpose: 'password_reset',
  });

  assert.equal(sent.delivery, 'resend');
  assert.equal(sent.messageId, 'email_msg_001');
  assert.equal(sent.previewCode, undefined);
  assert.equal(capturedRequests.length, 1);
  assert.equal(capturedRequests[0].url, 'https://api.resend.com/emails');
  assert.equal(capturedRequests[0].init.method, 'POST');
  assert.equal(capturedRequests[0].init.headers.authorization, 'Bearer re_test_12345');

  const body = JSON.parse(capturedRequests[0].init.body);
  assert.equal(body.from, 'RID <auth@moonwitness.id>');
  assert.deepEqual(body.to, ['carol@moonwitness.local']);
  assert.match(body.text, /\d{6}/);

  const failingService = createEmailOtpService({
    nodeEnv: 'production',
    secret: 'prod-otp-secret',
    resendApiKey: 're_test_12345',
    fetchImpl: async () => new Response('rate limited', { status: 429 }),
  });

  await assert.rejects(
    () => failingService.sendOtp({ email: 'carol@moonwitness.local', purpose: 'login_otp' }),
    /Resend email delivery failed \(429\)/,
  );
});

test('startRidServer OTP request, verify, and password-reset endpoints work end-to-end', async () => {
  const running = await startRidServer({
    port: 0,
    host: '127.0.0.1',
    dbPath: ':memory:',
    nodeEnv: 'test',
    signingKeyOptions: { nodeEnv: 'test', allowEphemeralKeys: true },
    otpOptions: {
      secret: 'server-otp-secret',
      resendApiKey: '',
      logger: () => {},
    },
  });

  try {
    // Create account with email
    const createResp = await fetch(`${running.url}/api/accounts`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        username: 'resetuser',
        password: 'OldPassword!123',
        email: 'resetuser@moonwitness.local',
      }),
    });
    assert.equal(createResp.status, 201);
    const created = await createResp.json();

    // 1. Login OTP request & verify
    const otpReqResp = await fetch(`${running.url}/api/auth/otp/request`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'resetuser@moonwitness.local', purpose: 'login_otp' }),
    });
    assert.equal(otpReqResp.status, 200);
    const otpReqBody = await otpReqResp.json();
    assert.equal(otpReqBody.sent, true);
    assert.equal(otpReqBody.delivery, 'console');
    assert.match(otpReqBody.previewCode, /^\d{6}$/);

    const otpVerifyResp = await fetch(`${running.url}/api/auth/otp/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        email: 'resetuser@moonwitness.local',
        code: otpReqBody.previewCode,
        token: otpReqBody.token,
        purpose: 'login_otp',
      }),
    });
    assert.equal(otpVerifyResp.status, 200);
    const otpVerifyBody = await otpVerifyResp.json();
    assert.equal(otpVerifyBody.verified, true);

    // Replay returns 401
    const replayResp = await fetch(`${running.url}/api/auth/otp/verify`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        email: 'resetuser@moonwitness.local',
        code: otpReqBody.previewCode,
        token: otpReqBody.token,
        purpose: 'login_otp',
      }),
    });
    assert.equal(replayResp.status, 401);

    // 2. Password reset confirm flow
    const resetReqResp = await fetch(`${running.url}/api/auth/otp/request`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'resetuser@moonwitness.local', purpose: 'password_reset' }),
    });
    assert.equal(resetReqResp.status, 200);
    const resetReqBody = await resetReqResp.json();

    const resetConfirmResp = await fetch(`${running.url}/api/auth/password-reset/confirm`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        email: 'resetuser@moonwitness.local',
        code: resetReqBody.previewCode,
        token: resetReqBody.token,
        newPassword: 'NewStrongPassword!456',
      }),
    });
    assert.equal(resetConfirmResp.status, 200);
    const resetConfirmBody = await resetConfirmResp.json();
    assert.equal(resetConfirmBody.reset, true);
    assert.equal(resetConfirmBody.sub, created.sub);

    const updatedAccount = running.identityDb.findAccountByEmail('resetuser@moonwitness.local');
    assert.ok(updatedAccount);
    assert.equal(verifyPassword('OldPassword!123', updatedAccount.password_hash), false);
    assert.equal(verifyPassword('NewStrongPassword!456', updatedAccount.password_hash), true);
  } finally {
    await running.close();
  }
});

test('startRidServer never leaks previewCode when nodeEnv is production', async () => {
  const { privateKey } = generateKeyPairSync('rsa', {
    modulusLength: 2048,
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    publicKeyEncoding: { type: 'spki', format: 'pem' },
  });

  const running = await startRidServer({
    port: 0,
    host: '127.0.0.1',
    dbPath: ':memory:',
    nodeEnv: 'production',
    signingKeyOptions: { nodeEnv: 'production', signingKeyPem: privateKey },
    otpOptions: {
      nodeEnv: 'production',
      secret: 'prod-server-otp-secret',
      resendApiKey: '',
      logger: () => {},
    },
  });

  try {
    const resp = await fetch(`${running.url}/api/auth/otp/request`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ email: 'produser@moonwitness.local', purpose: 'login_otp' }),
    });
    assert.equal(resp.status, 200);
    const body = await resp.json();
    assert.equal(body.sent, true);
    assert.equal('previewCode' in body, false);
    assert.equal(body.previewCode, undefined);
  } finally {
    await running.close();
  }
});
