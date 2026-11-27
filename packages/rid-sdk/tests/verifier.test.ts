import { describe, expect, test } from 'bun:test';
import { SignJWT, exportJWK, generateKeyPair, type JSONWebKeySet } from 'jose';
import { createRidVerifier, extractBearerToken } from '../src/verifier.js';

const ISSUER = 'https://id.moonwitness.local';
const AUDIENCE = 'moonwitness-api';

async function buildDualKidFixture() {
  const primary = await generateKeyPair('RS256');
  const secondary = await generateKeyPair('RS256');
  const primaryJwk = await exportJWK(primary.publicKey);
  const secondaryJwk = await exportJWK(secondary.publicKey);

  const jwks: JSONWebKeySet = {
    keys: [
      { ...primaryJwk, kid: 'kid-primary', use: 'sig', alg: 'RS256' },
      { ...secondaryJwk, kid: 'kid-secondary', use: 'sig', alg: 'RS256' },
    ],
  };

  return { primary, secondary, jwks };
}

async function signAccessToken(
  privateKey: Awaited<ReturnType<typeof generateKeyPair>>['privateKey'],
  kid: string,
  jti: string | undefined,
): Promise<string> {
  const builder = new SignJWT({
    sub: 'usr-42',
    scope: 'openid profile',
    client_id: 'mw-dock',
    ...(jti ? { jti } : {}),
  })
    .setProtectedHeader({ alg: 'RS256', typ: 'at+jwt', kid })
    .setIssuer(ISSUER)
    .setAudience(AUDIENCE)
    .setIssuedAt()
    .setExpirationTime('5m');

  return builder.sign(privateKey);
}

describe('@moonwitness/rid-sdk dual-kid RS256 verifier', () => {
  test('verifies tokens signed by both primary and secondary kids', async () => {
    const { primary, secondary, jwks } = await buildDualKidFixture();
    const verifier = createRidVerifier({ issuer: ISSUER, audience: AUDIENCE, jwks });

    const tokenA = await signAccessToken(primary.privateKey, 'kid-primary', 'jti-a');
    const tokenB = await signAccessToken(secondary.privateKey, 'kid-secondary', 'jti-b');

    const verifiedA = await verifier.verifyToken(tokenA);
    const verifiedB = await verifier.verifyToken(tokenB);

    expect(verifiedA.header.kid).toBe('kid-primary');
    expect(verifiedA.payload.jti).toBe('jti-a');
    expect(verifiedB.header.kid).toBe('kid-secondary');
    expect(verifiedB.payload.jti).toBe('jti-b');
  });

  test('rejects unknown kid, missing jti, and revoked jti', async () => {
    const { primary, jwks } = await buildDualKidFixture();
    const revokedJtis = new Set(['jti-revoked']);
    const verifier = createRidVerifier({
      issuer: ISSUER,
      audience: AUDIENCE,
      jwks,
      revokedJtis,
    });

    const unknownKidToken = await signAccessToken(primary.privateKey, 'kid-unknown', 'jti-1');
    await expect(verifier.verifyToken(unknownKidToken)).rejects.toThrow();

    const missingJtiToken = await signAccessToken(primary.privateKey, 'kid-primary', undefined);
    await expect(verifier.verifyToken(missingJtiToken)).rejects.toThrow(/jti/i);

    const revokedToken = await signAccessToken(primary.privateKey, 'kid-primary', 'jti-revoked');
    await expect(verifier.verifyToken(revokedToken)).rejects.toThrow(/revoked/i);
  });

  test('extracts bearer header and runs HTTP middleware', async () => {
    const { primary, jwks } = await buildDualKidFixture();
    const verifier = createRidVerifier({ issuer: ISSUER, audience: AUDIENCE, jwks });
    const validToken = await signAccessToken(primary.privateKey, 'kid-primary', 'jti-ok');

    expect(extractBearerToken(`Bearer ${validToken}`)).toBe(validToken);
    expect(() => extractBearerToken('Basic abc')).toThrow(/Bearer/i);

    let nextCalled = false;
    const okReq: { headers: Record<string, string>; ridAuth?: unknown } = {
      headers: { authorization: `Bearer ${validToken}` },
    };
    await verifier.middleware(okReq, {}, () => {
      nextCalled = true;
    });
    expect(nextCalled).toBe(true);
    expect(okReq.ridAuth).toBeDefined();

    let status = 0;
    let body = '';
    const badReq = { headers: {} };
    await verifier.middleware(
      badReq,
      {
        set statusCode(code: number) {
          status = code;
        },
        end(payload?: string) {
          body = payload ?? '';
        },
      },
      () => {
        throw new Error('next should not be called');
      },
    );
    expect(status).toBe(401);
    expect(body).toContain('unauthorized');
  });
});
