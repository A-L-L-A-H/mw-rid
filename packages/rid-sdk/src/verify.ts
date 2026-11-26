import { createRemoteJWKSet, jwtVerify, type JWTPayload, type JWTHeaderParameters } from 'jose';

const ALLOWED_ASYMMETRIC_ALGS = [
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'ES512',
  'EdDSA',
] as const;

export interface VerifyAccessTokenOptions {
  token: string;
  issuer: string;
  audience: string | string[];
  jwksUri: string;
}

export interface VerifiedAccessToken {
  header: JWTHeaderParameters;
  payload: JWTPayload & {
    sub?: string;
    scope?: string;
    client_id?: string;
  };
}

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

function getRemoteJwks(jwksUri: string): ReturnType<typeof createRemoteJWKSet> {
  const cached = jwksCache.get(jwksUri);
  if (cached) {
    return cached;
  }
  const remoteJwks = createRemoteJWKSet(new URL(jwksUri));
  jwksCache.set(jwksUri, remoteJwks);
  return remoteJwks;
}

export async function verifyAccessToken(
  options: VerifyAccessTokenOptions,
): Promise<VerifiedAccessToken> {
  const { token, issuer, audience, jwksUri } = options;

  if (!token || typeof token !== 'string') {
    throw new Error('Access token must be a non-empty string');
  }

  const jwks = getRemoteJwks(jwksUri);

  const verification = await jwtVerify(token, jwks, {
    issuer,
    audience,
    algorithms: [...ALLOWED_ASYMMETRIC_ALGS],
  });

  const { payload, protectedHeader } = verification;

  if (payload.token_use === 'id') {
    throw new Error('OIDC ID tokens are rejected; an access token is required');
  }

  const normalizedTyp = typeof protectedHeader.typ === 'string'
    ? protectedHeader.typ.toLowerCase()
    : '';

  if (normalizedTyp !== 'at+jwt' && normalizedTyp !== 'application/at+jwt') {
    throw new Error(`Invalid access token typ header: ${protectedHeader.typ ?? 'missing'}`);
  }

  if (typeof payload.at_hash === 'string' || typeof payload.c_hash === 'string') {
    throw new Error('OIDC ID tokens containing at_hash or c_hash are rejected');
  }

  if (typeof payload.exp !== 'number') {
    throw new Error('Access token must contain a numeric exp claim');
  }

  return {
    header: protectedHeader,
    payload: payload as VerifiedAccessToken['payload'],
  };
}
