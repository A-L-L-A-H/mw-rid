import {
  createRemoteJWKSet,
  jwtVerify,
  type JWTPayload,
  type JWTHeaderParameters,
} from 'jose';
import { checkJtiRevoked, type RevocationSyncClient } from './revocation.js';

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
  jwksCooldownDurationMs?: number;
  jwksCacheMaxAgeMs?: number;
  forceJwksRefresh?: boolean;
  requireJti?: boolean;
  revokedJtis?: ReadonlySet<string>;
  revocationSync?: Pick<RevocationSyncClient, 'isRevoked'>;
  revocationCheckUri?: string;
  revocationCheckHeaders?: Record<string, string>;
  fetchImpl?: typeof fetch;
  isJtiRevoked?: (
    jti: string,
    context: { header: JWTHeaderParameters; payload: JWTPayload },
  ) => boolean | Promise<boolean>;
}

export interface VerifiedAccessToken {
  header: JWTHeaderParameters;
  payload: JWTPayload & {
    sub?: string;
    scope?: string;
    client_id?: string;
    jti?: string;
  };
}

type RemoteJwksResolver = ReturnType<typeof createRemoteJWKSet>;

const jwksCache = new Map<string, Map<string, RemoteJwksResolver>>();

function getRemoteJwks(
  jwksUri: string,
  options?: { cooldownDurationMs?: number; cacheMaxAgeMs?: number },
): RemoteJwksResolver {
  let uriMap = jwksCache.get(jwksUri);
  if (!uriMap) {
    uriMap = new Map<string, RemoteJwksResolver>();
    jwksCache.set(jwksUri, uriMap);
  }

  const variantKey = `${options?.cooldownDurationMs ?? 'default'}:${options?.cacheMaxAgeMs ?? 'default'}`;
  const cached = uriMap.get(variantKey);
  if (cached) {
    return cached;
  }

  const remoteJwks = createRemoteJWKSet(new URL(jwksUri), {
    cooldownDuration: options?.cooldownDurationMs,
    cacheMaxAge: options?.cacheMaxAgeMs,
  });
  uriMap.set(variantKey, remoteJwks);
  return remoteJwks;
}

export function clearJwksCache(jwksUri?: string): void {
  if (!jwksUri) {
    jwksCache.clear();
    return;
  }
  jwksCache.delete(jwksUri);
}

export async function reloadJwks(jwksUri: string): Promise<void> {
  const uriMap = jwksCache.get(jwksUri);
  if (!uriMap) {
    return;
  }
  await Promise.all(Array.from(uriMap.values()).map((remoteJwks) => remoteJwks.reload()));
}

export async function verifyAccessToken(
  options: VerifyAccessTokenOptions,
): Promise<VerifiedAccessToken> {
  const { token, issuer, audience, jwksUri } = options;

  if (!token || typeof token !== 'string') {
    throw new Error('Access token must be a non-empty string');
  }

  const jwks = getRemoteJwks(jwksUri, {
    cooldownDurationMs: options.jwksCooldownDurationMs,
    cacheMaxAgeMs: options.jwksCacheMaxAgeMs,
  });

  if (options.forceJwksRefresh) {
    await jwks.reload();
  }

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

  const needsRevocationCheck = Boolean(
    options.requireJti ||
      options.revokedJtis ||
      options.revocationSync ||
      options.revocationCheckUri ||
      options.isJtiRevoked,
  );

  if (needsRevocationCheck) {
    const jti = typeof payload.jti === 'string' ? payload.jti.trim() : '';
    if (!jti) {
      throw new Error('Access token must contain a non-empty jti claim');
    }

    if (options.revokedJtis?.has(jti)) {
      throw new Error(`Access token jti is revoked: ${jti}`);
    }

    if (options.revocationSync?.isRevoked(jti)) {
      throw new Error(`Access token jti is revoked: ${jti}`);
    }

    if (options.isJtiRevoked) {
      const revoked = await options.isJtiRevoked(jti, {
        header: protectedHeader,
        payload,
      });
      if (revoked) {
        throw new Error(`Access token jti is revoked: ${jti}`);
      }
    }

    if (options.revocationCheckUri) {
      const remoteCheck = await checkJtiRevoked({
        jti,
        revocationCheckUri: options.revocationCheckUri,
        headers: options.revocationCheckHeaders,
        fetchImpl: options.fetchImpl,
      });
      if (remoteCheck.revoked) {
        throw new Error(`Access token jti is revoked: ${jti}`);
      }
    }
  }

  return {
    header: protectedHeader,
    payload: payload as VerifiedAccessToken['payload'],
  };
}
