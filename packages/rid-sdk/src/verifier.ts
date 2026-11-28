import {
  createLocalJWKSet,
  createRemoteJWKSet,
  jwtVerify,
  type JSONWebKeySet,
  type JWTHeaderParameters,
  type JWTPayload,
} from 'jose';
import { checkJtiRevoked, type RevocationSyncClient } from './revocation.js';
import type { VerifiedAccessToken } from './verify.js';

export type RidVerifierAlgorithm = 'RS256';

export interface RidVerifierConfig {
  readonly issuer: string;
  readonly audience: string | string[];
  readonly jwksUri?: string;
  readonly jwks?: JSONWebKeySet;
  readonly jwksCooldownDurationMs?: number;
  readonly jwksCacheMaxAgeMs?: number;
  readonly revokedJtis?: ReadonlySet<string>;
  readonly revocationSync?: Pick<RevocationSyncClient, 'isRevoked'>;
  readonly revocationCheckUri?: string;
  readonly revocationCheckHeaders?: Record<string, string>;
  readonly fetchImpl?: typeof fetch;
  readonly isJtiRevoked?: (
    jti: string,
    context: { header: JWTHeaderParameters; payload: JWTPayload },
  ) => boolean | Promise<boolean>;
}

export interface RidHttpRequest {
  headers: Record<string, string | string[] | undefined>;
  ridAuth?: VerifiedAccessToken;
}

export interface RidHttpResponse {
  statusCode?: number;
  setHeader?: (name: string, value: string) => void;
  end?: (body?: string) => void;
}

export type RidNextFunction = (err?: unknown) => void;

export interface RidVerifier {
  verifyToken: (token: string) => Promise<VerifiedAccessToken>;
  verifyBearerHeader: (authorizationHeader: string | string[] | undefined) => Promise<VerifiedAccessToken>;
  middleware: (req: RidHttpRequest, res: RidHttpResponse, next: RidNextFunction) => Promise<void>;
}

const REQUIRED_ALGORITHMS: RidVerifierAlgorithm[] = ['RS256'];

export function extractBearerToken(headerValue: string | string[] | undefined): string {
  const raw = Array.isArray(headerValue) ? headerValue[0] : headerValue;
  if (!raw || typeof raw !== 'string') {
    throw new Error('Missing Authorization header');
  }
  const trimmed = raw.trim();
  if (!trimmed.toLowerCase().startsWith('bearer ')) {
    throw new Error('Authorization header must use Bearer scheme');
  }
  const token = trimmed.slice(7).trim();
  if (!token) {
    throw new Error('Bearer token is empty');
  }
  return token;
}

function validateAccessTokenClaims(
  header: JWTHeaderParameters,
  payload: JWTPayload,
): string {
  if (!header.kid || typeof header.kid !== 'string' || !header.kid.trim()) {
    throw new Error('Access token header must contain a non-empty kid');
  }
  if (header.alg !== 'RS256') {
    throw new Error(`Unsupported access token algorithm: ${header.alg ?? 'missing'}`);
  }
  if (payload.token_use === 'id') {
    throw new Error('OIDC ID tokens are rejected; an access token is required');
  }
  const normalizedTyp = typeof header.typ === 'string' ? header.typ.toLowerCase() : '';
  if (normalizedTyp !== 'at+jwt' && normalizedTyp !== 'application/at+jwt') {
    throw new Error(`Invalid access token typ header: ${header.typ ?? 'missing'}`);
  }
  if (typeof payload.exp !== 'number') {
    throw new Error('Access token must contain a numeric exp claim');
  }
  const jti = typeof payload.jti === 'string' ? payload.jti.trim() : '';
  if (!jti) {
    throw new Error('Access token must contain a non-empty jti claim');
  }
  return jti;
}

async function assertNotRevoked(
  jti: string,
  header: JWTHeaderParameters,
  payload: JWTPayload,
  config: RidVerifierConfig,
): Promise<void> {
  if (config.revokedJtis?.has(jti)) {
    throw new Error(`Access token jti is revoked: ${jti}`);
  }
  if (config.revocationSync?.isRevoked(jti)) {
    throw new Error(`Access token jti is revoked: ${jti}`);
  }
  if (config.isJtiRevoked) {
    const revoked = await config.isJtiRevoked(jti, { header, payload });
    if (revoked) {
      throw new Error(`Access token jti is revoked: ${jti}`);
    }
  }
  if (config.revocationCheckUri) {
    const remoteResult = await checkJtiRevoked({
      jti,
      revocationCheckUri: config.revocationCheckUri,
      headers: config.revocationCheckHeaders,
      fetchImpl: config.fetchImpl,
    });
    if (remoteResult.revoked) {
      throw new Error(`Access token jti is revoked: ${jti}`);
    }
  }
}

function resolveKeySet(config: RidVerifierConfig) {
  if (config.jwks) {
    return createLocalJWKSet(config.jwks);
  }
  if (!config.jwksUri) {
    throw new Error('createRidVerifier requires either jwks or jwksUri');
  }
  return createRemoteJWKSet(new URL(config.jwksUri), {
    cooldownDuration: config.jwksCooldownDurationMs,
    cacheMaxAge: config.jwksCacheMaxAgeMs,
  });
}

function writeUnauthorized(res: RidHttpResponse, err: unknown): void {
  res.statusCode = 401;
  res.setHeader?.('content-type', 'application/json');
  const message = err instanceof Error ? err.message : 'Unauthorized';
  res.end?.(JSON.stringify({ error: 'unauthorized', message }));
}

export function createRidVerifier(config: RidVerifierConfig): RidVerifier {
  const keyResolver = resolveKeySet(config);

  const verifyToken = async (token: string): Promise<VerifiedAccessToken> => {
    if (!token || typeof token !== 'string') {
      throw new Error('Access token must be a non-empty string');
    }

    const { payload, protectedHeader } = await jwtVerify(token, keyResolver, {
      issuer: config.issuer,
      audience: config.audience,
      algorithms: REQUIRED_ALGORITHMS,
    });

    const jti = validateAccessTokenClaims(protectedHeader, payload);
    await assertNotRevoked(jti, protectedHeader, payload, config);

    return {
      header: protectedHeader,
      payload: payload as VerifiedAccessToken['payload'],
    };
  };

  const verifyBearerHeader = async (
    authorizationHeader: string | string[] | undefined,
  ): Promise<VerifiedAccessToken> => {
    return verifyToken(extractBearerToken(authorizationHeader));
  };

  const middleware = async (
    req: RidHttpRequest,
    res: RidHttpResponse,
    next: RidNextFunction,
  ): Promise<void> => {
    try {
      const authHeader = req.headers.authorization ?? req.headers.Authorization;
      req.ridAuth = await verifyBearerHeader(authHeader);
      next();
    } catch (err) {
      writeUnauthorized(res, err);
    }
  };

  return { verifyToken, verifyBearerHeader, middleware };
}
