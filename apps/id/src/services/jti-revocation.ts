import { decodeJwt, decodeProtectedHeader } from 'jose';
import type { IdentityDatabase, RevokedJtiRecord } from '../storage/sqlite.js';

export interface RevokedJtiPublicView {
  seq: number;
  jti: string;
  kid: string | null;
  sub: string | null;
  reason: string | null;
  expiresAt: number | null;
  revokedAt: string;
}

export interface RevokeJtiInput {
  jti?: string;
  token?: string;
  kid?: string | null;
  sub?: string | null;
  reason?: string | null;
  expiresAt?: number | null;
  revokedAt?: string;
}

export interface RevokeJtiResult {
  created: boolean;
  revocation: RevokedJtiPublicView;
}

export interface CheckJtiRevocationInput {
  jti?: string;
  token?: string;
}

export interface JtiRevocationCheckResult {
  revoked: boolean;
  jti: string;
  revocation: RevokedJtiPublicView | null;
}

export interface JtiRevocationSyncOptions {
  since?: number;
  sinceRevokedAt?: string;
  limit?: number;
  includeExpired?: boolean;
  nowEpochSeconds?: number;
}

export interface JtiRevocationSyncResult {
  revocations: RevokedJtiPublicView[];
  cursor: number;
  syncedAt: string;
}

function toPublicView(record: RevokedJtiRecord): RevokedJtiPublicView {
  return {
    seq: record.seq,
    jti: record.jti,
    kid: record.kid,
    sub: record.sub,
    reason: record.reason,
    expiresAt: record.expires_at,
    revokedAt: record.revoked_at,
  };
}

function extractTokenMetadata(token: string): {
  jti: string;
  kid: string | null;
  sub: string | null;
  expiresAt: number | null;
} {
  const trimmed = token.trim();
  if (!trimmed) {
    throw new Error('token must be a non-empty JWT string.');
  }

  let kid: string | null = null;
  try {
    const header = decodeProtectedHeader(trimmed);
    if (typeof header.kid === 'string' && header.kid.trim().length > 0) {
      kid = header.kid.trim();
    }
  } catch {
    throw new Error('token must be a valid JWT with a readable header.');
  }

  let payload: ReturnType<typeof decodeJwt>;
  try {
    payload = decodeJwt(trimmed);
  } catch {
    throw new Error('token must be a valid JWT with a readable payload.');
  }

  const jti = typeof payload.jti === 'string' ? payload.jti.trim() : '';
  if (!jti) {
    throw new Error('token does not contain a valid jti claim.');
  }

  const sub = typeof payload.sub === 'string' && payload.sub.trim().length > 0
    ? payload.sub.trim()
    : null;
  const expiresAt = typeof payload.exp === 'number' && Number.isFinite(payload.exp)
    ? Math.floor(payload.exp)
    : null;

  return { jti, kid, sub, expiresAt };
}

export class JtiRevocationService {
  private readonly identityDb: IdentityDatabase;

  constructor(identityDb: IdentityDatabase) {
    this.identityDb = identityDb;
  }

  public revoke(input: RevokeJtiInput): RevokeJtiResult {
    let jti = typeof input.jti === 'string' ? input.jti.trim() : '';
    let kid = typeof input.kid === 'string' && input.kid.trim().length > 0 ? input.kid.trim() : null;
    let sub = typeof input.sub === 'string' && input.sub.trim().length > 0 ? input.sub.trim() : null;
    let expiresAt =
      typeof input.expiresAt === 'number' && Number.isFinite(input.expiresAt)
        ? Math.floor(input.expiresAt)
        : null;

    if (typeof input.token === 'string' && input.token.trim().length > 0) {
      const extracted = extractTokenMetadata(input.token);
      if (!jti) {
        jti = extracted.jti;
      }
      kid = kid ?? extracted.kid;
      sub = sub ?? extracted.sub;
      expiresAt = expiresAt ?? extracted.expiresAt;
    }

    if (!jti) {
      throw new Error('A non-empty jti or JWT token with a jti claim is required.');
    }

    const reason =
      typeof input.reason === 'string' && input.reason.trim().length > 0
        ? input.reason.trim()
        : null;

    const result = this.identityDb.revokeJti({
      jti,
      kid,
      sub,
      reason,
      expiresAt,
      revokedAt: input.revokedAt,
    });

    return {
      created: result.created,
      revocation: toPublicView(result.record),
    };
  }

  public check(input: CheckJtiRevocationInput): JtiRevocationCheckResult {
    let jti = typeof input.jti === 'string' ? input.jti.trim() : '';
    if (!jti && typeof input.token === 'string' && input.token.trim().length > 0) {
      jti = extractTokenMetadata(input.token).jti;
    }

    if (!jti) {
      throw new Error('A non-empty jti or JWT token with a jti claim is required.');
    }

    const record = this.identityDb.findRevokedJti(jti);
    return {
      revoked: Boolean(record),
      jti,
      revocation: record ? toPublicView(record) : null,
    };
  }

  public isRevoked(jti: string): boolean {
    const trimmed = jti.trim();
    if (!trimmed) {
      return false;
    }
    return this.identityDb.isJtiRevoked(trimmed);
  }

  public sync(options: JtiRevocationSyncOptions = {}): JtiRevocationSyncResult {
    const sinceSeq =
      options.since !== undefined
        ? Math.max(0, Math.floor(options.since))
        : undefined;
    const records = this.identityDb.listRevokedJtis({
      sinceSeq,
      sinceRevokedAt: options.sinceRevokedAt,
      limit: options.limit,
      includeExpired: options.includeExpired ?? false,
      nowEpochSeconds: options.nowEpochSeconds,
    });

    const cursor =
      records.length > 0
        ? records[records.length - 1].seq
        : (sinceSeq ?? 0);

    return {
      revocations: records.map(toPublicView),
      cursor,
      syncedAt: new Date().toISOString(),
    };
  }

  public pruneExpired(nowEpochSeconds?: number): number {
    return this.identityDb.pruneExpiredRevokedJtis(nowEpochSeconds);
  }
}

export function createJtiRevocationService(identityDb: IdentityDatabase): JtiRevocationService {
  return new JtiRevocationService(identityDb);
}
