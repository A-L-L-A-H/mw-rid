import { randomBytes, randomUUID } from 'node:crypto';
import { hashSecretSha256, verifySecretSha256 } from '../crypto/passwords.js';
import type {
  IdentityDatabase,
  TenantApiKeyRecord,
  TenantApiKeyStatus,
} from '../storage/sqlite.js';

export type { TenantApiKeyRecord, TenantApiKeyStatus };

export interface TenantApiKeyPublicView {
  id: string;
  tenantId: string;
  name: string;
  keyPrefix: string;
  scopes: string[];
  status: TenantApiKeyStatus;
  expiresAt: string | null;
  lastUsedAt: string | null;
  createdAt: string;
  revokedAt: string | null;
}

export interface CreateTenantApiKeyInput {
  tenantId: string;
  name: string;
  scopes?: string[];
  expiresInDays?: number;
  nowMs?: number;
}

export interface CreatedTenantApiKey {
  key: TenantApiKeyPublicView;
  apiKey: string;
}

export type VerifiedTenantApiKey =
  | {
      valid: true;
      id: string;
      tenantId: string;
      name: string;
      keyPrefix: string;
      scopes: string[];
    }
  | {
      valid: false;
      reason: 'invalid_format' | 'not_found' | 'revoked' | 'expired';
    };

const MS_PER_DAY = 86_400_000;

function parseScopes(scopesJson: string): string[] {
  try {
    const parsed = JSON.parse(scopesJson) as unknown;
    if (Array.isArray(parsed)) {
      return parsed.filter((entry): entry is string => typeof entry === 'string');
    }
  } catch {
    // Fallback for unexpected malformed JSON
  }
  return [];
}

function toPublicView(record: TenantApiKeyRecord): TenantApiKeyPublicView {
  return {
    id: record.id,
    tenantId: record.tenant_id,
    name: record.name,
    keyPrefix: record.key_prefix,
    scopes: parseScopes(record.scopes),
    status: record.status,
    expiresAt: record.expires_at,
    lastUsedAt: record.last_used_at,
    createdAt: record.created_at,
    revokedAt: record.revoked_at,
  };
}

export class TenantApiKeyService {
  private readonly identityDb: IdentityDatabase;

  constructor(identityDb: IdentityDatabase) {
    this.identityDb = identityDb;
  }

  public createKey(input: CreateTenantApiKeyInput): CreatedTenantApiKey {
    const tenantId = input.tenantId.trim();
    const name = input.name.trim();
    if (!tenantId) {
      throw new Error('tenantId is required.');
    }
    if (!name) {
      throw new Error('name is required.');
    }

    const rawScopes = input.scopes ?? ['api:read'];
    const scopes = Array.from(
      new Set(rawScopes.map((entry) => String(entry).trim()).filter((entry) => entry.length > 0)),
    );
    if (scopes.length === 0) {
      throw new Error('At least one valid scope is required.');
    }

    const nowMs = input.nowMs ?? Date.now();
    let expiresAt: string | null = null;
    if (input.expiresInDays !== undefined) {
      if (!Number.isFinite(input.expiresInDays) || input.expiresInDays <= 0) {
        throw new Error('expiresInDays must be a positive finite number.');
      }
      expiresAt = new Date(nowMs + input.expiresInDays * MS_PER_DAY).toISOString();
    }

    const id = `key_${randomUUID()}`;
    const prefixHex = randomBytes(6).toString('hex');
    const secretPart = randomBytes(24).toString('base64url');
    const keyPrefix = `mw_k_${prefixHex}`;
    const apiKey = `${keyPrefix}_${secretPart}`;
    const secretHash = hashSecretSha256(apiKey);

    const record = this.identityDb.createTenantApiKey({
      id,
      tenantId,
      name,
      keyPrefix,
      secretHash,
      scopes,
      expiresAt,
      createdAt: new Date(nowMs).toISOString(),
    });

    return {
      key: toPublicView(record),
      apiKey,
    };
  }

  public verifyKey(rawKey: string, nowMs: number = Date.now()): VerifiedTenantApiKey {
    if (typeof rawKey !== 'string') {
      return { valid: false, reason: 'invalid_format' };
    }
    const trimmed = rawKey.trim();
    if (!/^mw_k_[0-9a-f]{12}_[A-Za-z0-9_-]+$/.test(trimmed)) {
      return { valid: false, reason: 'invalid_format' };
    }

    const secretHash = hashSecretSha256(trimmed);
    const record = this.identityDb.findTenantApiKeyBySecretHash(secretHash);
    if (!record || !verifySecretSha256(trimmed, record.secret_hash)) {
      return { valid: false, reason: 'not_found' };
    }

    if (record.status !== 'active') {
      return { valid: false, reason: 'revoked' };
    }

    if (record.expires_at !== null) {
      const expiresAtMs = Date.parse(record.expires_at);
      if (!Number.isFinite(expiresAtMs) || nowMs > expiresAtMs) {
        return { valid: false, reason: 'expired' };
      }
    }

    this.identityDb.touchTenantApiKeyLastUsed(record.id, new Date(nowMs).toISOString());

    return {
      valid: true,
      id: record.id,
      tenantId: record.tenant_id,
      name: record.name,
      keyPrefix: record.key_prefix,
      scopes: parseScopes(record.scopes),
    };
  }

  public listKeys(tenantId: string): TenantApiKeyPublicView[] {
    const normalizedTenantId = tenantId.trim();
    if (!normalizedTenantId) {
      throw new Error('tenantId is required.');
    }
    return this.identityDb.listTenantApiKeys(normalizedTenantId).map(toPublicView);
  }

  public revokeKey(id: string, tenantId?: string): boolean {
    const trimmedId = id.trim();
    if (!trimmedId) {
      return false;
    }
    const normalizedTenantId = tenantId?.trim();
    return this.identityDb.revokeTenantApiKey(
      trimmedId,
      normalizedTenantId && normalizedTenantId.length > 0 ? normalizedTenantId : undefined,
    );
  }
}

export function createTenantApiKeyService(identityDb: IdentityDatabase): TenantApiKeyService {
  return new TenantApiKeyService(identityDb);
}
