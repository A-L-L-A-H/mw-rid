import { randomBytes, randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { hashPassword, hashSecretSha256, verifySecretSha256 } from '../crypto/passwords.js';

export type AccountStatus = 'active' | 'disabled';
export type AccountRole = 'platform_owner' | 'member';
export type OutboxEventType =
  | 'account.created'
  | 'account.disabled'
  | 'grant.revoked'
  | 'api_key.created'
  | 'api_key.revoked'
  | 'jti.revoked'
  | 'jwks.rotated';

export interface RevokedJtiRecord {
  seq: number;
  jti: string;
  kid: string | null;
  sub: string | null;
  reason: string | null;
  expires_at: number | null;
  revoked_at: string;
}

export interface FederatedIdentityRecord {
  provider: string;
  provider_sub: string;
  account_sub: string;
  email: string;
  created_at: string;
}

export interface UpsertGoogleAccountResult {
  account: AccountRecord;
  created: boolean;
  linked: boolean;
}

export type TenantApiKeyStatus = 'active' | 'revoked';

export interface TenantApiKeyRecord {
  id: string;
  tenant_id: string;
  name: string;
  key_prefix: string;
  secret_hash: string;
  scopes: string;
  status: TenantApiKeyStatus;
  expires_at: string | null;
  last_used_at: string | null;
  created_at: string;
  revoked_at: string | null;
}

export interface AccountRecord {
  sub: string;
  username: string;
  email: string | null;
  password_hash: string;
  role: AccountRole;
  status: AccountStatus;
  created_at: string;
  updated_at: string;
}

export interface OutboxEventRecord {
  id: number;
  event_type: OutboxEventType;
  subject: string;
  payload: Record<string, unknown>;
  created_at: string;
  acked_at: string | null;
}

export interface ServicePrincipalRecord {
  client_id: string;
  name: string;
  secret_hash: string;
  scopes: string;
  status: AccountStatus;
  created_at: string;
}

export class IdentityDatabase {
  public readonly db: DatabaseSync;

  constructor(dbPath: string = ':memory:') {
    this.db = new DatabaseSync(dbPath);
    this.db.exec('PRAGMA journal_mode = WAL;');
    this.db.exec('PRAGMA foreign_keys = ON;');
    this.migrate();
  }

  private migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS oidc_store (
        id TEXT PRIMARY KEY,
        kind TEXT NOT NULL,
        payload TEXT NOT NULL,
        grant_id TEXT,
        user_code TEXT,
        uid TEXT,
        expires_at INTEGER,
        consumed_at INTEGER
      );
      CREATE INDEX IF NOT EXISTS idx_oidc_store_grant_id ON oidc_store(grant_id);
      CREATE INDEX IF NOT EXISTS idx_oidc_store_user_code ON oidc_store(user_code);
      CREATE INDEX IF NOT EXISTS idx_oidc_store_uid ON oidc_store(uid);

      CREATE TABLE IF NOT EXISTS accounts (
        sub TEXT PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        email TEXT,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS bootstrap_state (
        id INTEGER PRIMARY KEY CHECK (id = 1),
        secret_hash TEXT NOT NULL,
        consumed_at TEXT,
        owner_sub TEXT
      );

      CREATE TABLE IF NOT EXISTS service_principals (
        client_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        secret_hash TEXT NOT NULL,
        scopes TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS identity_outbox (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_type TEXT NOT NULL,
        subject TEXT NOT NULL,
        payload TEXT NOT NULL,
        created_at TEXT NOT NULL,
        acked_at TEXT
      );

      CREATE TABLE IF NOT EXISTS federated_identities (
        provider TEXT NOT NULL,
        provider_sub TEXT NOT NULL,
        account_sub TEXT NOT NULL,
        email TEXT NOT NULL,
        created_at TEXT NOT NULL,
        PRIMARY KEY (provider, provider_sub),
        FOREIGN KEY (account_sub) REFERENCES accounts(sub) ON DELETE CASCADE
      );
      CREATE INDEX IF NOT EXISTS idx_federated_identities_account_sub ON federated_identities(account_sub);

      CREATE TABLE IF NOT EXISTS tenant_api_keys (
        id TEXT PRIMARY KEY,
        tenant_id TEXT NOT NULL,
        name TEXT NOT NULL,
        key_prefix TEXT NOT NULL,
        secret_hash TEXT NOT NULL UNIQUE,
        scopes TEXT NOT NULL,
        status TEXT NOT NULL,
        expires_at TEXT,
        last_used_at TEXT,
        created_at TEXT NOT NULL,
        revoked_at TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_tenant_api_keys_tenant ON tenant_api_keys(tenant_id);

      CREATE TABLE IF NOT EXISTS revoked_jtis (
        seq INTEGER PRIMARY KEY AUTOINCREMENT,
        jti TEXT NOT NULL UNIQUE,
        kid TEXT,
        sub TEXT,
        reason TEXT,
        expires_at INTEGER,
        revoked_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_revoked_jtis_revoked_at ON revoked_jtis(revoked_at);
      CREATE INDEX IF NOT EXISTS idx_revoked_jtis_expires_at ON revoked_jtis(expires_at);
    `);
  }

  public initBootstrapSecretHash(secretHash: string): void {
    const existing = this.db
      .prepare('SELECT id FROM bootstrap_state WHERE id = 1')
      .get() as { id: number } | undefined;
    if (!existing) {
      this.db
        .prepare('INSERT INTO bootstrap_state (id, secret_hash, consumed_at, owner_sub) VALUES (1, ?, NULL, NULL)')
        .run(secretHash);
    }
  }

  public bootstrapPlatformOwner(input: {
    setupSecret: string;
    username: string;
    password: string;
    email?: string;
  }): AccountRecord {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const state = this.db
        .prepare('SELECT secret_hash, consumed_at FROM bootstrap_state WHERE id = 1')
        .get() as { secret_hash: string; consumed_at: string | null } | undefined;

      if (!state) {
        throw new Error('BOOTSTRAP_UNAVAILABLE');
      }
      if (state.consumed_at !== null) {
        throw new Error('BOOTSTRAP_ALREADY_CONSUMED');
      }
      if (!verifySecretSha256(input.setupSecret, state.secret_hash)) {
        throw new Error('BOOTSTRAP_INVALID_SECRET');
      }

      const now = new Date().toISOString();
      const sub = `rid_${randomUUID()}`;
      const passwordHash = hashPassword(input.password);
      const email = input.email ?? null;

      this.db
        .prepare(
          `INSERT INTO accounts (sub, username, email, password_hash, role, status, created_at, updated_at)
           VALUES (?, ?, ?, ?, 'platform_owner', 'active', ?, ?)`,
        )
        .run(sub, input.username, email, passwordHash, now, now);

      this.db
        .prepare('UPDATE bootstrap_state SET consumed_at = ?, owner_sub = ? WHERE id = 1')
        .run(now, sub);

      this.insertOutboxEvent('account.created', sub, {
        sub,
        username: input.username,
        role: 'platform_owner',
        status: 'active',
      });

      this.db.exec('COMMIT');

      return {
        sub,
        username: input.username,
        email,
        password_hash: passwordHash,
        role: 'platform_owner',
        status: 'active',
        created_at: now,
        updated_at: now,
      };
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  public createAccount(input: {
    username: string;
    password: string;
    email?: string;
    role?: AccountRole;
  }): AccountRecord {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const now = new Date().toISOString();
      const sub = `rid_${randomUUID()}`;
      const passwordHash = hashPassword(input.password);
      const role: AccountRole = input.role ?? 'member';
      const email = input.email ?? null;

      this.db
        .prepare(
          `INSERT INTO accounts (sub, username, email, password_hash, role, status, created_at, updated_at)
           VALUES (?, ?, ?, ?, ?, 'active', ?, ?)`,
        )
        .run(sub, input.username, email, passwordHash, role, now, now);

      this.insertOutboxEvent('account.created', sub, {
        sub,
        username: input.username,
        role,
        status: 'active',
      });

      this.db.exec('COMMIT');

      return {
        sub,
        username: input.username,
        email,
        password_hash: passwordHash,
        role,
        status: 'active',
        created_at: now,
        updated_at: now,
      };
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  public findAccountBySub(sub: string): AccountRecord | undefined {
    return this.db
      .prepare('SELECT * FROM accounts WHERE sub = ?')
      .get(sub) as AccountRecord | undefined;
  }

  public findAccountByUsername(username: string): AccountRecord | undefined {
    return this.db
      .prepare('SELECT * FROM accounts WHERE username = ?')
      .get(username) as AccountRecord | undefined;
  }

  public findAccountByEmail(email: string): AccountRecord | undefined {
    const normalized = email.trim().toLowerCase();
    if (!normalized) {
      return undefined;
    }
    return this.db
      .prepare('SELECT * FROM accounts WHERE LOWER(email) = ? LIMIT 1')
      .get(normalized) as AccountRecord | undefined;
  }

  public updateAccountPassword(sub: string, newPassword: string): boolean {
    const now = new Date().toISOString();
    const passwordHash = hashPassword(newPassword);
    const result = this.db
      .prepare('UPDATE accounts SET password_hash = ?, updated_at = ? WHERE sub = ?')
      .run(passwordHash, now, sub);
    return Number(result.changes) > 0;
  }

  public upsertGoogleAccount(input: {
    googleSub: string;
    email: string;
    name?: string;
  }): UpsertGoogleAccountResult {
    const googleSub = input.googleSub.trim();
    const email = input.email.trim().toLowerCase();
    if (!googleSub || !email) {
      throw new Error('googleSub and email are required.');
    }

    this.db.exec('BEGIN IMMEDIATE');
    try {
      const now = new Date().toISOString();
      const existingFed = this.db
        .prepare('SELECT * FROM federated_identities WHERE provider = ? AND provider_sub = ?')
        .get('google', googleSub) as FederatedIdentityRecord | undefined;

      if (existingFed) {
        const account = this.findAccountBySub(existingFed.account_sub);
        if (!account) {
          throw new Error('FEDERATED_ACCOUNT_MISSING');
        }
        if (account.status !== 'active') {
          throw new Error('ACCOUNT_DISABLED');
        }
        if (account.email !== email) {
          this.db
            .prepare('UPDATE accounts SET email = ?, updated_at = ? WHERE sub = ?')
            .run(email, now, account.sub);
          this.db
            .prepare('UPDATE federated_identities SET email = ? WHERE provider = ? AND provider_sub = ?')
            .run(email, 'google', googleSub);
          account.email = email;
          account.updated_at = now;
        }
        this.db.exec('COMMIT');
        return { account, created: false, linked: false };
      }

      const existingByEmail = this.findAccountByEmail(email);
      if (existingByEmail) {
        if (existingByEmail.status !== 'active') {
          throw new Error('ACCOUNT_DISABLED');
        }
        this.db
          .prepare(
            `INSERT INTO federated_identities (provider, provider_sub, account_sub, email, created_at)
             VALUES ('google', ?, ?, ?, ?)`,
          )
          .run(googleSub, existingByEmail.sub, email, now);
        this.db.exec('COMMIT');
        return { account: existingByEmail, created: false, linked: true };
      }

      const rawBase = (email.split('@')[0] || input.name || 'user')
        .toLowerCase()
        .replace(/[^a-z0-9._-]+/g, '_')
        .replace(/^_+|_+$/g, '')
        .slice(0, 24) || 'user';

      let username = rawBase;
      if (this.findAccountByUsername(username)) {
        username = `${rawBase}_${randomBytes(4).toString('hex')}`;
      }

      const sub = `rid_${randomUUID()}`;
      const passwordHash = hashPassword(randomBytes(32).toString('base64url'));

      this.db
        .prepare(
          `INSERT INTO accounts (sub, username, email, password_hash, role, status, created_at, updated_at)
           VALUES (?, ?, ?, ?, 'member', 'active', ?, ?)`,
        )
        .run(sub, username, email, passwordHash, now, now);

      this.db
        .prepare(
          `INSERT INTO federated_identities (provider, provider_sub, account_sub, email, created_at)
           VALUES ('google', ?, ?, ?, ?)`,
        )
        .run(googleSub, sub, email, now);

      this.insertOutboxEvent('account.created', sub, {
        sub,
        username,
        email,
        role: 'member',
        status: 'active',
        provider: 'google',
      });

      this.db.exec('COMMIT');

      return {
        account: {
          sub,
          username,
          email,
          password_hash: passwordHash,
          role: 'member',
          status: 'active',
          created_at: now,
          updated_at: now,
        },
        created: true,
        linked: true,
      };
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  public createTenantApiKey(input: {
    id: string;
    tenantId: string;
    name: string;
    keyPrefix: string;
    secretHash: string;
    scopes: string[];
    expiresAt: string | null;
    createdAt?: string;
  }): TenantApiKeyRecord {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const now = input.createdAt ?? new Date().toISOString();
      const scopesJson = JSON.stringify(input.scopes);

      this.db
        .prepare(
          `INSERT INTO tenant_api_keys
           (id, tenant_id, name, key_prefix, secret_hash, scopes, status, expires_at, last_used_at, created_at, revoked_at)
           VALUES (?, ?, ?, ?, ?, ?, 'active', ?, NULL, ?, NULL)`,
        )
        .run(
          input.id,
          input.tenantId,
          input.name,
          input.keyPrefix,
          input.secretHash,
          scopesJson,
          input.expiresAt,
          now,
        );

      this.insertOutboxEvent('api_key.created', input.id, {
        id: input.id,
        tenant_id: input.tenantId,
        key_prefix: input.keyPrefix,
        scopes: input.scopes,
        expires_at: input.expiresAt,
      });

      this.db.exec('COMMIT');

      return {
        id: input.id,
        tenant_id: input.tenantId,
        name: input.name,
        key_prefix: input.keyPrefix,
        secret_hash: input.secretHash,
        scopes: scopesJson,
        status: 'active',
        expires_at: input.expiresAt,
        last_used_at: null,
        created_at: now,
        revoked_at: null,
      };
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  public findTenantApiKeyBySecretHash(secretHash: string): TenantApiKeyRecord | undefined {
    return this.db
      .prepare('SELECT * FROM tenant_api_keys WHERE secret_hash = ? LIMIT 1')
      .get(secretHash) as TenantApiKeyRecord | undefined;
  }

  public findTenantApiKeyById(id: string): TenantApiKeyRecord | undefined {
    return this.db
      .prepare('SELECT * FROM tenant_api_keys WHERE id = ? LIMIT 1')
      .get(id) as TenantApiKeyRecord | undefined;
  }

  public listTenantApiKeys(tenantId: string): TenantApiKeyRecord[] {
    return this.db
      .prepare('SELECT * FROM tenant_api_keys WHERE tenant_id = ? ORDER BY created_at DESC, id ASC')
      .all(tenantId) as unknown as TenantApiKeyRecord[];
  }

  public touchTenantApiKeyLastUsed(id: string, usedAtIso: string): boolean {
    const result = this.db
      .prepare('UPDATE tenant_api_keys SET last_used_at = ? WHERE id = ?')
      .run(usedAtIso, id);
    return Number(result.changes) > 0;
  }

  public revokeTenantApiKey(id: string, tenantId?: string): boolean {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const now = new Date().toISOString();
      const result = tenantId
        ? this.db
            .prepare(
              `UPDATE tenant_api_keys SET status = 'revoked', revoked_at = ?
               WHERE id = ? AND tenant_id = ? AND status = 'active'`,
            )
            .run(now, id, tenantId)
        : this.db
            .prepare(
              `UPDATE tenant_api_keys SET status = 'revoked', revoked_at = ?
               WHERE id = ? AND status = 'active'`,
            )
            .run(now, id);

      const revoked = Number(result.changes) > 0;
      if (revoked) {
        this.insertOutboxEvent('api_key.revoked', id, { id, tenant_id: tenantId ?? null, revoked_at: now });
      }
      this.db.exec('COMMIT');
      return revoked;
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  public registerServicePrincipal(input: {
    name: string;
    clientId: string;
    clientSecret: string;
    scopes: string[];
  }): ServicePrincipalRecord {
    this.db.exec('BEGIN IMMEDIATE');
    try {
      const now = new Date().toISOString();
      const secretHash = hashSecretSha256(input.clientSecret);
      const scopesText = input.scopes.join(' ');

      this.db
        .prepare(
          `INSERT INTO service_principals (client_id, name, secret_hash, scopes, status, created_at)
           VALUES (?, ?, ?, ?, 'active', ?)`,
        )
        .run(input.clientId, input.name, secretHash, scopesText, now);

      const clientPayload = JSON.stringify({
        client_id: input.clientId,
        client_secret: input.clientSecret,
        grant_types: ['client_credentials'],
        response_types: [],
        redirect_uris: [],
        token_endpoint_auth_method: 'client_secret_basic',
        scope: scopesText,
      });

      this.db
        .prepare(
          `INSERT OR REPLACE INTO oidc_store (id, kind, payload, grant_id, user_code, uid, expires_at, consumed_at)
           VALUES (?, 'Client', ?, NULL, NULL, NULL, NULL, NULL)`,
        )
        .run(`Client:${input.clientId}`, clientPayload);

      this.insertOutboxEvent('account.created', input.clientId, {
        client_id: input.clientId,
        name: input.name,
        principal_type: 'service_principal',
        scopes: input.scopes,
      });

      this.db.exec('COMMIT');

      return {
        client_id: input.clientId,
        name: input.name,
        secret_hash: secretHash,
        scopes: scopesText,
        status: 'active',
        created_at: now,
      };
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  public insertOutboxEvent(
    eventType: OutboxEventType,
    subject: string,
    payload: Record<string, unknown>,
  ): number {
    const now = new Date().toISOString();
    const result = this.db
      .prepare(
        `INSERT INTO identity_outbox (event_type, subject, payload, created_at, acked_at)
         VALUES (?, ?, ?, ?, NULL)`,
      )
      .run(eventType, subject, JSON.stringify(payload), now);
    return Number(result.lastInsertRowid);
  }

  public listOutboxEvents(onlyUnacked: boolean = true): OutboxEventRecord[] {
    const sql = onlyUnacked
      ? 'SELECT * FROM identity_outbox WHERE acked_at IS NULL ORDER BY id ASC'
      : 'SELECT * FROM identity_outbox ORDER BY id ASC';
    const rows = this.db.prepare(sql).all() as Array<{
      id: number;
      event_type: OutboxEventType;
      subject: string;
      payload: string;
      created_at: string;
      acked_at: string | null;
    }>;

    return rows.map((row) => ({
      id: row.id,
      event_type: row.event_type,
      subject: row.subject,
      payload: JSON.parse(row.payload) as Record<string, unknown>,
      created_at: row.created_at,
      acked_at: row.acked_at,
    }));
  }

  public ackOutboxEvent(eventId: number): boolean {
    const now = new Date().toISOString();
    const result = this.db
      .prepare('UPDATE identity_outbox SET acked_at = ? WHERE id = ? AND acked_at IS NULL')
      .run(now, eventId);
    return Number(result.changes) > 0;
  }

  public revokeJti(input: {
    jti: string;
    kid?: string | null;
    sub?: string | null;
    reason?: string | null;
    expiresAt?: number | null;
    revokedAt?: string;
  }): { record: RevokedJtiRecord; created: boolean } {
    const jti = input.jti.trim();
    if (!jti) {
      throw new Error('jti is required.');
    }

    this.db.exec('BEGIN IMMEDIATE');
    try {
      const existing = this.db
        .prepare('SELECT * FROM revoked_jtis WHERE jti = ? LIMIT 1')
        .get(jti) as RevokedJtiRecord | undefined;

      if (existing) {
        this.db.exec('COMMIT');
        return { record: existing, created: false };
      }

      const now = input.revokedAt ?? new Date().toISOString();
      const kid = input.kid ?? null;
      const sub = input.sub ?? null;
      const reason = input.reason ?? null;
      const expiresAt =
        typeof input.expiresAt === 'number' && Number.isFinite(input.expiresAt)
          ? Math.floor(input.expiresAt)
          : null;

      const insertResult = this.db
        .prepare(
          `INSERT INTO revoked_jtis (jti, kid, sub, reason, expires_at, revoked_at)
           VALUES (?, ?, ?, ?, ?, ?)`,
        )
        .run(jti, kid, sub, reason, expiresAt, now);

      const seq = Number(insertResult.lastInsertRowid);

      this.insertOutboxEvent('jti.revoked', jti, {
        seq,
        jti,
        kid,
        sub,
        reason,
        expires_at: expiresAt,
        revoked_at: now,
      });

      this.db.exec('COMMIT');

      return {
        created: true,
        record: {
          seq,
          jti,
          kid,
          sub,
          reason,
          expires_at: expiresAt,
          revoked_at: now,
        },
      };
    } catch (error) {
      this.db.exec('ROLLBACK');
      throw error;
    }
  }

  public findRevokedJti(jti: string): RevokedJtiRecord | undefined {
    const trimmed = jti.trim();
    if (!trimmed) {
      return undefined;
    }
    return this.db
      .prepare('SELECT * FROM revoked_jtis WHERE jti = ? LIMIT 1')
      .get(trimmed) as RevokedJtiRecord | undefined;
  }

  public isJtiRevoked(jti: string): boolean {
    const trimmed = jti.trim();
    if (!trimmed) {
      return false;
    }
    const row = this.db
      .prepare('SELECT 1 AS found FROM revoked_jtis WHERE jti = ? LIMIT 1')
      .get(trimmed) as { found: number } | undefined;
    return row !== undefined;
  }

  public listRevokedJtis(options: {
    sinceSeq?: number;
    sinceRevokedAt?: string;
    limit?: number;
    includeExpired?: boolean;
    nowEpochSeconds?: number;
  } = {}): RevokedJtiRecord[] {
    const clauses: string[] = [];
    const params: Array<number | string> = [];

    if (options.sinceSeq !== undefined && Number.isFinite(options.sinceSeq)) {
      clauses.push('seq > ?');
      params.push(Math.max(0, Math.floor(options.sinceSeq)));
    }

    if (options.sinceRevokedAt && options.sinceRevokedAt.trim().length > 0) {
      clauses.push('revoked_at > ?');
      params.push(options.sinceRevokedAt.trim());
    }

    if (!options.includeExpired) {
      const nowEpoch = options.nowEpochSeconds ?? Math.floor(Date.now() / 1000);
      clauses.push('(expires_at IS NULL OR expires_at >= ?)');
      params.push(nowEpoch);
    }

    const whereSql = clauses.length > 0 ? `WHERE ${clauses.join(' AND ')}` : '';
    const rawLimit = options.limit ?? 500;
    const boundedLimit = Math.min(1000, Math.max(1, Math.floor(rawLimit)));
    params.push(boundedLimit);

    return this.db
      .prepare(`SELECT * FROM revoked_jtis ${whereSql} ORDER BY seq ASC LIMIT ?`)
      .all(...params) as unknown as RevokedJtiRecord[];
  }

  public pruneExpiredRevokedJtis(nowEpochSeconds: number = Math.floor(Date.now() / 1000)): number {
    const result = this.db
      .prepare('DELETE FROM revoked_jtis WHERE expires_at IS NOT NULL AND expires_at < ?')
      .run(nowEpochSeconds);
    return Number(result.changes);
  }

  public close(): void {
    this.db.close();
  }
}
