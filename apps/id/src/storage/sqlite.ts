import { randomUUID } from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import { hashPassword, hashSecretSha256, verifySecretSha256 } from '../crypto/passwords.js';

export type AccountStatus = 'active' | 'disabled';
export type AccountRole = 'platform_owner' | 'member';
export type OutboxEventType = 'account.created' | 'account.disabled' | 'grant.revoked';

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

  public close(): void {
    this.db.close();
  }
}
