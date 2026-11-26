import type { Adapter, AdapterConstructor, AdapterPayload } from 'oidc-provider';
import type { IdentityDatabase } from './sqlite.js';

export function createSqliteAdapterFactory(identityDb: IdentityDatabase): AdapterConstructor {
  return class SqliteOidcAdapter implements Adapter {
    readonly kind: string;

    constructor(name: string) {
      this.kind = name;
    }

    key(id: string): string {
      return `${this.kind}:${id}`;
    }

    async upsert(id: string, payload: AdapterPayload, expiresIn: number): Promise<void> {
      const expiresAt = expiresIn ? Math.floor(Date.now() / 1000) + expiresIn : null;
      const grantId = typeof payload.grantId === 'string' ? payload.grantId : null;
      const userCode = typeof payload.userCode === 'string' ? payload.userCode : null;
      const uid = typeof payload.uid === 'string' ? payload.uid : null;

      identityDb.db
        .prepare(
          `INSERT OR REPLACE INTO oidc_store
           (id, kind, payload, grant_id, user_code, uid, expires_at, consumed_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, NULL)`,
        )
        .run(
          this.key(id),
          this.kind,
          JSON.stringify(payload),
          grantId,
          userCode,
          uid,
          expiresAt,
        );
    }

    async find(id: string): Promise<AdapterPayload | undefined> {
      const row = identityDb.db
        .prepare('SELECT payload, expires_at, consumed_at FROM oidc_store WHERE id = ?')
        .get(this.key(id)) as
        | { payload: string; expires_at: number | null; consumed_at: number | null }
        | undefined;

      if (!row) {
        return undefined;
      }

      if (row.expires_at !== null && row.expires_at < Math.floor(Date.now() / 1000)) {
        return undefined;
      }

      const parsed = JSON.parse(row.payload) as AdapterPayload;
      if (row.consumed_at !== null) {
        parsed.consumed = row.consumed_at;
      }
      return parsed;
    }

    async findByUserCode(userCode: string): Promise<AdapterPayload | undefined> {
      const row = identityDb.db
        .prepare(
          'SELECT payload, expires_at, consumed_at FROM oidc_store WHERE kind = ? AND user_code = ?',
        )
        .get(this.kind, userCode) as
        | { payload: string; expires_at: number | null; consumed_at: number | null }
        | undefined;

      if (!row) {
        return undefined;
      }
      if (row.expires_at !== null && row.expires_at < Math.floor(Date.now() / 1000)) {
        return undefined;
      }
      const parsed = JSON.parse(row.payload) as AdapterPayload;
      if (row.consumed_at !== null) {
        parsed.consumed = row.consumed_at;
      }
      return parsed;
    }

    async findByUid(uid: string): Promise<AdapterPayload | undefined> {
      const row = identityDb.db
        .prepare(
          'SELECT payload, expires_at, consumed_at FROM oidc_store WHERE kind = ? AND uid = ?',
        )
        .get(this.kind, uid) as
        | { payload: string; expires_at: number | null; consumed_at: number | null }
        | undefined;

      if (!row) {
        return undefined;
      }
      if (row.expires_at !== null && row.expires_at < Math.floor(Date.now() / 1000)) {
        return undefined;
      }
      const parsed = JSON.parse(row.payload) as AdapterPayload;
      if (row.consumed_at !== null) {
        parsed.consumed = row.consumed_at;
      }
      return parsed;
    }

    async consume(id: string): Promise<void> {
      const consumedAt = Math.floor(Date.now() / 1000);
      identityDb.db
        .prepare('UPDATE oidc_store SET consumed_at = ? WHERE id = ?')
        .run(consumedAt, this.key(id));
    }

    async destroy(id: string): Promise<void> {
      identityDb.db.prepare('DELETE FROM oidc_store WHERE id = ?').run(this.key(id));
    }

    async revokeByGrantId(grantId: string): Promise<void> {
      identityDb.db.prepare('DELETE FROM oidc_store WHERE grant_id = ?').run(grantId);
      identityDb.insertOutboxEvent('grant.revoked', grantId, { grant_id: grantId });
    }
  };
}
