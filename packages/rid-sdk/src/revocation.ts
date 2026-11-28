export interface RevokedJtiEntry {
  seq: number;
  jti: string;
  kid: string | null;
  sub: string | null;
  reason: string | null;
  expiresAt: number | null;
  revokedAt: string;
}

export interface RevocationSyncResponse {
  revocations: RevokedJtiEntry[];
  cursor: number;
  syncedAt: string;
}

export interface CheckJtiRevokedOptions {
  jti: string;
  revocationCheckUri: string;
  headers?: Record<string, string>;
  fetchImpl?: typeof fetch;
}

export interface CheckJtiRevokedResult {
  revoked: boolean;
  jti: string;
  revocation: RevokedJtiEntry | null;
}

export interface CreateRevocationSyncClientOptions {
  revocationsUri: string;
  headers?: Record<string, string>;
  fetchImpl?: typeof fetch;
  initialCursor?: number;
  limit?: number;
}

export interface RevocationSyncSummary {
  added: number;
  cursor: number;
  total: number;
  syncedAt: string;
}

export interface RevocationSyncClient {
  sync: () => Promise<RevocationSyncSummary>;
  isRevoked: (jti: string) => boolean;
  getEntry: (jti: string) => RevokedJtiEntry | undefined;
  getCursor: () => number;
  size: () => number;
  list: () => RevokedJtiEntry[];
  clear: () => void;
}

export async function checkJtiRevoked(
  options: CheckJtiRevokedOptions,
): Promise<CheckJtiRevokedResult> {
  const jti = options.jti.trim();
  if (!jti) {
    throw new Error('jti must be a non-empty string');
  }

  const fetchFn = options.fetchImpl ?? fetch;
  const response = await fetchFn(options.revocationCheckUri, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...options.headers,
    },
    body: JSON.stringify({ jti }),
  });

  if (!response.ok) {
    throw new Error(`Revocation check failed with HTTP ${response.status}`);
  }

  const payload = (await response.json()) as Partial<CheckJtiRevokedResult>;
  if (typeof payload.revoked !== 'boolean') {
    throw new Error('Invalid revocation check response payload');
  }

  return {
    revoked: payload.revoked,
    jti: typeof payload.jti === 'string' ? payload.jti : jti,
    revocation: payload.revocation ?? null,
  };
}

export function createRevocationSyncClient(
  options: CreateRevocationSyncClientOptions,
): RevocationSyncClient {
  const fetchFn = options.fetchImpl ?? fetch;
  const entries = new Map<string, RevokedJtiEntry>();
  let cursor =
    typeof options.initialCursor === 'number' && Number.isFinite(options.initialCursor)
      ? Math.max(0, Math.floor(options.initialCursor))
      : 0;

  return {
    async sync(): Promise<RevocationSyncSummary> {
      const targetUrl = new URL(options.revocationsUri);
      targetUrl.searchParams.set('since', String(cursor));
      if (typeof options.limit === 'number' && Number.isFinite(options.limit) && options.limit > 0) {
        targetUrl.searchParams.set('limit', String(Math.floor(options.limit)));
      }

      const response = await fetchFn(targetUrl.toString(), {
        method: 'GET',
        headers: {
          accept: 'application/json',
          ...options.headers,
        },
      });

      if (!response.ok) {
        throw new Error(`Revocation sync failed with HTTP ${response.status}`);
      }

      const payload = (await response.json()) as Partial<RevocationSyncResponse>;
      if (!Array.isArray(payload.revocations)) {
        throw new Error('Invalid revocation sync response payload');
      }

      let added = 0;
      for (const entry of payload.revocations) {
        if (entry && typeof entry.jti === 'string' && entry.jti.trim().length > 0) {
          if (!entries.has(entry.jti)) {
            added += 1;
          }
          entries.set(entry.jti, entry);
        }
      }

      if (typeof payload.cursor === 'number' && Number.isFinite(payload.cursor)) {
        cursor = Math.max(cursor, Math.floor(payload.cursor));
      }

      return {
        added,
        cursor,
        total: entries.size,
        syncedAt: typeof payload.syncedAt === 'string' ? payload.syncedAt : new Date().toISOString(),
      };
    },
    isRevoked(jti: string): boolean {
      const trimmed = jti.trim();
      if (!trimmed) {
        return false;
      }
      return entries.has(trimmed);
    },
    getEntry(jti: string): RevokedJtiEntry | undefined {
      return entries.get(jti.trim());
    },
    getCursor(): number {
      return cursor;
    },
    size(): number {
      return entries.size;
    },
    list(): RevokedJtiEntry[] {
      return Array.from(entries.values());
    },
    clear(): void {
      entries.clear();
      cursor = 0;
    },
  };
}
