import { readFileSync } from 'node:fs';
import {
  calculateJwkThumbprint,
  exportJWK,
  generateKeyPair,
  importPKCS8,
  type JWK,
} from 'jose';

export interface SigningKeySet {
  keys: JWK[];
}

export interface LoadSigningKeysOptions {
  nodeEnv?: string;
  signingKeyPem?: string;
  signingKeyPath?: string;
  previousSigningKeyPem?: string;
  previousSigningKeyPath?: string;
  graceWindowSeconds?: number;
  allowEphemeralKeys?: boolean;
  nowMs?: number;
}

export interface SigningKeyEntry {
  kid: string;
  privateJwk: JWK;
  publicJwk: JWK;
  createdAt: string;
  graceExpiresAtMs?: number;
}

export interface RotateSigningKeyOptions {
  signingKeyPem?: string;
  signingKeyPath?: string;
  graceWindowSeconds?: number;
  nowMs?: number;
}

export interface KeyRotationResult {
  activeKid: string;
  previousKid: string | null;
  graceExpiresAt: string | null;
  kids: string[];
}

export interface KeyRotationStatus {
  activeKid: string;
  previousKid: string | null;
  graceExpiresAt: string | null;
  kids: string[];
}

const DEFAULT_GRACE_WINDOW_SECONDS = 3600;

function resolvePem(pemValue?: string, pemPath?: string): string | undefined {
  if (pemValue && pemValue.trim().length > 0) {
    return pemValue.replace(/\\n/g, '\n');
  }
  if (pemPath && pemPath.trim().length > 0) {
    return readFileSync(pemPath, 'utf8');
  }
  return undefined;
}

export function toPublicJwk(jwk: JWK): JWK {
  return {
    kty: jwk.kty,
    use: jwk.use ?? 'sig',
    kid: jwk.kid,
    alg: jwk.alg ?? 'RS256',
    e: jwk.e,
    n: jwk.n,
  };
}

async function importRs256KeyEntry(
  pem: string,
  createdAtMs: number,
  graceExpiresAtMs?: number,
): Promise<SigningKeyEntry> {
  const privateKey = await importPKCS8(pem, 'RS256', { extractable: true });
  const privateJwk = await exportJWK(privateKey);
  const kid = await calculateJwkThumbprint(privateJwk, 'sha256');
  const fullPrivateJwk: JWK = {
    ...privateJwk,
    alg: 'RS256',
    use: 'sig',
    kid,
  };
  return {
    kid,
    privateJwk: fullPrivateJwk,
    publicJwk: toPublicJwk(fullPrivateJwk),
    createdAt: new Date(createdAtMs).toISOString(),
    graceExpiresAtMs,
  };
}

async function generateRs256KeyEntry(createdAtMs: number): Promise<SigningKeyEntry> {
  const { privateKey } = await generateKeyPair('RS256', { extractable: true });
  const privateJwk = await exportJWK(privateKey);
  const kid = await calculateJwkThumbprint(privateJwk, 'sha256');
  const fullPrivateJwk: JWK = {
    ...privateJwk,
    alg: 'RS256',
    use: 'sig',
    kid,
  };
  return {
    kid,
    privateJwk: fullPrivateJwk,
    publicJwk: toPublicJwk(fullPrivateJwk),
    createdAt: new Date(createdAtMs).toISOString(),
  };
}

function resolveGraceWindowSeconds(
  explicitSeconds?: number,
  fallbackSeconds: number = DEFAULT_GRACE_WINDOW_SECONDS,
): number {
  if (explicitSeconds === undefined) {
    return fallbackSeconds;
  }
  if (!Number.isFinite(explicitSeconds) || explicitSeconds < 0) {
    throw new Error('graceWindowSeconds must be a non-negative finite number.');
  }
  return explicitSeconds;
}

export class SigningKeyManager {
  private active: SigningKeyEntry;
  private previous: SigningKeyEntry | null;
  private readonly defaultGraceWindowSeconds: number;

  constructor(
    active: SigningKeyEntry,
    previous: SigningKeyEntry | null = null,
    defaultGraceWindowSeconds: number = DEFAULT_GRACE_WINDOW_SECONDS,
  ) {
    this.active = active;
    this.previous = previous;
    this.defaultGraceWindowSeconds = resolveGraceWindowSeconds(defaultGraceWindowSeconds);
  }

  private getValidPrevious(nowMs: number = Date.now()): SigningKeyEntry | null {
    if (!this.previous) {
      return null;
    }
    if (
      this.previous.graceExpiresAtMs !== undefined &&
      nowMs > this.previous.graceExpiresAtMs
    ) {
      this.previous = null;
      return null;
    }
    return this.previous;
  }

  public getActiveKid(): string {
    return this.active.kid;
  }

  public getPreviousKid(nowMs: number = Date.now()): string | null {
    return this.getValidPrevious(nowMs)?.kid ?? null;
  }

  public getKeyStatus(nowMs: number = Date.now()): KeyRotationStatus {
    const validPrevious = this.getValidPrevious(nowMs);
    return {
      activeKid: this.active.kid,
      previousKid: validPrevious?.kid ?? null,
      graceExpiresAt:
        validPrevious?.graceExpiresAtMs !== undefined
          ? new Date(validPrevious.graceExpiresAtMs).toISOString()
          : null,
      kids: validPrevious ? [this.active.kid, validPrevious.kid] : [this.active.kid],
    };
  }

  public getOidcJwks(nowMs: number = Date.now()): SigningKeySet {
    const validPrevious = this.getValidPrevious(nowMs);
    return {
      keys: validPrevious
        ? [this.active.privateJwk, validPrevious.privateJwk]
        : [this.active.privateJwk],
    };
  }

  public getPublicJwks(nowMs: number = Date.now()): SigningKeySet {
    const validPrevious = this.getValidPrevious(nowMs);
    return {
      keys: validPrevious
        ? [this.active.publicJwk, validPrevious.publicJwk]
        : [this.active.publicJwk],
    };
  }

  public async rotateKey(options: RotateSigningKeyOptions = {}): Promise<KeyRotationResult> {
    const nowMs = options.nowMs ?? Date.now();
    const graceWindowSeconds = resolveGraceWindowSeconds(
      options.graceWindowSeconds,
      this.defaultGraceWindowSeconds,
    );

    const nextPem = resolvePem(options.signingKeyPem, options.signingKeyPath);
    const nextActive = nextPem
      ? await importRs256KeyEntry(nextPem, nowMs)
      : await generateRs256KeyEntry(nowMs);

    if (nextActive.kid === this.active.kid) {
      throw new Error('New signing key must differ from the current active signing key.');
    }

    if (graceWindowSeconds > 0) {
      const graceExpiresAtMs = nowMs + graceWindowSeconds * 1000;
      this.previous = {
        ...this.active,
        graceExpiresAtMs,
      };
    } else {
      this.previous = null;
    }

    this.active = nextActive;

    return this.getKeyStatus(nowMs);
  }

  public expireGraceKey(): boolean {
    if (!this.previous) {
      return false;
    }
    this.previous = null;
    return true;
  }
}

export async function createSigningKeyManager(
  options: LoadSigningKeysOptions = {},
): Promise<SigningKeyManager> {
  const nowMs = options.nowMs ?? Date.now();
  const nodeEnv = options.nodeEnv ?? process.env.NODE_ENV ?? 'development';
  const isProduction = nodeEnv === 'production';

  const envGraceRaw = process.env.MW_RID_KEY_ROTATION_GRACE_SECONDS;
  const envGraceSeconds =
    envGraceRaw !== undefined && envGraceRaw.trim().length > 0
      ? Number(envGraceRaw)
      : undefined;
  const defaultGraceWindowSeconds = resolveGraceWindowSeconds(
    options.graceWindowSeconds ?? envGraceSeconds,
    DEFAULT_GRACE_WINDOW_SECONDS,
  );

  const activePem = resolvePem(
    options.signingKeyPem ?? process.env.MW_RID_SIGNING_KEY_PEM,
    options.signingKeyPath ?? process.env.MW_RID_SIGNING_KEY_PATH,
  );

  let activeEntry: SigningKeyEntry;
  if (activePem) {
    activeEntry = await importRs256KeyEntry(activePem, nowMs);
  } else {
    if (isProduction) {
      throw new Error(
        'Fail-closed: MW_RID_SIGNING_KEY_PEM or MW_RID_SIGNING_KEY_PATH is required in production.',
      );
    }

    const allowEphemeral =
      options.allowEphemeralKeys ??
      (nodeEnv === 'test' || process.env.MW_RID_ALLOW_EPHEMERAL_KEYS === '1');

    if (!allowEphemeral) {
      throw new Error(
        'Fail-closed: No signing key configured. Set MW_RID_SIGNING_KEY_PEM or MW_RID_ALLOW_EPHEMERAL_KEYS=1 for non-production.',
      );
    }

    activeEntry = await generateRs256KeyEntry(nowMs);
  }

  const previousPem = resolvePem(
    options.previousSigningKeyPem ?? process.env.MW_RID_PREVIOUS_SIGNING_KEY_PEM,
    options.previousSigningKeyPath ?? process.env.MW_RID_PREVIOUS_SIGNING_KEY_PATH,
  );

  let previousEntry: SigningKeyEntry | null = null;
  if (previousPem && defaultGraceWindowSeconds > 0) {
    const candidate = await importRs256KeyEntry(
      previousPem,
      nowMs,
      nowMs + defaultGraceWindowSeconds * 1000,
    );
    if (candidate.kid !== activeEntry.kid) {
      previousEntry = candidate;
    }
  }

  return new SigningKeyManager(activeEntry, previousEntry, defaultGraceWindowSeconds);
}

export async function loadSigningKeys(
  options: LoadSigningKeysOptions = {},
): Promise<SigningKeySet> {
  const manager = await createSigningKeyManager(options);
  return manager.getOidcJwks(options.nowMs ?? Date.now());
}
