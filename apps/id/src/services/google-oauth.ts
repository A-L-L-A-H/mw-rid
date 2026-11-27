import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import type { AccountRecord, IdentityDatabase } from '../storage/sqlite.js';

export const DEFAULT_GOOGLE_STATE_TTL_MS = 10 * 60 * 1000;
const GOOGLE_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token';
const GOOGLE_USERINFO_URL = 'https://openidconnect.googleapis.com/v1/userinfo';

export interface GoogleOAuthConfig {
  clientId?: string;
  clientSecret?: string;
  redirectUri?: string;
  stateSecret?: string;
  allowedHostedDomain?: string;
  stateTtlMs?: number;
  nodeEnv?: string;
  fetchImpl?: typeof fetch;
  authBaseUrl?: string;
  tokenUrl?: string;
  userInfoUrl?: string;
}

export interface GoogleUserProfile {
  sub: string;
  email: string;
  email_verified: boolean;
  name?: string;
  given_name?: string;
  family_name?: string;
  picture?: string;
  hd?: string;
}

export interface GoogleTokenResponse {
  access_token: string;
  token_type?: string;
  expires_in?: number;
  scope?: string;
  id_token?: string;
  refresh_token?: string;
}

export interface GoogleAuthUrlInput {
  nonce?: string;
  loginHint?: string;
  nowMs?: number;
}

export interface GoogleAuthUrlResult {
  url: string;
  state: string;
  expiresAt: string;
}

export type GoogleStateVerifyResult =
  | {
      valid: true;
      nonce: string;
      exp: number;
    }
  | {
      valid: false;
      reason: 'invalid_state' | 'invalid_signature' | 'expired';
    };

export interface GoogleCallbackInput {
  code: string;
  state: string;
  identityDb: IdentityDatabase;
  nowMs?: number;
}

export interface GoogleCallbackResult {
  account: AccountRecord;
  profile: GoogleUserProfile;
  created: boolean;
  linked: boolean;
}

interface GoogleStatePayload {
  nonce: string;
  exp: number;
}

export class GoogleOAuthError extends Error {
  public readonly code: string;
  public readonly statusCode: number;

  constructor(code: string, message: string, statusCode: number = 400) {
    super(message);
    this.name = 'GoogleOAuthError';
    this.code = code;
    this.statusCode = statusCode;
  }
}

export class GoogleOAuthService {
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly redirectUri: string;
  private readonly stateSecret: string;
  private readonly allowedHostedDomain: string | null;
  private readonly stateTtlMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly authBaseUrl: string;
  private readonly tokenUrl: string;
  private readonly userInfoUrl: string;

  constructor(options: GoogleOAuthConfig = {}) {
    const nodeEnv = options.nodeEnv ?? process.env.NODE_ENV ?? 'development';
    this.clientId = (options.clientId ?? process.env.MW_RID_GOOGLE_CLIENT_ID ?? '').trim();
    this.clientSecret = (options.clientSecret ?? process.env.MW_RID_GOOGLE_CLIENT_SECRET ?? '').trim();
    this.redirectUri = (options.redirectUri ?? process.env.MW_RID_GOOGLE_REDIRECT_URI ?? '').trim();

    const configuredStateSecret =
      options.stateSecret !== undefined
        ? options.stateSecret
        : (process.env.MW_RID_GOOGLE_STATE_SECRET ?? '');

    if (
      nodeEnv === 'production' &&
      this.isConfigured() &&
      configuredStateSecret.trim().length === 0
    ) {
      throw new Error(
        'Fail-closed: MW_RID_GOOGLE_STATE_SECRET is required in production when Google OAuth is configured.',
      );
    }

    this.stateSecret =
      configuredStateSecret.trim().length > 0
        ? configuredStateSecret.trim()
        : randomBytes(32).toString('base64url');

    const rawHd = (options.allowedHostedDomain ?? process.env.MW_RID_GOOGLE_HOSTED_DOMAIN ?? '').trim();
    this.allowedHostedDomain = rawHd.length > 0 ? rawHd.toLowerCase() : null;
    this.stateTtlMs = options.stateTtlMs ?? DEFAULT_GOOGLE_STATE_TTL_MS;
    if (!Number.isFinite(this.stateTtlMs) || this.stateTtlMs <= 0) {
      throw new Error('Google OAuth stateTtlMs must be a positive finite number.');
    }
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch;
    this.authBaseUrl = options.authBaseUrl ?? GOOGLE_AUTH_URL;
    this.tokenUrl = options.tokenUrl ?? GOOGLE_TOKEN_URL;
    this.userInfoUrl = options.userInfoUrl ?? GOOGLE_USERINFO_URL;
  }

  public isConfigured(): boolean {
    return this.clientId.length > 0 && this.clientSecret.length > 0 && this.redirectUri.length > 0;
  }

  public buildAuthorizationUrl(input: GoogleAuthUrlInput = {}): GoogleAuthUrlResult {
    if (!this.isConfigured()) {
      throw new GoogleOAuthError(
        'google_oauth_not_configured',
        'Google OAuth is not configured.',
        503,
      );
    }

    const nowMs = input.nowMs ?? Date.now();
    const exp = nowMs + this.stateTtlMs;
    const nonce = (input.nonce ?? randomBytes(16).toString('base64url')).trim();
    const payload: GoogleStatePayload = { nonce, exp };
    const encodedPayload = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    const signingInput = `v1.${encodedPayload}`;
    const signature = this.sign(signingInput);
    const state = `${signingInput}.${signature}`;

    const authUrl = new URL(this.authBaseUrl);
    authUrl.searchParams.set('client_id', this.clientId);
    authUrl.searchParams.set('redirect_uri', this.redirectUri);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('scope', 'openid email profile');
    authUrl.searchParams.set('access_type', 'offline');
    authUrl.searchParams.set('prompt', 'select_account');
    authUrl.searchParams.set('state', state);

    if (input.loginHint && input.loginHint.trim().length > 0) {
      authUrl.searchParams.set('login_hint', input.loginHint.trim());
    }
    if (this.allowedHostedDomain) {
      authUrl.searchParams.set('hd', this.allowedHostedDomain);
    }

    return {
      url: authUrl.toString(),
      state,
      expiresAt: new Date(exp).toISOString(),
    };
  }

  public verifyState(state: string, nowMs: number = Date.now()): GoogleStateVerifyResult {
    if (typeof state !== 'string' || state.trim().length === 0) {
      return { valid: false, reason: 'invalid_state' };
    }

    const parts = state.split('.');
    if (parts.length !== 3 || parts[0] !== 'v1' || !parts[1] || !parts[2]) {
      return { valid: false, reason: 'invalid_state' };
    }

    const [, encodedPayload, providedSig] = parts;
    const expectedSig = this.sign(`v1.${encodedPayload}`);
    if (!this.constantTimeEqualBase64Url(providedSig, expectedSig)) {
      return { valid: false, reason: 'invalid_signature' };
    }

    let payload: GoogleStatePayload;
    try {
      const parsed = JSON.parse(
        Buffer.from(encodedPayload, 'base64url').toString('utf8'),
      ) as Partial<GoogleStatePayload>;
      if (typeof parsed.nonce !== 'string' || parsed.nonce.length === 0 || typeof parsed.exp !== 'number') {
        return { valid: false, reason: 'invalid_state' };
      }
      payload = parsed as GoogleStatePayload;
    } catch {
      return { valid: false, reason: 'invalid_state' };
    }

    if (nowMs > payload.exp) {
      return { valid: false, reason: 'expired' };
    }

    return {
      valid: true,
      nonce: payload.nonce,
      exp: payload.exp,
    };
  }

  public async exchangeCode(code: string): Promise<GoogleTokenResponse> {
    if (!this.isConfigured()) {
      throw new GoogleOAuthError(
        'google_oauth_not_configured',
        'Google OAuth is not configured.',
        503,
      );
    }

    const trimmedCode = code.trim();
    if (!trimmedCode) {
      throw new GoogleOAuthError('invalid_code', 'Authorization code is required.', 400);
    }

    const response = await this.fetchImpl(this.tokenUrl, {
      method: 'POST',
      headers: {
        'content-type': 'application/x-www-form-urlencoded',
      },
      body: new URLSearchParams({
        code: trimmedCode,
        client_id: this.clientId,
        client_secret: this.clientSecret,
        redirect_uri: this.redirectUri,
        grant_type: 'authorization_code',
      }).toString(),
    });

    if (!response.ok) {
      const detail = await response.text().catch(() => '');
      throw new GoogleOAuthError(
        'google_token_exchange_failed',
        `Google token exchange failed (${response.status}): ${detail}`,
        502,
      );
    }

    const tokenPayload = (await response.json()) as Partial<GoogleTokenResponse>;
    if (typeof tokenPayload.access_token !== 'string' || tokenPayload.access_token.length === 0) {
      throw new GoogleOAuthError(
        'google_token_missing',
        'Google token response did not include access_token.',
        502,
      );
    }

    return tokenPayload as GoogleTokenResponse;
  }

  public async fetchUserInfo(accessToken: string): Promise<GoogleUserProfile> {
    const token = accessToken.trim();
    if (!token) {
      throw new GoogleOAuthError('invalid_access_token', 'Access token is required.', 400);
    }

    const response = await this.fetchImpl(this.userInfoUrl, {
      method: 'GET',
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    if (!response.ok) {
      const detail = await response.text().catch(() => '');
      throw new GoogleOAuthError(
        'google_userinfo_failed',
        `Google userinfo request failed (${response.status}): ${detail}`,
        502,
      );
    }

    const rawProfile = (await response.json()) as Partial<GoogleUserProfile>;
    if (typeof rawProfile.sub !== 'string' || rawProfile.sub.trim().length === 0) {
      throw new GoogleOAuthError('invalid_google_profile', 'Google profile is missing sub.', 401);
    }
    if (typeof rawProfile.email !== 'string' || rawProfile.email.trim().length === 0) {
      throw new GoogleOAuthError('invalid_google_profile', 'Google profile is missing email.', 401);
    }
    if (rawProfile.email_verified !== true) {
      throw new GoogleOAuthError(
        'email_not_verified',
        'Google account email_verified must be true.',
        401,
      );
    }

    const normalizedHd =
      typeof rawProfile.hd === 'string' && rawProfile.hd.trim().length > 0
        ? rawProfile.hd.trim().toLowerCase()
        : undefined;

    if (this.allowedHostedDomain && normalizedHd !== this.allowedHostedDomain) {
      throw new GoogleOAuthError(
        'hosted_domain_forbidden',
        `Google hosted domain does not match required domain (${this.allowedHostedDomain}).`,
        403,
      );
    }

    return {
      sub: rawProfile.sub.trim(),
      email: rawProfile.email.trim().toLowerCase(),
      email_verified: true,
      name: typeof rawProfile.name === 'string' ? rawProfile.name.trim() : undefined,
      given_name: typeof rawProfile.given_name === 'string' ? rawProfile.given_name.trim() : undefined,
      family_name:
        typeof rawProfile.family_name === 'string' ? rawProfile.family_name.trim() : undefined,
      picture: typeof rawProfile.picture === 'string' ? rawProfile.picture.trim() : undefined,
      hd: normalizedHd,
    };
  }

  public async authenticateCallback(input: GoogleCallbackInput): Promise<GoogleCallbackResult> {
    const stateCheck = this.verifyState(input.state, input.nowMs);
    if (!stateCheck.valid) {
      throw new GoogleOAuthError(
        'invalid_state',
        `Google OAuth state verification failed (${stateCheck.reason}).`,
        401,
      );
    }

    const tokenResponse = await this.exchangeCode(input.code);
    const profile = await this.fetchUserInfo(tokenResponse.access_token);

    try {
      const upserted = input.identityDb.upsertGoogleAccount({
        googleSub: profile.sub,
        email: profile.email,
        name: profile.name,
      });

      return {
        account: upserted.account,
        profile,
        created: upserted.created,
        linked: upserted.linked,
      };
    } catch (err) {
      if (err instanceof Error && err.message === 'ACCOUNT_DISABLED') {
        throw new GoogleOAuthError('account_disabled', 'Linked account is disabled.', 403);
      }
      throw err;
    }
  }

  private sign(input: string): string {
    return createHmac('sha256', this.stateSecret).update(input, 'utf8').digest('base64url');
  }

  private constantTimeEqualBase64Url(a: string, b: string): boolean {
    const bufA = Buffer.from(a, 'base64url');
    const bufB = Buffer.from(b, 'base64url');
    if (bufA.length === 0 || bufA.length !== bufB.length) {
      return false;
    }
    return timingSafeEqual(bufA, bufB);
  }
}

export function createGoogleOAuthService(options: GoogleOAuthConfig = {}): GoogleOAuthService {
  return new GoogleOAuthService(options);
}
