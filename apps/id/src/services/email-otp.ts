import { createHmac, randomBytes, randomInt, timingSafeEqual } from 'node:crypto';
import { hashSecretSha256, verifySecretSha256 } from '../crypto/passwords.js';

export const OTP_TTL_MS = 5 * 60 * 1000;

export type EmailOtpPurpose = 'login_otp' | 'email_verify' | 'password_reset';

export const EMAIL_OTP_PURPOSES: readonly EmailOtpPurpose[] = [
  'login_otp',
  'email_verify',
  'password_reset',
];

export interface EmailOtpServiceOptions {
  secret?: string;
  nodeEnv?: string;
  resendApiKey?: string;
  resendFrom?: string;
  resendApiUrl?: string;
  ttlMs?: number;
  fetchImpl?: typeof fetch;
  logger?: (entry: Record<string, unknown>) => void;
}

export interface SendOtpInput {
  email: string;
  purpose: EmailOtpPurpose;
  nowMs?: number;
}

export interface SendOtpResult {
  delivery: 'resend' | 'console';
  token: string;
  expiresAt: string;
  messageId?: string | null;
  previewCode?: string;
}

export interface VerifyOtpInput {
  email: string;
  code: string;
  token: string;
  purpose: EmailOtpPurpose;
  nowMs?: number;
}

export type VerifyOtpResult =
  | {
      valid: true;
      email: string;
      purpose: EmailOtpPurpose;
    }
  | {
      valid: false;
      reason:
        | 'invalid_input'
        | 'invalid_token'
        | 'invalid_signature'
        | 'expired'
        | 'email_mismatch'
        | 'purpose_mismatch'
        | 'invalid_code'
        | 'already_used';
    };

interface OtpTokenPayload {
  email: string;
  purpose: EmailOtpPurpose;
  codeHash: string;
  nonce: string;
  exp: number;
}

const EMAIL_REGEX = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX_CONSUMED_NONCES = 10_000;

export function isValidEmailOtpPurpose(value: unknown): value is EmailOtpPurpose {
  return typeof value === 'string' && EMAIL_OTP_PURPOSES.includes(value as EmailOtpPurpose);
}

export function normalizeOtpEmail(email: string): string {
  return email.trim().toLowerCase();
}

export class EmailOtpService {
  private readonly secret: string;
  private readonly nodeEnv: string;
  private readonly resendApiKey: string;
  private readonly resendFrom: string;
  private readonly resendApiUrl: string;
  private readonly ttlMs: number;
  private readonly fetchImpl: typeof fetch;
  private readonly logger: (entry: Record<string, unknown>) => void;
  private readonly consumedNonces = new Map<string, number>();

  constructor(options: EmailOtpServiceOptions = {}) {
    this.nodeEnv = options.nodeEnv ?? process.env.NODE_ENV ?? 'development';
    const configuredSecret =
      options.secret !== undefined ? options.secret : process.env.MW_RID_OTP_SECRET;

    if (this.nodeEnv === 'production' && (!configuredSecret || configuredSecret.trim().length === 0)) {
      throw new Error('Fail-closed: MW_RID_OTP_SECRET is required in production.');
    }

    this.secret =
      configuredSecret && configuredSecret.trim().length > 0
        ? configuredSecret
        : randomBytes(32).toString('base64url');

    const configuredApiKey =
      options.resendApiKey !== undefined
        ? options.resendApiKey
        : (process.env.RESEND_API_KEY ?? process.env.MW_RID_RESEND_API_KEY ?? '');
    this.resendApiKey = configuredApiKey.trim();
    this.resendFrom =
      options.resendFrom ??
      process.env.MW_RID_OTP_FROM ??
      'MoonWitness ID <no-reply@moonwitness.local>';
    this.resendApiUrl =
      options.resendApiUrl ??
      process.env.MW_RID_RESEND_API_URL ??
      'https://api.resend.com/emails';
    this.ttlMs = options.ttlMs ?? OTP_TTL_MS;
    if (!Number.isFinite(this.ttlMs) || this.ttlMs <= 0) {
      throw new Error('OTP ttlMs must be a positive finite number.');
    }
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch;
    this.logger = options.logger ?? ((entry) => console.info(JSON.stringify(entry)));
  }

  public async sendOtp(input: SendOtpInput): Promise<SendOtpResult> {
    if (!isValidEmailOtpPurpose(input.purpose)) {
      throw new Error(`Invalid OTP purpose: ${String(input.purpose)}`);
    }
    const email = normalizeOtpEmail(String(input.email ?? ''));
    if (!EMAIL_REGEX.test(email)) {
      throw new Error('Valid email address is required.');
    }

    const nowMs = input.nowMs ?? Date.now();
    const exp = nowMs + this.ttlMs;
    const expiresAt = new Date(exp).toISOString();
    const code = randomInt(100_000, 1_000_000).toString();
    const nonce = randomBytes(16).toString('base64url');

    const payload: OtpTokenPayload = {
      email,
      purpose: input.purpose,
      codeHash: hashSecretSha256(code),
      nonce,
      exp,
    };

    const encodedPayload = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
    const signingInput = `v1.${encodedPayload}`;
    const signature = this.sign(signingInput);
    const token = `${signingInput}.${signature}`;

    if (this.resendApiKey.length > 0) {
      const subject = this.buildSubject(input.purpose);
      const text = `Your MoonWitness verification code is ${code}. It expires in 5 minutes (${expiresAt}).`;
      const html = `<p>Your MoonWitness verification code is <strong>${code}</strong>.</p><p>This code expires at ${expiresAt}.</p>`;

      const response = await this.fetchImpl(this.resendApiUrl, {
        method: 'POST',
        headers: {
          authorization: `Bearer ${this.resendApiKey}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          from: this.resendFrom,
          to: [email],
          subject,
          text,
          html,
        }),
      });

      if (!response.ok) {
        const errorText = await response.text().catch(() => '');
        throw new Error(`Resend email delivery failed (${response.status}): ${errorText}`);
      }

      const body = (await response.json().catch(() => ({}))) as { id?: string };
      return {
        delivery: 'resend',
        token,
        expiresAt,
        messageId: typeof body.id === 'string' ? body.id : null,
      };
    }

    this.logger({
      event: 'email_otp.console_fallback',
      email,
      purpose: input.purpose,
      code: this.nodeEnv === 'production' ? '[redacted]' : code,
      expiresAt,
      ts: new Date(nowMs).toISOString(),
    });

    const result: SendOtpResult = {
      delivery: 'console',
      token,
      expiresAt,
    };
    if (this.nodeEnv !== 'production') {
      result.previewCode = code;
    }
    return result;
  }

  public verifyOtp(input: VerifyOtpInput): VerifyOtpResult {
    const nowMs = input.nowMs ?? Date.now();
    this.pruneExpiredNonces(nowMs);

    if (
      typeof input.email !== 'string' ||
      typeof input.code !== 'string' ||
      typeof input.token !== 'string' ||
      !isValidEmailOtpPurpose(input.purpose)
    ) {
      return { valid: false, reason: 'invalid_input' };
    }

    const email = normalizeOtpEmail(input.email);
    const code = input.code.trim();
    if (!EMAIL_REGEX.test(email) || code.length === 0) {
      return { valid: false, reason: 'invalid_input' };
    }

    const parts = input.token.split('.');
    if (parts.length !== 3 || parts[0] !== 'v1' || !parts[1] || !parts[2]) {
      return { valid: false, reason: 'invalid_token' };
    }

    const [, encodedPayload, providedSig] = parts;
    const expectedSig = this.sign(`v1.${encodedPayload}`);
    if (!this.constantTimeEqualBase64Url(providedSig, expectedSig)) {
      return { valid: false, reason: 'invalid_signature' };
    }

    let payload: OtpTokenPayload;
    try {
      const parsed = JSON.parse(Buffer.from(encodedPayload, 'base64url').toString('utf8')) as Partial<OtpTokenPayload>;
      if (
        typeof parsed.email !== 'string' ||
        !isValidEmailOtpPurpose(parsed.purpose) ||
        typeof parsed.codeHash !== 'string' ||
        typeof parsed.nonce !== 'string' ||
        typeof parsed.exp !== 'number'
      ) {
        return { valid: false, reason: 'invalid_token' };
      }
      payload = parsed as OtpTokenPayload;
    } catch {
      return { valid: false, reason: 'invalid_token' };
    }

    if (nowMs > payload.exp) {
      return { valid: false, reason: 'expired' };
    }

    if (payload.email !== email) {
      return { valid: false, reason: 'email_mismatch' };
    }

    if (payload.purpose !== input.purpose) {
      return { valid: false, reason: 'purpose_mismatch' };
    }

    if (!verifySecretSha256(code, payload.codeHash)) {
      return { valid: false, reason: 'invalid_code' };
    }

    if (this.consumedNonces.has(payload.nonce)) {
      return { valid: false, reason: 'already_used' };
    }

    this.recordConsumedNonce(payload.nonce, payload.exp);

    return {
      valid: true,
      email,
      purpose: input.purpose,
    };
  }

  private sign(input: string): string {
    return createHmac('sha256', this.secret).update(input, 'utf8').digest('base64url');
  }

  private constantTimeEqualBase64Url(a: string, b: string): boolean {
    const bufA = Buffer.from(a, 'base64url');
    const bufB = Buffer.from(b, 'base64url');
    if (bufA.length === 0 || bufA.length !== bufB.length) {
      return false;
    }
    return timingSafeEqual(bufA, bufB);
  }

  private buildSubject(purpose: EmailOtpPurpose): string {
    switch (purpose) {
      case 'login_otp':
        return 'Your MoonWitness Sign-In Code';
      case 'email_verify':
        return 'Verify Your MoonWitness Email Address';
      case 'password_reset':
        return 'Reset Your MoonWitness Password';
    }
  }

  private pruneExpiredNonces(nowMs: number): void {
    for (const [nonce, exp] of this.consumedNonces.entries()) {
      if (exp <= nowMs) {
        this.consumedNonces.delete(nonce);
      }
    }
  }

  private recordConsumedNonce(nonce: string, exp: number): void {
    if (this.consumedNonces.size >= MAX_CONSUMED_NONCES) {
      const oldestKey = this.consumedNonces.keys().next().value;
      if (oldestKey !== undefined) {
        this.consumedNonces.delete(oldestKey);
      }
    }
    this.consumedNonces.set(nonce, exp);
  }
}

export function createEmailOtpService(options: EmailOtpServiceOptions = {}): EmailOtpService {
  return new EmailOtpService(options);
}
