import { randomBytes } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { ClientMetadata } from 'oidc-provider';
import type { LoadSigningKeysOptions } from './crypto/keys.js';
import { hashSecretSha256, verifyPassword } from './crypto/passwords.js';
import { createOidcProvider } from './oidc/provider.js';
import {
  createEmailOtpService,
  isValidEmailOtpPurpose,
  type EmailOtpServiceOptions,
} from './services/email-otp.js';
import {
  createGoogleOAuthService,
  GoogleOAuthError,
  type GoogleOAuthConfig,
} from './services/google-oauth.js';
import { createTenantApiKeyService } from './services/tenant-api-keys.js';
import { IdentityDatabase } from './storage/sqlite.js';

export interface RidServerOptions {
  port?: number;
  host?: string;
  issuer?: string;
  dbPath?: string;
  bootstrapSecret?: string;
  defaultAudience?: string;
  clients?: ClientMetadata[];
  signingKeyOptions?: LoadSigningKeysOptions;
  nodeEnv?: string;
  otpOptions?: EmailOtpServiceOptions;
  googleOAuthOptions?: GoogleOAuthConfig;
}

export interface RunningRidServer {
  server: Server;
  url: string;
  port: number;
  identityDb: IdentityDatabase;
  bootstrapSecret: string;
  close: () => Promise<void>;
}

async function readJsonBody(request: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
  }
  const rawBody = Buffer.concat(chunks).toString('utf8').trim();
  if (!rawBody) {
    return {};
  }
  return JSON.parse(rawBody) as Record<string, unknown>;
}

function sendJson(
  response: ServerResponse,
  statusCode: number,
  payload: Record<string, unknown>,
): void {
  const serialized = JSON.stringify(payload);
  response.statusCode = statusCode;
  response.setHeader('content-type', 'application/json; charset=utf-8');
  response.setHeader('cache-control', 'no-store');
  response.end(serialized);
}

export async function startRidServer(options: RidServerOptions = {}): Promise<RunningRidServer> {
  const host = options.host ?? '127.0.0.1';
  const requestedPort = options.port ?? Number(process.env.MW_RID_PORT ?? 4480);
  const dbPath = options.dbPath ?? process.env.MW_RID_DB_PATH ?? ':memory:';
  const nodeEnv = options.nodeEnv ?? options.otpOptions?.nodeEnv ?? process.env.NODE_ENV ?? 'development';

  const identityDb = new IdentityDatabase(dbPath);
  const emailOtpService = createEmailOtpService({
    nodeEnv,
    ...options.otpOptions,
  });
  const googleOAuthService = createGoogleOAuthService({
    nodeEnv,
    ...options.googleOAuthOptions,
  });
  const tenantApiKeyService = createTenantApiKeyService(identityDb);
  const bootstrapSecret =
    options.bootstrapSecret ??
    process.env.MW_RID_BOOTSTRAP_SECRET ??
    randomBytes(32).toString('base64url');
  identityDb.initBootstrapSecretHash(hashSecretSha256(bootstrapSecret));

  const tempServer = createServer();
  await new Promise<void>((resolve) => {
    tempServer.listen(requestedPort, host, () => resolve());
  });
  const address = tempServer.address();
  const actualPort = typeof address === 'object' && address ? address.port : requestedPort;
  const baseUrl = `http://${host}:${actualPort}`;
  const issuer = options.issuer ?? process.env.MW_RID_ISSUER ?? baseUrl;

  const provider = await createOidcProvider({
    issuer,
    identityDb,
    defaultAudience: options.defaultAudience ?? process.env.MW_RID_DEFAULT_AUDIENCE,
    clients: options.clients,
    signingKeyOptions: options.signingKeyOptions,
  });

  const oidcCallback = provider.callback();

  tempServer.on('request', async (request: IncomingMessage, response: ServerResponse) => {
    try {
      const requestUrl = new URL(request.url ?? '/', baseUrl);
      const pathname = requestUrl.pathname;
      const method = request.method ?? 'GET';

      if (method === 'GET' && pathname === '/health') {
        sendJson(response, 200, { status: 'ok', service: 'mw-rid', issuer });
        return;
      }

      if (method === 'POST' && pathname === '/api/auth/otp/request') {
        const body = await readJsonBody(request);
        const email = typeof body.email === 'string' ? body.email.trim() : '';
        const purposeRaw = body.purpose ?? 'login_otp';

        if (!email || !isValidEmailOtpPurpose(purposeRaw)) {
          sendJson(response, 400, {
            error: 'invalid_request',
            message: 'Valid email and purpose (login_otp | email_verify | password_reset) are required.',
          });
          return;
        }

        try {
          const result = await emailOtpService.sendOtp({
            email,
            purpose: purposeRaw,
          });
          const responsePayload: Record<string, unknown> = {
            sent: true,
            delivery: result.delivery,
            token: result.token,
            expiresAt: result.expiresAt,
          };
          if (result.messageId !== undefined) {
            responsePayload.messageId = result.messageId;
          }
          if (nodeEnv !== 'production' && result.previewCode !== undefined) {
            responsePayload.previewCode = result.previewCode;
          }
          sendJson(response, 200, responsePayload);
        } catch (err) {
          const message = err instanceof Error ? err.message : 'otp_request_failed';
          sendJson(response, 400, { error: 'otp_request_failed', message });
        }
        return;
      }

      if (method === 'POST' && pathname === '/api/auth/otp/verify') {
        const body = await readJsonBody(request);
        const email = typeof body.email === 'string' ? body.email.trim() : '';
        const code = typeof body.code === 'string' ? body.code.trim() : '';
        const token = typeof body.token === 'string' ? body.token.trim() : '';
        const purposeRaw = body.purpose ?? 'login_otp';

        if (!email || !code || !token || !isValidEmailOtpPurpose(purposeRaw)) {
          sendJson(response, 400, {
            error: 'invalid_request',
            message: 'email, code, token, and valid purpose are required.',
          });
          return;
        }

        const verification = emailOtpService.verifyOtp({
          email,
          code,
          token,
          purpose: purposeRaw,
        });
        if (!verification.valid) {
          sendJson(response, 401, {
            error: 'invalid_otp',
            reason: verification.reason,
          });
          return;
        }

        sendJson(response, 200, {
          verified: true,
          email: verification.email,
          purpose: verification.purpose,
        });
        return;
      }

      if (method === 'POST' && pathname === '/api/auth/password-reset/confirm') {
        const body = await readJsonBody(request);
        const email = typeof body.email === 'string' ? body.email.trim() : '';
        const code = typeof body.code === 'string' ? body.code.trim() : '';
        const token = typeof body.token === 'string' ? body.token.trim() : '';
        const newPassword = typeof body.newPassword === 'string' ? body.newPassword : '';

        if (!email || !code || !token || newPassword.length < 8) {
          sendJson(response, 400, {
            error: 'invalid_request',
            message: 'email, code, token, and newPassword (min 8 chars) are required.',
          });
          return;
        }

        const verification = emailOtpService.verifyOtp({
          email,
          code,
          token,
          purpose: 'password_reset',
        });
        if (!verification.valid) {
          sendJson(response, 401, {
            error: 'invalid_otp',
            reason: verification.reason,
          });
          return;
        }

        const account = identityDb.findAccountByEmail(verification.email);
        if (!account || account.status !== 'active') {
          sendJson(response, 404, {
            error: 'account_not_found',
            message: 'Active account for email not found.',
          });
          return;
        }

        identityDb.updateAccountPassword(account.sub, newPassword);
        sendJson(response, 200, {
          reset: true,
          sub: account.sub,
          email: verification.email,
        });
        return;
      }

      if (method === 'GET' && pathname === '/api/auth/google/start') {
        if (!googleOAuthService.isConfigured()) {
          sendJson(response, 503, {
            error: 'google_oauth_not_configured',
            message: 'Google OAuth is not configured.',
          });
          return;
        }
        const loginHint = requestUrl.searchParams.get('login_hint') ?? undefined;
        const authResult = googleOAuthService.buildAuthorizationUrl({ loginHint });
        sendJson(response, 200, {
          url: authResult.url,
          state: authResult.state,
          expiresAt: authResult.expiresAt,
        });
        return;
      }

      if (method === 'GET' && pathname === '/api/auth/google/callback') {
        if (!googleOAuthService.isConfigured()) {
          sendJson(response, 503, {
            error: 'google_oauth_not_configured',
            message: 'Google OAuth is not configured.',
          });
          return;
        }

        const oauthError = requestUrl.searchParams.get('error');
        if (oauthError) {
          sendJson(response, 400, {
            error: 'google_oauth_error',
            message: oauthError,
          });
          return;
        }

        const code = requestUrl.searchParams.get('code')?.trim() ?? '';
        const state = requestUrl.searchParams.get('state')?.trim() ?? '';
        if (!code || !state) {
          sendJson(response, 400, {
            error: 'invalid_request',
            message: 'code and state query parameters are required.',
          });
          return;
        }

        try {
          const result = await googleOAuthService.authenticateCallback({
            code,
            state,
            identityDb,
          });
          sendJson(response, 200, {
            authenticated: true,
            created: result.created,
            linked: result.linked,
            account: {
              sub: result.account.sub,
              username: result.account.username,
              email: result.account.email,
              role: result.account.role,
              status: result.account.status,
            },
            profile: {
              sub: result.profile.sub,
              email: result.profile.email,
              name: result.profile.name,
              hd: result.profile.hd,
            },
          });
        } catch (err) {
          if (err instanceof GoogleOAuthError) {
            sendJson(response, err.statusCode, {
              error: err.code,
              message: err.message,
            });
            return;
          }
          const message = err instanceof Error ? err.message : 'google_callback_failed';
          sendJson(response, 500, { error: 'google_callback_failed', message });
        }
        return;
      }

      const tenantApiKeysMatch = pathname.match(/^\/api\/tenants\/([^/]+)\/api-keys$/);
      if (tenantApiKeysMatch) {
        const tenantId = decodeURIComponent(tenantApiKeysMatch[1]).trim();
        if (!tenantId) {
          sendJson(response, 400, { error: 'invalid_request', message: 'tenantId is required.' });
          return;
        }

        if (method === 'POST') {
          const body = await readJsonBody(request);
          const name = typeof body.name === 'string' ? body.name.trim() : '';
          const scopes = Array.isArray(body.scopes)
            ? body.scopes.map((entry) => String(entry))
            : undefined;
          const expiresInDays =
            typeof body.expiresInDays === 'number' ? body.expiresInDays : undefined;

          if (!name) {
            sendJson(response, 400, {
              error: 'invalid_request',
              message: 'name is required.',
            });
            return;
          }

          try {
            const created = tenantApiKeyService.createKey({
              tenantId,
              name,
              scopes,
              expiresInDays,
            });
            sendJson(response, 201, {
              key: created.key,
              apiKey: created.apiKey,
            });
          } catch (err) {
            const message = err instanceof Error ? err.message : 'api_key_creation_failed';
            sendJson(response, 400, { error: 'invalid_request', message });
          }
          return;
        }

        if (method === 'GET') {
          const keys = tenantApiKeyService.listKeys(tenantId);
          sendJson(response, 200, { tenantId, keys });
          return;
        }
      }

      if (method === 'POST' && pathname === '/api/api-keys/verify') {
        const body = await readJsonBody(request);
        const authHeader = request.headers.authorization;
        const bearerKey =
          typeof authHeader === 'string' && authHeader.toLowerCase().startsWith('bearer ')
            ? authHeader.slice(7).trim()
            : '';
        const rawKey =
          typeof body.apiKey === 'string'
            ? body.apiKey.trim()
            : typeof body.api_key === 'string'
              ? body.api_key.trim()
              : bearerKey;

        if (!rawKey) {
          sendJson(response, 400, {
            error: 'invalid_request',
            message: 'apiKey is required.',
          });
          return;
        }

        const verified = tenantApiKeyService.verifyKey(rawKey);
        if (!verified.valid) {
          sendJson(response, 401, {
            valid: false,
            error: 'invalid_api_key',
            reason: verified.reason,
          });
          return;
        }

        sendJson(response, 200, {
          valid: true,
          id: verified.id,
          tenantId: verified.tenantId,
          name: verified.name,
          keyPrefix: verified.keyPrefix,
          scopes: verified.scopes,
        });
        return;
      }

      const apiKeyRevokeMatch = pathname.match(/^\/api\/api-keys\/([^/]+)\/revoke$/);
      if (method === 'POST' && apiKeyRevokeMatch) {
        const keyId = decodeURIComponent(apiKeyRevokeMatch[1]).trim();
        const body = await readJsonBody(request);
        const tenantId =
          typeof body.tenantId === 'string' && body.tenantId.trim().length > 0
            ? body.tenantId.trim()
            : (requestUrl.searchParams.get('tenantId') ?? undefined);

        const revoked = tenantApiKeyService.revokeKey(keyId, tenantId);
        if (!revoked) {
          sendJson(response, 404, {
            error: 'not_found',
            message: 'API key not found or already revoked.',
          });
          return;
        }

        sendJson(response, 200, { id: keyId, revoked: true });
        return;
      }

      if (method === 'POST' && pathname === '/api/bootstrap') {
        const body = await readJsonBody(request);
        const setupSecret = String(body.setupSecret ?? '');
        const username = String(body.username ?? '').trim();
        const password = String(body.password ?? '');
        const email = typeof body.email === 'string' ? body.email.trim() : undefined;

        if (!setupSecret || !username || password.length < 8) {
          sendJson(response, 400, {
            error: 'invalid_request',
            message: 'setupSecret, username, and password (min 8 chars) are required.',
          });
          return;
        }

        try {
          const owner = identityDb.bootstrapPlatformOwner({
            setupSecret,
            username,
            password,
            email,
          });
          sendJson(response, 201, {
            sub: owner.sub,
            username: owner.username,
            role: owner.role,
            status: owner.status,
          });
        } catch (err) {
          const code = err instanceof Error ? err.message : 'BOOTSTRAP_FAILED';
          if (code === 'BOOTSTRAP_ALREADY_CONSUMED') {
            sendJson(response, 409, {
              error: 'bootstrap_consumed',
              message: 'Platform Owner bootstrap has already been completed.',
            });
            return;
          }
          if (code === 'BOOTSTRAP_INVALID_SECRET') {
            sendJson(response, 403, {
              error: 'invalid_bootstrap_secret',
              message: 'Invalid bootstrap setup secret.',
            });
            return;
          }
          sendJson(response, 400, { error: 'bootstrap_failed', message: code });
        }
        return;
      }

      if (method === 'POST' && pathname === '/api/accounts') {
        const body = await readJsonBody(request);
        const username = String(body.username ?? '').trim();
        const password = String(body.password ?? '');
        const email = typeof body.email === 'string' ? body.email.trim() : undefined;

        if (!username || password.length < 8) {
          sendJson(response, 400, {
            error: 'invalid_request',
            message: 'username and password (min 8 chars) are required.',
          });
          return;
        }

        try {
          const account = identityDb.createAccount({ username, password, email });
          sendJson(response, 201, {
            sub: account.sub,
            username: account.username,
            role: account.role,
            status: account.status,
          });
        } catch (err) {
          const message = err instanceof Error ? err.message : 'account_creation_failed';
          sendJson(response, 409, { error: 'account_conflict', message });
        }
        return;
      }

      if (method === 'POST' && pathname === '/api/service-principals') {
        const body = await readJsonBody(request);
        const name = String(body.name ?? '').trim();
        const rawScopes = Array.isArray(body.scopes)
          ? body.scopes.map((scopeEntry) => String(scopeEntry))
          : ['api:read'];

        if (!name) {
          sendJson(response, 400, {
            error: 'invalid_request',
            message: 'name is required.',
          });
          return;
        }

        const clientId = `sp_${randomBytes(12).toString('hex')}`;
        const clientSecret = `spsec_${randomBytes(24).toString('base64url')}`;

        const principal = identityDb.registerServicePrincipal({
          name,
          clientId,
          clientSecret,
          scopes: rawScopes,
        });

        sendJson(response, 201, {
          client_id: principal.client_id,
          client_secret: clientSecret,
          name: principal.name,
          scopes: rawScopes,
          status: principal.status,
        });
        return;
      }

      if (method === 'GET' && pathname === '/api/outbox') {
        const includeAcked = requestUrl.searchParams.get('all') === 'true';
        const events = identityDb.listOutboxEvents(!includeAcked);
        sendJson(response, 200, { events });
        return;
      }

      const outboxAckMatch = pathname.match(/^\/api\/outbox\/(\d+)\/ack$/);
      if (method === 'POST' && outboxAckMatch) {
        const eventId = Number(outboxAckMatch[1]);
        const acked = identityDb.ackOutboxEvent(eventId);
        if (!acked) {
          sendJson(response, 404, { error: 'not_found', message: 'Outbox event not found or already acked.' });
          return;
        }
        sendJson(response, 200, { id: eventId, acked: true });
        return;
      }

      const interactionLoginMatch = pathname.match(/^\/interaction\/([^/]+)\/login$/);
      if (method === 'POST' && interactionLoginMatch) {
        const details = await provider.interactionDetails(request, response);
        const body = await readJsonBody(request);
        const username = String(body.username ?? '').trim();
        const password = String(body.password ?? '');

        const account = identityDb.findAccountByUsername(username);
        if (!account || account.status !== 'active' || !verifyPassword(password, account.password_hash)) {
          sendJson(response, 401, { error: 'invalid_credentials' });
          return;
        }

        const grant = new provider.Grant({
          accountId: account.sub,
          clientId: String(details.params.client_id),
        });

        const requestedScope = String(details.params.scope ?? 'openid');
        grant.addOIDCScope(requestedScope);

        const requestedResource =
          typeof details.params.resource === 'string'
            ? details.params.resource
            : (options.defaultAudience ?? 'urn:moonwitness:api');
        grant.addResourceScope(requestedResource, requestedScope);

        const grantId = await grant.save();

        await provider.interactionFinished(
          request,
          response,
          {
            login: { accountId: account.sub },
            consent: { grantId },
          },
          { mergeWithLastSubmission: false },
        );
        return;
      }

      const interactionMatch = pathname.match(/^\/interaction\/([^/]+)$/);
      if (method === 'GET' && interactionMatch) {
        const details = await provider.interactionDetails(request, response);
        sendJson(response, 200, {
          uid: details.uid,
          prompt: details.prompt.name,
          client_id: details.params.client_id,
          login_url: `/interaction/${details.uid}/login`,
        });
        return;
      }

      await oidcCallback(request, response);
    } catch (error) {
      const message = error instanceof Error ? error.message : 'Internal server error';
      if (!response.headersSent) {
        sendJson(response, 500, { error: 'internal_error', message });
      }
    }
  });

  return {
    server: tempServer,
    url: baseUrl,
    port: actualPort,
    identityDb,
    bootstrapSecret,
    close: async () => {
      await new Promise<void>((resolve, reject) => {
        tempServer.close((closeError) => {
          if (closeError) {
            reject(closeError);
          } else {
            resolve();
          }
        });
      });
      identityDb.close();
    },
  };
}
