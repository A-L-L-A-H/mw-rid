import { randomBytes } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { ClientMetadata } from 'oidc-provider';
import type { LoadSigningKeysOptions } from './crypto/keys.js';
import { hashSecretSha256, verifyPassword } from './crypto/passwords.js';
import { createOidcProvider } from './oidc/provider.js';
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

  const identityDb = new IdentityDatabase(dbPath);
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
