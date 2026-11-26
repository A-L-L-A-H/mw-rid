import Provider, { type ClientMetadata, type Configuration } from 'oidc-provider';
import { loadSigningKeys, type LoadSigningKeysOptions } from '../crypto/keys.js';
import { createSqliteAdapterFactory } from '../storage/oidc-adapter.js';
import type { IdentityDatabase } from '../storage/sqlite.js';

export interface CreateOidcProviderOptions {
  issuer: string;
  identityDb: IdentityDatabase;
  defaultAudience?: string;
  clients?: ClientMetadata[];
  cookieKeys?: string[];
  signingKeyOptions?: LoadSigningKeysOptions;
}

export function getDefaultPublicClients(): ClientMetadata[] {
  return [
    {
      client_id: 'mw-board',
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      redirect_uris: ['http://127.0.0.1:3000/auth/callback', 'http://localhost:3000/auth/callback'],
    },
    {
      client_id: 'mw-echo',
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      redirect_uris: ['http://127.0.0.1:3001/auth/callback', 'http://localhost:3001/auth/callback'],
    },
    {
      client_id: 'mw-mylove',
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      redirect_uris: ['http://127.0.0.1:3002/auth/callback', 'http://localhost:3002/auth/callback'],
    },
  ];
}

export async function createOidcProvider(options: CreateOidcProviderOptions): Promise<Provider> {
  const { issuer, identityDb } = options;
  const defaultAudience = options.defaultAudience ?? 'urn:moonwitness:api';
  const jwks = await loadSigningKeys(options.signingKeyOptions);
  const adapter = createSqliteAdapterFactory(identityDb);

  const configuration: Configuration = {
    adapter,
    jwks,
    clients: options.clients ?? getDefaultPublicClients(),
    cookies: {
      keys: options.cookieKeys ?? [
        process.env.MW_RID_COOKIE_SECRET ?? 'mw-rid-dev-cookie-key-rotate-in-prod',
      ],
    },
    pkce: {
      required: () => true,
      methods: ['S256'],
    },
    rotateRefreshToken: true,
    scopes: ['openid', 'profile', 'email', 'offline_access', 'api:read', 'api:write'],
    claims: {
      openid: ['sub'],
      profile: ['preferred_username', 'role'],
      email: ['email'],
    },
    features: {
      devInteractions: { enabled: false },
      clientCredentials: { enabled: true },
      revocation: { enabled: true },
      userinfo: { enabled: true },
      resourceIndicators: {
        enabled: true,
        defaultResource: () => defaultAudience,
        useGrantedResource: () => true,
        getResourceServerInfo: (_ctx: unknown, resourceIndicator: string) => ({
          scope: 'openid profile email offline_access api:read api:write',
          audience: resourceIndicator,
          accessTokenTTL: 900,
          accessTokenFormat: 'jwt',
          jwt: {
            sign: { alg: 'RS256' },
          },
        }),
      },
    },
    interactions: {
      url(_ctx, interaction) {
        return `/interaction/${interaction.uid}`;
      },
    },
    async findAccount(_ctx, sub) {
      const account = identityDb.findAccountBySub(sub);
      if (!account || account.status !== 'active') {
        return undefined;
      }
      return {
        accountId: account.sub,
        async claims() {
          return {
            sub: account.sub,
            preferred_username: account.username,
            email: account.email ?? undefined,
            role: account.role,
          };
        },
      };
    },
    ttl: {
      AccessToken: 900,
      AuthorizationCode: 300,
      ClientCredentials: 900,
      Grant: 86400 * 14,
      IdToken: 900,
      RefreshToken: 86400 * 14,
      Interaction: 600,
      Session: 86400,
    },
  };

  return new Provider(issuer, configuration);
}
