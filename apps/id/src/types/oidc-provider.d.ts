declare module 'oidc-provider' {
  import type { IncomingMessage, ServerResponse } from 'node:http';
  import type { JWK } from 'jose';

  export interface AdapterPayload {
    grantId?: string;
    userCode?: string;
    uid?: string;
    consumed?: number;
    [key: string]: unknown;
  }

  export interface Adapter {
    upsert(id: string, payload: AdapterPayload, expiresIn: number): Promise<void>;
    find(id: string): Promise<AdapterPayload | undefined>;
    findByUserCode(userCode: string): Promise<AdapterPayload | undefined>;
    findByUid(uid: string): Promise<AdapterPayload | undefined>;
    consume(id: string): Promise<void>;
    destroy(id: string): Promise<void>;
    revokeByGrantId(grantId: string): Promise<void>;
  }

  export type AdapterConstructor = new (name: string) => Adapter;

  export interface ClientMetadata {
    client_id: string;
    client_secret?: string;
    token_endpoint_auth_method?: string;
    grant_types?: string[];
    response_types?: string[];
    redirect_uris?: string[];
    scope?: string;
    [key: string]: unknown;
  }

  export interface Configuration {
    adapter?: AdapterConstructor;
    jwks?: { keys: JWK[] };
    clients?: ClientMetadata[];
    cookies?: { keys?: string[] };
    pkce?: {
      required?: () => boolean;
      methods?: string[];
    };
    rotateRefreshToken?: boolean;
    scopes?: string[];
    claims?: Record<string, string[]>;
    features?: Record<string, unknown>;
    interactions?: {
      url?: (ctx: unknown, interaction: { uid: string }) => string;
    };
    findAccount?: (
      ctx: unknown,
      sub: string,
    ) => Promise<
      | {
          accountId: string;
          claims: () => Promise<Record<string, unknown>>;
        }
      | undefined
    >;
    ttl?: Record<string, number>;
    [key: string]: unknown;
  }

  export interface GrantInstance {
    addOIDCScope(scope: string): void;
    addResourceScope(resource: string, scope: string): void;
    save(): Promise<string>;
  }

  export interface InteractionDetails {
    uid: string;
    prompt: { name: string };
    params: Record<string, unknown>;
  }

  export default class Provider {
    constructor(issuer: string, configuration?: Configuration);
    Grant: new (options: { accountId: string; clientId: string }) => GrantInstance;
    callback(): (req: IncomingMessage, res: ServerResponse) => Promise<void> | void;
    interactionDetails(req: IncomingMessage, res: ServerResponse): Promise<InteractionDetails>;
    interactionFinished(
      req: IncomingMessage,
      res: ServerResponse,
      result: Record<string, unknown>,
      options?: { mergeWithLastSubmission?: boolean },
    ): Promise<void>;
  }
}
