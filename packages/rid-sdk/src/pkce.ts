import { createHash, randomBytes } from 'node:crypto';

export interface PkcePair {
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: 'S256';
}

export interface BuildAuthorizationUrlOptions {
  authorizationEndpoint: string;
  clientId: string;
  redirectUri: string;
  scope: string;
  state: string;
  codeChallenge: string;
  resource?: string;
  nonce?: string;
}

export function createPkcePair(): PkcePair {
  const codeVerifier = randomBytes(32).toString('base64url');
  const codeChallenge = createHash('sha256').update(codeVerifier).digest('base64url');
  return {
    codeVerifier,
    codeChallenge,
    codeChallengeMethod: 'S256',
  };
}

export function buildAuthorizationUrl(options: BuildAuthorizationUrlOptions): string {
  const authUrl = new URL(options.authorizationEndpoint);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('client_id', options.clientId);
  authUrl.searchParams.set('redirect_uri', options.redirectUri);
  authUrl.searchParams.set('scope', options.scope);
  authUrl.searchParams.set('state', options.state);
  authUrl.searchParams.set('code_challenge', options.codeChallenge);
  authUrl.searchParams.set('code_challenge_method', 'S256');

  if (options.resource) {
    authUrl.searchParams.set('resource', options.resource);
  }
  if (options.nonce) {
    authUrl.searchParams.set('nonce', options.nonce);
  }

  return authUrl.toString();
}
