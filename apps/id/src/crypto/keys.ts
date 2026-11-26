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
  allowEphemeralKeys?: boolean;
}

export async function loadSigningKeys(
  options: LoadSigningKeysOptions = {},
): Promise<SigningKeySet> {
  const nodeEnv = options.nodeEnv ?? process.env.NODE_ENV ?? 'development';
  const isProduction = nodeEnv === 'production';

  const pemFromEnv = options.signingKeyPem ?? process.env.MW_RID_SIGNING_KEY_PEM;
  const pemPath = options.signingKeyPath ?? process.env.MW_RID_SIGNING_KEY_PATH;

  let resolvedPem: string | undefined;
  if (pemFromEnv && pemFromEnv.trim().length > 0) {
    resolvedPem = pemFromEnv.replace(/\\n/g, '\n');
  } else if (pemPath && pemPath.trim().length > 0) {
    resolvedPem = readFileSync(pemPath, 'utf8');
  }

  if (resolvedPem) {
    const privateKey = await importPKCS8(resolvedPem, 'RS256', { extractable: true });
    const privateJwk = await exportJWK(privateKey);
    const kid = await calculateJwkThumbprint(privateJwk, 'sha256');
    return {
      keys: [
        {
          ...privateJwk,
          alg: 'RS256',
          use: 'sig',
          kid,
        },
      ],
    };
  }

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

  const { privateKey } = await generateKeyPair('RS256', { extractable: true });
  const privateJwk = await exportJWK(privateKey);
  const kid = await calculateJwkThumbprint(privateJwk, 'sha256');

  return {
    keys: [
      {
        ...privateJwk,
        alg: 'RS256',
        use: 'sig',
        kid,
      },
    ],
  };
}
