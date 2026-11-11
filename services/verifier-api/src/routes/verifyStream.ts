import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';
import crypto from 'node:crypto';
import { pkiTrustStore } from './pkiRegistry.js';

export interface VerifyStreamTokenBody {
  // Option 1: Object payload containing individual verification properties
  frameHash?: string;
  keyId?: string;
  signature?: string;
  timestamp?: number | string;
  sequenceNumber?: number;
  algorithm?: string;

  // Option 2: Compact signed token string or object token
  token?: string | {
    frameHash?: string;
    keyId?: string;
    signature?: string;
    timestamp?: number | string;
    sequenceNumber?: number;
  };
}

export interface StreamVerificationResult {
  verified: boolean;
  status: 'VALID' | 'INVALID_SIGNATURE' | 'EXPIRED' | 'UNREGISTERED_KEY' | 'MALFORMED_TOKEN';
  frameHash: string;
  keyId: string;
  timestamp: string | number;
  sequenceNumber?: number;
  errors: string[];
}

export function parseStreamToken(body: VerifyStreamTokenBody): {
  frameHash: string;
  keyId: string;
  signature: string;
  timestamp: number | string;
  sequenceNumber?: number;
  algorithm?: string;
} | null {
  // If `token` is a compact string (e.g., base64 encoded JSON or JWT-like header.payload.signature)
  if (typeof body.token === 'string') {
    try {
      const parts = body.token.split('.');
      if (parts.length === 3) {
        // JWT structure: header.payload.signature
        const payloadJson = Buffer.from(parts[1], 'base64url').toString('utf8');
        const payload = JSON.parse(payloadJson);
        return {
          frameHash: payload.frameHash || payload.sub,
          keyId: payload.keyId || payload.kid,
          signature: parts[2],
          timestamp: payload.timestamp || payload.iat,
          sequenceNumber: payload.sequenceNumber || payload.seq,
          algorithm: payload.alg,
        };
      } else {
        // Base64-encoded JSON or JSON string
        const decoded = Buffer.from(body.token, 'base64').toString('utf8');
        const parsed = JSON.parse(decoded);
        return {
          frameHash: parsed.frameHash,
          keyId: parsed.keyId,
          signature: parsed.signature,
          timestamp: parsed.timestamp,
          sequenceNumber: parsed.sequenceNumber,
          algorithm: parsed.algorithm,
        };
      }
    } catch {
      // If parsing failed as base64, attempt direct JSON parse
      try {
        const parsed = JSON.parse(body.token);
        return {
          frameHash: parsed.frameHash,
          keyId: parsed.keyId,
          signature: parsed.signature,
          timestamp: parsed.timestamp,
          sequenceNumber: parsed.sequenceNumber,
          algorithm: parsed.algorithm,
        };
      } catch {
        return null;
      }
    }
  }

  // If `token` is an object
  if (typeof body.token === 'object' && body.token !== null) {
    if (body.token.frameHash && body.token.keyId && body.token.signature) {
      return {
        frameHash: body.token.frameHash,
        keyId: body.token.keyId,
        signature: body.token.signature,
        timestamp: body.token.timestamp ?? Date.now(),
        sequenceNumber: body.token.sequenceNumber,
      };
    }
  }

  // Direct properties in body
  if (body.frameHash && body.keyId && body.signature) {
    return {
      frameHash: body.frameHash,
      keyId: body.keyId,
      signature: body.signature,
      timestamp: body.timestamp ?? Date.now(),
      sequenceNumber: body.sequenceNumber,
      algorithm: body.algorithm,
    };
  }

  return null;
}

export function verifyCryptographicSignature(
  publicKeyPem: string,
  dataToVerify: string | Buffer,
  signatureHexOrBase64: string,
  algorithm = 'SHA256'
): boolean {
  try {
    const verifier = crypto.createVerify(algorithm);
    verifier.update(dataToVerify);
    verifier.end();

    const isHex = /^[0-9a-fA-F]+$/.test(signatureHexOrBase64) && signatureHexOrBase64.length % 2 === 0;
    const encoding: crypto.BinaryToTextEncoding = isHex ? 'hex' : 'base64';

    return verifier.verify(publicKeyPem, signatureHexOrBase64, encoding);
  } catch {
    // If standard node crypto fails (e.g. non-standard PEM formatting), check base64url or fallback format
    try {
      const verifier = crypto.createVerify(algorithm);
      verifier.update(dataToVerify);
      verifier.end();
      const sigBuf = Buffer.from(signatureHexOrBase64, 'base64url');
      return verifier.verify(publicKeyPem, sigBuf);
    } catch {
      return false;
    }
  }
}

export async function registerStreamVerifyRoutes(app: FastifyInstance) {
  // POST /v1/verify/stream-token: validates signed WebRTC frame hash tokens sent during live video calls
  app.post('/v1/verify/stream-token', async (request: FastifyRequest<{ Body: VerifyStreamTokenBody }>, reply: FastifyReply) => {
    const parsed = parseStreamToken(request.body || {});

    if (!parsed || !parsed.frameHash || !parsed.keyId || !parsed.signature) {
      return reply.status(400).send({
        verified: false,
        status: 'MALFORMED_TOKEN',
        frameHash: parsed?.frameHash || '',
        keyId: parsed?.keyId || '',
        timestamp: parsed?.timestamp || '',
        errors: ['Invalid request: frameHash, keyId, and signature are required in stream token payload.'],
      });
    }

    const { frameHash, keyId, signature, timestamp, sequenceNumber } = parsed;

    // Check if key exists in PKI Trust Store
    const registeredDevice = pkiTrustStore.getKey(keyId);
    if (!registeredDevice) {
      return reply.status(401).send({
        verified: false,
        status: 'UNREGISTERED_KEY',
        frameHash,
        keyId,
        timestamp,
        sequenceNumber,
        errors: [`Key ID '${keyId}' is not registered in institutional PKI Trust Store.`],
      });
    }

    // Verify timestamp freshness to mitigate replay attacks (allow 5-minute clock drift/window)
    const tokenTime = typeof timestamp === 'string' ? new Date(timestamp).getTime() : Number(timestamp);
    const now = Date.now();
    const MAX_ALLOWED_DRIFT_MS = 5 * 60 * 1000; // 5 minutes

    if (isNaN(tokenTime) || Math.abs(now - tokenTime) > MAX_ALLOWED_DRIFT_MS) {
      return reply.status(400).send({
        verified: false,
        status: 'EXPIRED',
        frameHash,
        keyId,
        timestamp,
        sequenceNumber,
        errors: ['Stream token expired or timestamp exceeds maximum allowed drift window.'],
      });
    }

    // Verify cryptographic signature against frameHash or combined payload
    // Support signing either frameHash alone or `${frameHash}:${timestamp}` or `${frameHash}:${sequenceNumber}:${timestamp}`
    let signatureValid = false;

    const dataCandidates = [
      `${frameHash}:${timestamp}`,
      frameHash,
      `${frameHash}:${sequenceNumber ?? ''}:${timestamp}`,
      JSON.stringify({ frameHash, timestamp }),
    ];

    for (const candidate of dataCandidates) {
      if (verifyCryptographicSignature(registeredDevice.publicKey, candidate, signature)) {
        signatureValid = true;
        break;
      }
    }

    if (!signatureValid) {
      return reply.status(400).send({
        verified: false,
        status: 'INVALID_SIGNATURE',
        frameHash,
        keyId,
        timestamp,
        sequenceNumber,
        errors: ['Cryptographic signature verification failed against registered device public key.'],
      });
    }

    return reply.status(200).send({
      verified: true,
      status: 'VALID',
      frameHash,
      keyId,
      timestamp,
      sequenceNumber,
      deviceModel: registeredDevice.deviceModel,
      enclaveType: registeredDevice.enclaveType,
      errors: [],
    });
  });
}
