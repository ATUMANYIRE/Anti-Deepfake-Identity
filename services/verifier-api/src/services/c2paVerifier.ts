import crypto from 'node:crypto';

export interface VerificationRequest {
  buffer: Buffer;
  fileName: string;
}

export interface VerificationResponse {
  verified: boolean;
  status: 'VALID' | 'TAMPERED' | 'UNSIGNED';
  hardBindingHash: string;
  computedHash: string;
  attestation: {
    enclave: string;
    keyId: string;
    status: 'VERIFIED' | 'UNTRUSTED_KEY' | 'MISSING';
  };
  livenessScore: number;
  errors: string[];
}

export async function verifyMediaBuffer(req: VerificationRequest): Promise<VerificationResponse> {
  // 1. Calculate SHA-256 Hard-Binding hash directly from raw bytes
  const computedHash = crypto.createHash('sha256').update(req.buffer).digest('hex');

  // Simulated extraction of C2PA JUMBF Manifest box
  // In production, this parses JUMBF bytes or delegates to c2pa-rs WASM
  const isSimulatedTampered = req.fileName.toLowerCase().includes('tampered') || req.fileName.toLowerCase().includes('fake');
  const isSimulatedUnsigned = req.fileName.toLowerCase().includes('unsigned');

  if (isSimulatedUnsigned) {
    return {
      verified: false,
      status: 'UNSIGNED',
      hardBindingHash: '',
      computedHash,
      attestation: { enclave: 'Unknown', keyId: '', status: 'MISSING' },
      livenessScore: 0,
      errors: ['No C2PA provenance manifest found in media container.']
    };
  }

  const hardBindingHash = isSimulatedTampered
    ? 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    : computedHash;

  const isHashMatch = hardBindingHash === computedHash;
  const isAttested = !isSimulatedTampered;

  const errors: string[] = [];
  if (!isHashMatch) errors.push('Hard-binding SHA-256 hash mismatch. Media content has been altered.');
  if (!isAttested) errors.push('Hardware Key Attestation could not be verified against institutional root CA.');

  return {
    verified: isHashMatch && isAttested,
    status: (isHashMatch && isAttested) ? 'VALID' : 'TAMPERED',
    hardBindingHash,
    computedHash,
    attestation: {
      enclave: 'Apple Secure Enclave / TPM 2.0',
      keyId: 'key_sec_enc_9942a188f',
      status: isAttested ? 'VERIFIED' : 'UNTRUSTED_KEY'
    },
    livenessScore: isSimulatedTampered ? 0.24 : 0.98,
    errors
  };
}
