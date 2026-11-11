import { VerificationResult, C2PAManifest } from './types';

export function bufferToHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function computeSHA256(data: ArrayBuffer): Promise<string> {
  const hashBuffer = await window.crypto.subtle.digest('SHA-256', data);
  return bufferToHex(hashBuffer);
}

export async function parseAndVerifyMedia(file: File): Promise<VerificationResult> {
  const startTime = performance.now();
  const fileBuffer = await file.arrayBuffer();
  const computedHash = await computeSHA256(fileBuffer);
  const manifest = extractMockC2PAData(file, fileBuffer, computedHash);
  const duration = Math.round(performance.now() - startTime);

  let status: VerificationResult['status'] = 'UNSIGNED';
  const errors: string[] = [];

  if (manifest) {
    if (!manifest.isHashMatch) {
      status = 'TAMPERED';
      errors.push('Media bytes do not match the signed manifest hash (Hard Binding Integrity Failed).');
    } else if (manifest.hardwareAttestation.attestationStatus !== 'VERIFIED') {
      status = 'TAMPERED';
      errors.push('Hardware Key Attestation could not be verified against vendor PKI roots.');
    } else {
      status = 'VALID';
    }
  } else {
    errors.push('No embedded C2PA Manifest found in media container.');
  }

  return {
    fileName: file.name,
    fileSize: file.size,
    mimeType: file.type || 'application/octet-stream',
    status,
    manifest,
    verificationDurationMs: duration,
    errors,
  };
}

function extractMockC2PAData(file: File, buffer: ArrayBuffer, computedHash: string): C2PAManifest | null {
  const isSimulatedTampered = file.name.toLowerCase().includes('tampered') || file.name.toLowerCase().includes('fake');
  const isSimulatedUnsigned = file.name.toLowerCase().includes('unsigned') || file.name.toLowerCase().includes('plain');

  if (isSimulatedUnsigned) {
    return null;
  }

  const expectedHash = isSimulatedTampered
    ? 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'
    : computedHash;

  return {
    claimGenerator: 'AntiDeepfake Hardware Engine v1.4 / iOS SecureEnclave',
    signatureAlgorithm: 'ECDSA-P256-SHA256',
    issuerCertificate: 'CN=BankOfAmerica Hardware Root CA, O=Financial Trust Network',
    hardBindingHash: expectedHash,
    computedHash: computedHash,
    isHashMatch: expectedHash === computedHash,
    hardwareAttestation: {
      enclaveType: 'Apple Secure Enclave',
      hardwareKeyId: 'key_sec_enc_9942a188f',
      attestationStatus: isSimulatedTampered ? 'UNTRUSTED_KEY' : 'VERIFIED',
      timestamp: new Date().toISOString(),
      deviceModel: 'iPhone 15 Pro Hardware KMS',
    },
    livenessProof: {
      score: isSimulatedTampered ? 0.24 : 0.98,
      passed: !isSimulatedTampered,
      challengeType: 'OPTICAL_DEPTH_ANALYSIS',
    },
    signingTime: new Date(Date.now() - 3600000).toISOString(),
  };
}
