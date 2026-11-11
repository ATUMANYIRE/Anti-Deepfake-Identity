export type VerificationStatus = 'IDLE' | 'PARSING' | 'HASHING' | 'VERIFYING' | 'VALID' | 'TAMPERED' | 'UNSIGNED';

export interface HardwareAttestation {
  enclaveType: 'Apple Secure Enclave' | 'Windows TPM 2.0' | 'Android StrongBox' | 'Software (Unverified)';
  hardwareKeyId: string;
  attestationStatus: 'VERIFIED' | 'UNTRUSTED_KEY' | 'MISSING';
  timestamp: string;
  deviceModel: string;
}

export interface LivenessProof {
  score: number;
  passed: boolean;
  challengeType: 'DYNAMIC_PROMPT_RESPONSE' | 'OPTICAL_DEPTH_ANALYSIS' | 'NONE';
}

export interface C2PAManifest {
  claimGenerator: string;
  signatureAlgorithm: string;
  issuerCertificate: string;
  hardBindingHash: string;
  computedHash: string;
  isHashMatch: boolean;
  hardwareAttestation: HardwareAttestation;
  livenessProof: LivenessProof;
  signingTime: string;
}

export interface VerificationResult {
  fileName: string;
  fileSize: number;
  mimeType: string;
  status: VerificationStatus;
  manifest: C2PAManifest | null;
  verificationDurationMs: number;
  errors: string[];
}
