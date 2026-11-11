import { FastifyInstance, FastifyRequest, FastifyReply } from 'fastify';

export interface DeviceKeyRecord {
  keyId: string;
  publicKey: string;
  certificate?: string;
  deviceModel?: string;
  enclaveType?: string;
  issuer?: string;
  registeredAt: string;
}

export interface RootCAAnchor {
  id: string;
  commonName: string;
  organization: string;
  certificatePem: string;
  fingerprintSha256: string;
  validFrom: string;
  validTo: string;
}

// In-memory PKI trust store
class PKITrustStore {
  private deviceKeys = new Map<string, DeviceKeyRecord>();
  private rootAnchors: RootCAAnchor[] = [
    {
      id: 'root-ca-apple-se',
      commonName: 'Apple Secure Enclave Root CA - G1',
      organization: 'Apple Inc.',
      certificatePem: '-----BEGIN CERTIFICATE-----\nMIIBojCCAUqgAwIBAgIIAQEBAQEBAQAwDQYJKoZIhvcNAQELBQAwKTEnMCUGA1UE\nAxMeQXBwbGUgU2VjdXJlIEVuY2xhdmUgUm9vdCBDQTAeFw0yMDAxMDEwMDAwMDBa\nFw00MDAxMDEwMDAwMDBaMCkxJzAlBgNVBAMTHkFwcGxlIFNlY3VyZSBFbmNsYXZl\nIFJvb3QgQ0EwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAR5f7xW9P43i0k8H...=\n-----END CERTIFICATE-----',
      fingerprintSha256: 'a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0',
      validFrom: '2020-01-01T00:00:00Z',
      validTo: '2040-01-01T00:00:00Z',
    },
    {
      id: 'root-ca-android-strongbox',
      commonName: 'Google Android StrongBox Hardware Root CA',
      organization: 'Google LLC',
      certificatePem: '-----BEGIN CERTIFICATE-----\nMIIBpDCCAUygAwIBAgIJAJ2X9Q123456MA0GCSqGSIb3DQEBCwUAMDIxMDAuBgNV\nBAMTJ0dvb2dsZSBBbmRyb2lkIFN0cm9uZ0JveCBIYXJkd2FyZSBSb290IENBMB4X\nDTIwMDEwMTAwMDAwMFoXDTQwMDEwMTAwMDAwMFowMjEwMC4GA1UEAxMnR29vZ2xl\nIEFuZHJvaWQgU3Ryb25nQm94IEhhcmR3YXJlIFJvb3QgQ0EwWTATBgcqhkjOPQIB\n-----END CERTIFICATE-----',
      fingerprintSha256: 'b2c3d4e5f6a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456',
      validFrom: '2020-01-01T00:00:00Z',
      validTo: '2040-01-01T00:00:00Z',
    },
    {
      id: 'root-ca-institutional-financial',
      commonName: 'Financial Trust Network Hardware Root CA - Institutional',
      organization: 'Financial Trust Network',
      certificatePem: '-----BEGIN CERTIFICATE-----\nMIIBqzCCAVKgAwIBAgIJAP9876543210MA0GCSqGSIb3DQEBCwUAMDYxNDAyBgNV\nBAMTK0ZpbmFuY2lhbCBUcnVzdCBOZXR3b3JrIEhhcmR3YXJlIFJvb3QgQ0EgLSBJ\nMB4XDTIwMDEwMTAwMDAwMFoXDTQwMDEwMTAwMDAwMFowNjE0MDIGA1UEAxMrRmlu\nYW5jaWFsIFRydXN0IE5ldHdvcmsgSGFyZHdhcmUgUm9vdCBDQSAtIEkwWTATBgcq\n-----END CERTIFICATE-----',
      fingerprintSha256: 'c3d4e5f6a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef012345678',
      validFrom: '2020-01-01T00:00:00Z',
      validTo: '2040-01-01T00:00:00Z',
    },
  ];

  public registerKey(record: Omit<DeviceKeyRecord, 'registeredAt'>): DeviceKeyRecord {
    const entry: DeviceKeyRecord = {
      ...record,
      registeredAt: new Date().toISOString(),
    };
    this.deviceKeys.set(record.keyId, entry);
    return entry;
  }

  public getKey(keyId: string): DeviceKeyRecord | undefined {
    return this.deviceKeys.get(keyId);
  }

  public getAnchors(): RootCAAnchor[] {
    return [...this.rootAnchors];
  }

  public clearKeys(): void {
    this.deviceKeys.clear();
  }
}

export const pkiTrustStore = new PKITrustStore();

export interface RegisterKeyBody {
  keyId?: string;
  publicKey?: string;
  certificate?: string;
  deviceModel?: string;
  enclaveType?: string;
  issuer?: string;
}

export async function registerPkiRoutes(app: FastifyInstance) {
  // POST /v1/pki/register-key: Stores public keys and device hardware certificates
  app.post('/v1/pki/register-key', async (request: FastifyRequest<{ Body: RegisterKeyBody }>, reply: FastifyReply) => {
    const { keyId, publicKey, certificate, deviceModel, enclaveType, issuer } = request.body || {};

    if (!keyId || typeof keyId !== 'string') {
      return reply.status(400).send({
        error: 'Validation failed: keyId is required and must be a string.',
      });
    }

    if (!publicKey || typeof publicKey !== 'string') {
      return reply.status(400).send({
        error: 'Validation failed: publicKey is required and must be a string.',
      });
    }

    const savedKey = pkiTrustStore.registerKey({
      keyId,
      publicKey,
      certificate,
      deviceModel,
      enclaveType,
      issuer,
    });

    return reply.status(201).send({
      success: true,
      message: `Device key '${keyId}' registered successfully in PKI Trust Store.`,
      key: savedKey,
    });
  });

  // GET /v1/pki/anchors: Returns verified root CA certs
  app.get('/v1/pki/anchors', async (_request: FastifyRequest, reply: FastifyReply) => {
    const anchors = pkiTrustStore.getAnchors();
    return reply.send({
      count: anchors.length,
      anchors,
    });
  });
}
