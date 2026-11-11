import { test, describe, before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { buildApp } from '../dist/app.js';
import { pkiTrustStore } from '../dist/routes/pkiRegistry.js';

type AppInstance = Awaited<ReturnType<typeof buildApp>>;

describe('Verifier API Test Suite', () => {
  let app: AppInstance;
  let testKeyPair: crypto.KeyPairSyncResult<string, string>;

  before(async () => {
    testKeyPair = crypto.generateKeyPairSync('ed25519', {
      publicKeyEncoding: { type: 'spki', format: 'pem' },
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    // Or EC keypair for standard ECDSA P-256
    app = await buildApp();
    await app.ready();
  });

  after(async () => {
    await app.close();
  });

  describe('Health Check', () => {
    test('GET /health returns 200 ok', async () => {
      const response = await app.inject({
        method: 'GET',
        url: '/health',
      });
      assert.equal(response.statusCode, 200);
      const json = response.json();
      assert.equal(json.status, 'ok');
      assert.equal(json.service, 'Anti-Deepfake Verifier API');
      assert.ok(json.timestamp);
    });
  });

  describe('PKI Registry Endpoints', () => {
    test('GET /v1/pki/anchors returns trusted institutional root CA certificates', async () => {
      const response = await app.inject({
        method: 'GET',
        url: '/v1/pki/anchors',
      });
      assert.equal(response.statusCode, 200);
      const json = response.json();
      assert.ok(Array.isArray(json.anchors));
      assert.ok(json.anchors.length >= 3);
      assert.equal(json.count, json.anchors.length);

      const appleAnchor = json.anchors.find((a: any) => a.id === 'root-ca-apple-se');
      assert.ok(appleAnchor);
      assert.equal(appleAnchor.organization, 'Apple Inc.');
      assert.ok(appleAnchor.certificatePem.includes('BEGIN CERTIFICATE'));
    });

    test('POST /v1/pki/register-key successfully stores a device public key and hardware certificate', async () => {
      const ecKey = crypto.generateKeyPairSync('ec', {
        namedCurve: 'prime256v1',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });

      const response = await app.inject({
        method: 'POST',
        url: '/v1/pki/register-key',
        payload: {
          keyId: 'hw_key_iphone15_pro_01',
          publicKey: ecKey.publicKey,
          certificate: '-----BEGIN CERTIFICATE-----\nMIIB...hwcert\n-----END CERTIFICATE-----',
          deviceModel: 'iPhone 15 Pro Hardware KMS',
          enclaveType: 'Apple Secure Enclave',
          issuer: 'CN=Apple Secure Enclave Root CA - G1',
        },
      });

      assert.equal(response.statusCode, 201);
      const json = response.json();
      assert.equal(json.success, true);
      assert.equal(json.key.keyId, 'hw_key_iphone15_pro_01');
      assert.equal(json.key.publicKey, ecKey.publicKey);
      assert.equal(json.key.deviceModel, 'iPhone 15 Pro Hardware KMS');
      assert.ok(json.key.registeredAt);

      // Verify it is stored in the store
      const stored = pkiTrustStore.getKey('hw_key_iphone15_pro_01');
      assert.ok(stored);
      assert.equal(stored.keyId, 'hw_key_iphone15_pro_01');
    });

    test('POST /v1/pki/register-key validates missing keyId or publicKey', async () => {
      const res1 = await app.inject({
        method: 'POST',
        url: '/v1/pki/register-key',
        payload: {
          publicKey: 'mock-key',
        },
      });
      assert.equal(res1.statusCode, 400);
      assert.ok(res1.json().error.includes('keyId is required'));

      const res2 = await app.inject({
        method: 'POST',
        url: '/v1/pki/register-key',
        payload: {
          keyId: 'test-id',
        },
      });
      assert.equal(res2.statusCode, 400);
      assert.ok(res2.json().error.includes('publicKey is required'));
    });
  });

  describe('WebRTC Stream Token Verification Endpoint', () => {
    let ecdsaKey: crypto.KeyPairSyncResult<string, string>;
    const keyId = 'stream_cam_device_001';

    before(async () => {
      // Generate EC keypair for ECDSA SHA-256 signing
      ecdsaKey = crypto.generateKeyPairSync('ec', {
        namedCurve: 'prime256v1',
        publicKeyEncoding: { type: 'spki', format: 'pem' },
        privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      });

      // Register key in PKI
      await app.inject({
        method: 'POST',
        url: '/v1/pki/register-key',
        payload: {
          keyId,
          publicKey: ecdsaKey.publicKey,
          deviceModel: 'MacBook Pro Secure Camera M3',
          enclaveType: 'Apple Secure Enclave',
        },
      });
    });

    test('POST /v1/verify/stream-token validates valid signed WebRTC frame hash token', async () => {
      const frameHash = crypto.createHash('sha256').update('frame-pixel-data-webrtc-12345').digest('hex');
      const timestamp = Date.now();
      const sequenceNumber = 1042;
      const dataToSign = `${frameHash}:${timestamp}`;

      const signer = crypto.createSign('SHA256');
      signer.update(dataToSign);
      signer.end();
      const signature = signer.sign(ecdsaKey.privateKey, 'hex');

      const response = await app.inject({
        method: 'POST',
        url: '/v1/verify/stream-token',
        payload: {
          frameHash,
          keyId,
          signature,
          timestamp,
          sequenceNumber,
        },
      });

      assert.equal(response.statusCode, 200);
      const json = response.json();
      assert.equal(json.verified, true);
      assert.equal(json.status, 'VALID');
      assert.equal(json.frameHash, frameHash);
      assert.equal(json.keyId, keyId);
      assert.equal(json.sequenceNumber, sequenceNumber);
      assert.equal(json.enclaveType, 'Apple Secure Enclave');
      assert.equal(json.errors.length, 0);
    });

    test('POST /v1/verify/stream-token supports compact base64-encoded JSON token', async () => {
      const frameHash = crypto.createHash('sha256').update('frame-pixel-data-webrtc-67890').digest('hex');
      const timestamp = Date.now();

      const signer = crypto.createSign('SHA256');
      signer.update(frameHash);
      signer.end();
      const signature = signer.sign(ecdsaKey.privateKey, 'hex');

      const tokenObj = {
        frameHash,
        keyId,
        signature,
        timestamp,
        sequenceNumber: 1043,
      };
      const compactToken = Buffer.from(JSON.stringify(tokenObj)).toString('base64');

      const response = await app.inject({
        method: 'POST',
        url: '/v1/verify/stream-token',
        payload: {
          token: compactToken,
        },
      });

      assert.equal(response.statusCode, 200);
      const json = response.json();
      assert.equal(json.verified, true);
      assert.equal(json.status, 'VALID');
      assert.equal(json.frameHash, frameHash);
      assert.equal(json.keyId, keyId);
    });

    test('POST /v1/verify/stream-token rejects tampered frame hash / invalid signature', async () => {
      const originalFrame = crypto.createHash('sha256').update('authentic-frame').digest('hex');
      const tamperedFrame = crypto.createHash('sha256').update('deepfake-injected-frame').digest('hex');
      const timestamp = Date.now();

      const signer = crypto.createSign('SHA256');
      signer.update(`${originalFrame}:${timestamp}`);
      signer.end();
      const signature = signer.sign(ecdsaKey.privateKey, 'hex');

      const response = await app.inject({
        method: 'POST',
        url: '/v1/verify/stream-token',
        payload: {
          frameHash: tamperedFrame, // mismatch with signature
          keyId,
          signature,
          timestamp,
        },
      });

      assert.equal(response.statusCode, 400);
      const json = response.json();
      assert.equal(json.verified, false);
      assert.equal(json.status, 'INVALID_SIGNATURE');
      assert.ok(json.errors[0].includes('signature verification failed'));
    });

    test('POST /v1/verify/stream-token rejects expired token or timestamp drift', async () => {
      const frameHash = crypto.createHash('sha256').update('frame-data').digest('hex');
      const staleTimestamp = Date.now() - 10 * 60 * 1000; // 10 minutes ago (exceeds 5m drift)

      const signer = crypto.createSign('SHA256');
      signer.update(`${frameHash}:${staleTimestamp}`);
      signer.end();
      const signature = signer.sign(ecdsaKey.privateKey, 'hex');

      const response = await app.inject({
        method: 'POST',
        url: '/v1/verify/stream-token',
        payload: {
          frameHash,
          keyId,
          signature,
          timestamp: staleTimestamp,
        },
      });

      assert.equal(response.statusCode, 400);
      const json = response.json();
      assert.equal(json.verified, false);
      assert.equal(json.status, 'EXPIRED');
      assert.ok(json.errors[0].includes('expired'));
    });

    test('POST /v1/verify/stream-token rejects unregistered keyId', async () => {
      const frameHash = crypto.createHash('sha256').update('frame-data').digest('hex');
      const timestamp = Date.now();

      const response = await app.inject({
        method: 'POST',
        url: '/v1/verify/stream-token',
        payload: {
          frameHash,
          keyId: 'unknown_hardware_key_9999',
          signature: 'abcd1234deadbeef',
          timestamp,
        },
      });

      assert.equal(response.statusCode, 401);
      const json = response.json();
      assert.equal(json.verified, false);
      assert.equal(json.status, 'UNREGISTERED_KEY');
      assert.ok(json.errors[0].includes('not registered'));
    });

    test('POST /v1/verify/stream-token returns 400 on malformed or empty token payload', async () => {
      const response = await app.inject({
        method: 'POST',
        url: '/v1/verify/stream-token',
        payload: {},
      });

      assert.equal(response.statusCode, 400);
      const json = response.json();
      assert.equal(json.verified, false);
      assert.equal(json.status, 'MALFORMED_TOKEN');
    });
  });
});
