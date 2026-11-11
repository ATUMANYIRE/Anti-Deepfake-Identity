import Fastify from 'fastify';
import cors from '@fastify/cors';
import multipart from '@fastify/multipart';
import { registerVerifyRoutes } from './routes/verifyMedia.js';
import { registerPkiRoutes } from './routes/pkiRegistry.js';
import { registerStreamVerifyRoutes } from './routes/verifyStream.js';

export async function buildApp() {
  const app = Fastify({ logger: true });

  await app.register(cors, { origin: '*' });
  await app.register(multipart, { limits: { fileSize: 100 * 1024 * 1024 } });

  app.get('/health', async () => {
    return { status: 'ok', service: 'Anti-Deepfake Verifier API', timestamp: new Date().toISOString() };
  });

  await app.register(registerVerifyRoutes);
  await app.register(registerPkiRoutes);
  await app.register(registerStreamVerifyRoutes);

  return app;
}
