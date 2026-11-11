import { buildApp } from './app.js';

const PORT = process.env.PORT ? parseInt(process.env.PORT) : 4000;

async function start() {
  const app = await buildApp();
  try {
    await app.listen({ port: PORT, host: '0.0.0.0' });
    console.log(`🚀 Verifier API running on http://localhost:${PORT}`);
  } catch (err) {
    app.log.error(err);
    process.exit(1);
  }
}

start();
