import { FastifyInstance } from 'fastify';
import { verifyMediaBuffer } from '../services/c2paVerifier.js';

export async function registerVerifyRoutes(app: FastifyInstance) {
  app.post('/v1/verify/media', async (request, reply) => {
    const data = await request.file();
    if (!data) {
      return reply.status(400).send({ error: 'No media file uploaded' });
    }

    const buffer = await data.toBuffer();
    const result = await verifyMediaBuffer({
      buffer,
      fileName: data.filename
    });

    return reply.send(result);
  });
}
