import cors from 'cors';
import express, { type Express } from 'express';
import path from 'node:path';
import { adminRouter, adminUiMiddleware } from './routes/admin';
import { publicRouter } from './routes/public';

export interface CreateAppOptions {
  /** Override the directory that hosts the static admin UI. */
  adminPublicDir?: string;
}

export function createApp(options: CreateAppOptions = {}): Express {
  const app = express();
  app.disable('x-powered-by');
  app.use(cors());
  app.use(express.json({ limit: '1mb' }));

  // Admin static UI is mounted FIRST so that GET /admin and /admin/<asset>
  // serve files. Unknown sub-paths (e.g. /admin/data) fall through to the
  // adminRouter() below, which handles the JSON API endpoints from the SRS.
  const publicDir =
    options.adminPublicDir ?? path.resolve(__dirname, '..', 'public', 'admin');

  app.use('/admin', adminUiMiddleware(publicDir));
  app.use('/admin', adminRouter());

  app.use('/', publicRouter());

  // Last-resort 404 handler for unknown routes.
  app.use((_req, res) => {
    res.status(404).json({ error: 'not_found' });
  });

  return app;
}
