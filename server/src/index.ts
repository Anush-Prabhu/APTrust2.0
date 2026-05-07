import { createApp } from './app';

const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '127.0.0.1';

const app = createApp();

const server = app.listen(PORT, HOST, () => {
  // The SRS demo speaks of localhost; we listen on 127.0.0.1 by default but
  // print "localhost" in the banner so docs and demo lines match.
  // eslint-disable-next-line no-console
  console.log(`AP Trust local server running at http://localhost:${PORT}`);
});

server.on('error', (err: NodeJS.ErrnoException) => {
  if (err.code === 'EADDRINUSE') {
    // eslint-disable-next-line no-console
    console.error(
      `[aptrust] port ${PORT} is already in use. Stop the other process or run with a different PORT.`,
    );
  } else {
    // eslint-disable-next-line no-console
    console.error('[aptrust] failed to start server:', err);
  }
  process.exit(1);
});
