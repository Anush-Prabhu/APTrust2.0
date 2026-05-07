import { CONFIG, SERVER_UNAVAILABLE_MESSAGE } from './config.js';

async function call(method, path, body) {
  const url = `${CONFIG.serverBase}${path}`;
  const init = {
    method,
    headers: { 'Accept': 'application/json' },
  };
  if (body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(url, init);
  } catch (err) {
    throw new ServerUnavailableError(SERVER_UNAVAILABLE_MESSAGE);
  }
  let data = null;
  const text = await res.text();
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = { raw: text };
    }
  }
  if (!res.ok) {
    const message =
      (data && (data.message || data.error)) ||
      `Server returned HTTP ${res.status}`;
    const error = new Error(message);
    error.status = res.status;
    error.body = data;
    throw error;
  }
  return data;
}

export class ServerUnavailableError extends Error {
  constructor(message) {
    super(message);
    this.name = 'ServerUnavailableError';
  }
}

export const api = {
  health: () => call('GET', '/health'),
  search: (q) => call('GET', `/search?q=${encodeURIComponent(q || '')}`),
  verify: (boundary, url) => call('POST', '/verify', { boundary, url }),
};
