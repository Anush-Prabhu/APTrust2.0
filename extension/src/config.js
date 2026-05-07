/**
 * Central config for the extension (MV3, ES modules).
 *
 * v2.0 server on port 3000. All verification goes through POST /verify.
 */

export const CONFIG = {
  serverBase: 'http://localhost:3000',

  storageKeys: {
    protectMode: 'aptrust.protectMode',
    selectedBoundary: 'aptrust.selectedBoundary',
  },

  /**
   * When the tab URL is inside a recognized webmail host, downgrade a raw
   * UNTRUSTED page verdict to MAIL_CLIENT so the inbox UI itself is not
   * painted as an impersonation target (links in messages are still scanned).
   */
  emailHosts: [
    'mail.google.com',
    'outlook.live.com',
    'outlook.office.com',
    'outlook.office365.com',
    'outlook.cloud.microsoft',
    'mail.yahoo.com',
    'mail.proton.me',
    'mail.aol.com',
    'mail.zoho.com',
    'app.fastmail.com',
    'icloud.com',
  ],
};

/** Legacy content-script + background contract from APT 1.0. */
export const STATUS = {
  TRUSTED: 'trusted',
  UNTRUSTED: 'untrusted',
  EXCLUDED: 'excluded',
  SKIPPED: 'skipped',
  MAIL_CLIENT: 'mail_client',
};

export const SERVER_UNAVAILABLE_MESSAGE =
  'Local AP Trust server unavailable. Start the local server and try again.';
