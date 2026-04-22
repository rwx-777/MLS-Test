const path = require('path');

function parseApiKeys(value) {
  return (value || 'dev-change-me').split(',').map((v) => v.trim()).filter(Boolean);
}

const config = {
  port: Number(process.env.PORT || 8080),
  apiKeys: parseApiKeys(process.env.API_KEYS),
  maxFileSizeBytes: Number(process.env.MAX_FILE_SIZE_BYTES || 25 * 1024 * 1024),
  allowedMimeTypes: (process.env.ALLOWED_MIME_TYPES || 'application/octet-stream,image/png,image/jpeg,application/pdf')
    .split(',')
    .map((v) => v.trim())
    .filter(Boolean),
  uploadDir: process.env.UPLOAD_DIR || path.join('/tmp', 'mls-files'),
  // When true every application message and MLS event must include a valid Ed25519
  // signature over its canonical signing payload (default: false for backward compat).
  requireMessageSignatures: process.env.REQUIRE_MESSAGE_SIGNATURES === 'true',
  // How many past epochs application messages are accepted from before the server
  // rejects them as stale (sliding window replay protection).
  epochWindowSize: Number(process.env.EPOCH_WINDOW_SIZE || 2),
};

module.exports = { config };
