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
  uploadDir: process.env.UPLOAD_DIR || path.join('/tmp', 'mls-files')
};

module.exports = { config };
