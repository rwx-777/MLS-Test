# Secure Communication Backend (MLS-Ready)

Cloud-ready backend server for secure enterprise communication with MLS-ready message workflows.

## What this build includes

- Secure API baseline (Helmet, rate limiting, CORS-off by default, API key auth)
- 1:1 chat conversation APIs
- Group chat conversation APIs
- Encrypted message relay/storage APIs (ciphertext only)
- Secure file transfer APIs (encrypted file payload handling, metadata + access control)
- MLS event transport endpoints (commit/proposal/welcome/key package envelopes)
- Health endpoint for cloud/runtime checks
- Dockerfile for container deployment
- Basic integration tests
- Calling capability placeholder endpoint for future phases

> **Important**: This server is **MLS-ready transport/orchestration**. End-to-end cryptography and MLS state transitions are expected to be performed by clients or an MLS engine service. The backend stores/relays encrypted payloads and MLS envelopes.

## Architecture

- **Transport API**: Express REST API
- **Security layer**:
  - API key authentication (`Authorization: Bearer <key>` or `x-api-key`)
  - `helmet` security headers
  - request rate limiting
  - strict payload validation with `zod`
- **Messaging model**:
  - Users
  - Conversations (`direct` and `group`) with `mlsGroupId`
  - Ciphertext messages per conversation
  - MLS events per conversation
- **File transfer model**:
  - Server receives encrypted file blob and metadata
  - Per-conversation access control for metadata/content retrieval

Current persistence is in-memory + filesystem storage under `UPLOAD_DIR` for uploaded encrypted files. For production, replace with managed DB/object storage.

## Quick start

### Prerequisites

- Node.js 20+

### Install

```bash
npm install
```

### Configure

```bash
cp .env.example .env
```

Environment variables:

- `PORT` (default: `8080`)
- `API_KEYS` (comma-separated, default: `dev-change-me`)
- `MAX_FILE_SIZE_BYTES` (default: `26214400`)
- `ALLOWED_MIME_TYPES` (comma-separated)
- `UPLOAD_DIR` (default: `/tmp/mls-files`)

### Run

```bash
API_KEYS=dev-change-me npm start
```

### Test

```bash
npm test
```

## API overview

All endpoints require API key auth.

### Health

- `GET /healthz`

### Users

- `POST /v1/users`
  - body: `{ id, displayName, identityKey }`

### Conversations

- `POST /v1/conversations/direct`
  - body: `{ memberA, memberB, mlsGroupId }`
- `POST /v1/conversations/group`
  - body: `{ name, members[], mlsGroupId }`

### Messages (ciphertext only)

- `POST /v1/conversations/:conversationId/messages`
  - body: `{ senderId, ciphertext, contentType, metadata? }`
- `GET /v1/conversations/:conversationId/messages?requesterId=<userId>&after=<ISO timestamp>`

### MLS event transport

- `POST /v1/conversations/:conversationId/mls/events`
  - body: `{ senderId, eventType, eventCiphertext }`
  - `eventType`: `commit | proposal | welcome | key_package`
- `GET /v1/conversations/:conversationId/mls/events?requesterId=<userId>`

### File transfer (encrypted payload)

- `POST /v1/files/upload` (`multipart/form-data`)
  - file field: `file`
  - fields: `conversationId`, `senderId`, `sha256`, `encryptedFileKeyEnvelope`
- `GET /v1/files/:fileId/metadata?requesterId=<userId>`
- `GET /v1/files/:fileId/content?requesterId=<userId>`

## Container deployment

Build image:

```bash
docker build -t mls-backend .
```

Run:

```bash
docker run --rm -p 8080:8080 -e API_KEYS=prod-strong-key mls-backend
```

## Future calling support

Calling support is planned. This phase includes:

- `GET /v1/calling/capabilities` (placeholder contract)

Next phases can add:

- signaling channels (WebSocket/WebRTC signaling)
- MLS-integrated media key distribution
- SFU integration and policy controls

## Production hardening recommendations

- Replace in-memory store with PostgreSQL/Redis-backed services
- Store files in encrypted object storage (S3/GCS/Azure Blob)
- Add mTLS/service mesh for service-to-service security
- Integrate external KMS/HSM for key envelope workflows
- Add audit logging, SIEM export, and anomaly detection
- Add full MLS engine integration and key package lifecycle management
