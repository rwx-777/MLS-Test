# Secure Communication Backend (MLS E2E)

Cloud-ready backend server for enterprise communication with full MLS-based
end-to-end security infrastructure (RFC 9420).

## What this build includes

- Secure API baseline (Helmet, rate limiting, CORS-off by default, API key auth)
- 1:1 and group chat conversation APIs
- Ciphertext-only message relay with **replay protection** (SHA-256 hash dedup)
- Message **sequence numbers** for gap detection
- **MLS Key Package Distribution Service** — one-time-use key packages per user
  (RFC 9420 §10), upload/claim/count lifecycle
- **MLS Group Epoch State Machine** — proposal/commit/welcome ordering enforced
  server-side; epoch advances only on valid commits
- **Per-member Delivery Inbox** — fan-out of messages and MLS events to each
  member's personal inbox with acknowledgement support
- **Ed25519 Signature Verification** — optional (`REQUIRE_MESSAGE_SIGNATURES=true`)
  per-message and per-event signature verification using the user's registered
  identity key
- Encrypted file transfer APIs (ciphertext blob + MLS epoch reference)
- MLS Welcome fan-out routes invitations only to the `targetUserId`
- Health endpoint for cloud/runtime checks
- Dockerfile for container deployment
- Integration test suite (15 tests)
- Calling capability placeholder endpoint for future phases

> **Architecture note**: The server enforces MLS transport invariants
> (epoch ordering, replay protection, key-package lifecycle, fan-out).
> Actual group secret derivation, AEAD encryption/decryption, and credential
> binding are performed exclusively by clients or a dedicated MLS engine
> service — the server only ever sees opaque ciphertext envelopes.

## Architecture

- **Transport API**: Express REST API
- **Security layer**:
  - API key authentication (`Authorization: Bearer …` or `x-api-key`)
  - `helmet` security headers
  - Request rate limiting (240 req/min)
  - Strict payload validation with `zod`
- **MLS layer**:
  - `src/mls/crypto.js` — Ed25519 signature verification, SHA-256, canonical
    signing-payload constructors
  - `src/mls/keyPackageService.js` — upload/claim/count one-time key packages
  - `src/mls/epochService.js` — group epoch state machine (proposal → commit →
    epoch advance; sliding-window app-message acceptance)
  - `src/mls/inboxService.js` — per-member fan-out inbox with acknowledge
- **Messaging model**:
  - Users (with `identityKey` for signature verification)
  - Conversations (`direct` / `group`) with `mlsGroupId`
  - Ciphertext messages with `epoch`, `sequenceNumber`, and replay protection
  - MLS events (`commit`, `proposal`, `welcome`, `key_package`) with epoch
    validation and typed fan-out
- **File transfer model**:
  - Server receives encrypted file blob and metadata including `epoch`
  - Per-conversation access control for metadata/content retrieval

Current persistence is in-memory + filesystem storage under `UPLOAD_DIR`.
For production, replace with managed DB/object storage.

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

| Variable | Default | Description |
|---|---|---|
| `PORT` | `8080` | Listening port |
| `API_KEYS` | `dev-change-me` | Comma-separated API keys |
| `MAX_FILE_SIZE_BYTES` | `26214400` | Max file upload size |
| `ALLOWED_MIME_TYPES` | `application/octet-stream,…` | Allowed file MIME types |
| `UPLOAD_DIR` | `/tmp/mls-files` | Encrypted file storage dir |
| `REQUIRE_MESSAGE_SIGNATURES` | `false` | Enforce Ed25519 signatures on all messages/events |
| `EPOCH_WINDOW_SIZE` | `2` | Past-epoch acceptance window for app messages |

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
  - `identityKey`: base64-encoded DER SubjectPublicKeyInfo of the user's Ed25519
    signing key (used for message/event signature verification)

### Key Package Distribution (RFC 9420 §10)

- `POST /v1/users/:userId/key-packages`
  - body: `{ keyPackages: [{ keyPackageData, signature? }] }` (up to 50)
  - Uploads one-time-use key packages. When `REQUIRE_MESSAGE_SIGNATURES=true`
    each package must be self-signed with the user's identity key over
    `keyPackageSigningPayload(userId, keyPackageData)`.
- `GET /v1/users/:userId/key-packages/claim?requesterId=<userId>`
  - Claims (consumes) one key package. Used to prepare an Add proposal.
  - Returns `404` when no packages are available.
- `GET /v1/users/:userId/key-packages/count?requesterId=<userId>`
  - Returns `{ userId, available: N }`. Top up when low.

### Conversations

- `POST /v1/conversations/direct`
  - body: `{ memberA, memberB, mlsGroupId }`
- `POST /v1/conversations/group`
  - body: `{ name, members[], mlsGroupId }`

### Messages (ciphertext only)

- `POST /v1/conversations/:conversationId/messages`
  - body: `{ senderId, ciphertext, contentType?, epoch?, signature?, metadata? }`
  - `epoch`: MLS epoch the message was encrypted under (recommended)
  - `signature`: Ed25519 sig over `messageSigningPayload(conversationId, senderId, epoch, ciphertext)` — required when `REQUIRE_MESSAGE_SIGNATURES=true`
  - Duplicate ciphertexts are rejected (replay protection)
  - Messages outside the epoch sliding window are rejected
  - Returns the stored message including `sequenceNumber`
  - Fans out to all member inboxes
- `GET /v1/conversations/:conversationId/messages?requesterId=<userId>&after=<ISO>`

### MLS event transport

- `POST /v1/conversations/:conversationId/mls/events`
  - body: `{ senderId, eventType, eventCiphertext, epoch?, signature?, targetUserId? }`
  - `eventType`: `commit | proposal | welcome | key_package`
  - `epoch` required for `commit`, `proposal`, `welcome`
  - `targetUserId` required for `welcome` — the new member being invited
  - Epoch state machine: proposals queue at current epoch; commits advance epoch
  - Fan-out: commit/proposal → all members except sender; welcome → targetUserId only
  - `welcome` automatically adds `targetUserId` to conversation members
  - Returns the stored event plus `groupEpoch` (current epoch after processing)
- `GET /v1/conversations/:conversationId/mls/events?requesterId=<userId>`
- `GET /v1/conversations/:conversationId/mls/epoch?requesterId=<userId>`
  - Returns `{ mlsGroupId, epoch, pendingProposals, commitHistory }`

### Member inbox (delivery service)

- `GET /v1/inbox?requesterId=<userId>[&conversationId=<id>][&type=application|mls_event]`
  - Retrieve unread inbox entries fanned out to this member
- `POST /v1/inbox/:inboxEntryId/ack?requesterId=<userId>`
  - Mark an inbox entry as read/acknowledged

### File transfer (encrypted payload)

- `POST /v1/files/upload` (`multipart/form-data`)
  - file field: `file`
  - fields: `conversationId`, `senderId`, `sha256`, `encryptedFileKeyEnvelope`, `epoch?`
  - `epoch`: MLS epoch under which the file key envelope was sealed
- `GET /v1/files/:fileId/metadata?requesterId=<userId>`
- `GET /v1/files/:fileId/content?requesterId=<userId>`

## Typical MLS group-add flow

```
1. Bob uploads key packages:
   POST /v1/users/bob/key-packages  { keyPackages: [...] }

2. Alice claims Bob's key package to create an Add proposal:
   GET  /v1/users/bob/key-packages/claim?requesterId=alice

3. Alice sends an Add proposal (encrypted for the group):
   POST /v1/conversations/:id/mls/events  { eventType:"proposal", epoch:N, ... }

4. Alice commits the proposal (epoch advances N → N+1):
   POST /v1/conversations/:id/mls/events  { eventType:"commit", epoch:N, ... }

5. Alice sends Bob a Welcome (encrypted for Bob's key package):
   POST /v1/conversations/:id/mls/events
     { eventType:"welcome", epoch:N+1, targetUserId:"bob", ... }
   → Server fans Welcome to Bob's inbox and adds Bob to conversation members.

6. Bob polls his inbox, processes the Welcome with his MLS client, and
   can now send/receive application messages at epoch N+1.
```

## Ed25519 signing payloads

When `REQUIRE_MESSAGE_SIGNATURES=true` clients must sign the following
canonical UTF-8 JSON strings with their Ed25519 identity key:

| Context | Payload |
|---|---|
| Application message | `{"conversationId":"…","senderId":"…","epoch":N,"ciphertext":"…"}` |
| MLS event | `{"conversationId":"…","senderId":"…","eventType":"…","epoch":N,"eventCiphertext":"…"}` |
| Key package | `{"userId":"…","keyPackageData":"…"}` |

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

- Signaling channels (WebSocket/WebRTC signaling)
- MLS-integrated media key distribution
- SFU integration and policy controls

## Production hardening recommendations

- Replace in-memory store with PostgreSQL/Redis-backed services
- Store files in encrypted object storage (S3/GCS/Azure Blob)
- Add mTLS/service mesh for service-to-service security
- Integrate external KMS/HSM for key envelope workflows
- Add audit logging, SIEM export, and anomaly detection
- Enable `REQUIRE_MESSAGE_SIGNATURES=true` and enforce valid Ed25519 keys
- Add full MLS engine integration (OpenMLS, mlspp) for cryptographic validation
- Implement key package replenishment alerts (webhook when count drops below threshold)
