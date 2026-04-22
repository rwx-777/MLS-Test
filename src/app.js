'use strict';

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const { randomUUID } = require('crypto');
const fs = require('fs/promises');
const path = require('path');
const { z } = require('zod');
const { InMemoryStore } = require('./store');
const { config } = require('./config');
const { KeyPackageService } = require('./mls/keyPackageService');
const { EpochService } = require('./mls/epochService');
const { InboxService } = require('./mls/inboxService');
const {
  verifyEd25519Signature,
  sha256Hex,
  messageSigningPayload,
  mlsEventSigningPayload,
} = require('./mls/crypto');

// ---------------------------------------------------------------------------
// Middleware helpers
// ---------------------------------------------------------------------------

function authMiddleware(apiKeys) {
  return (req, res, next) => {
    const auth = req.header('authorization') || '';
    const bearer = auth.startsWith('Bearer ') ? auth.slice('Bearer '.length).trim() : null;
    const key = req.header('x-api-key') || bearer;

    if (!key || !apiKeys.includes(key)) {
      return res.status(401).json({ error: 'Unauthorized' });
    }

    next();
  };
}

function validateBody(schema) {
  return (req, res, next) => {
    const result = schema.safeParse(req.body);
    if (!result.success) {
      return res.status(400).json({ error: 'Invalid payload', details: result.error.issues });
    }
    req.validatedBody = result.data;
    next();
  };
}

function assertParticipant(store, conversationId, userId) {
  const conversation = store.conversations.get(conversationId);
  if (!conversation) {
    return { error: { status: 404, message: 'Conversation not found' } };
  }
  if (!conversation.members.includes(userId)) {
    return { error: { status: 403, message: 'User is not a conversation member' } };
  }
  return { conversation };
}

// ---------------------------------------------------------------------------
// Application factory
// ---------------------------------------------------------------------------

function createApp({ store = new InMemoryStore(), runtimeConfig = config } = {}) {
  const app = express();

  const keyPackageSvc = new KeyPackageService(store);
  const epochSvc = new EpochService(store, runtimeConfig.epochWindowSize);
  const inboxSvc = new InboxService(store);

  const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: runtimeConfig.maxFileSizeBytes },
  });

  app.use(helmet());
  app.use(cors({ origin: false }));
  app.use(rateLimit({ windowMs: 60 * 1000, max: 240 }));
  app.use(express.json({ limit: '1mb' }));
  app.use(authMiddleware(runtimeConfig.apiKeys));

  // -------------------------------------------------------------------------
  // Health
  // -------------------------------------------------------------------------

  app.get('/healthz', (_req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  // -------------------------------------------------------------------------
  // Users
  // -------------------------------------------------------------------------

  const userSchema = z.object({
    id: z.string().min(1),
    displayName: z.string().min(1),
    identityKey: z.string().min(16),
  });

  app.post('/v1/users', validateBody(userSchema), (req, res) => {
    const { id } = req.validatedBody;
    if (store.users.has(id)) {
      return res.status(409).json({ error: 'User already exists' });
    }
    const user = store.createUser(req.validatedBody);
    return res.status(201).json(user);
  });

  // -------------------------------------------------------------------------
  // Key package distribution (RFC 9420 §10)
  // -------------------------------------------------------------------------

  const keyPackageUploadSchema = z.object({
    keyPackages: z
      .array(
        z.object({
          keyPackageData: z.string().min(1),
          signature: z.string().min(1).optional(),
        })
      )
      .min(1)
      .max(50),
  });

  /**
   * POST /v1/users/:userId/key-packages
   * Upload one or more one-time-use key packages.
   * When REQUIRE_MESSAGE_SIGNATURES=true each package must carry a valid
   * self-signature over keyPackageSigningPayload(userId, keyPackageData).
   */
  app.post('/v1/users/:userId/key-packages', validateBody(keyPackageUploadSchema), (req, res) => {
    const { userId } = req.params;
    const user = store.users.get(userId);
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    const result = keyPackageSvc.upload(
      userId,
      req.validatedBody.keyPackages,
      user.identityKey,
      runtimeConfig.requireMessageSignatures
    );

    return res.status(201).json({
      uploaded: result.uploaded,
      skipped: result.skipped,
      available: keyPackageSvc.countAvailable(userId),
    });
  });

  /**
   * GET /v1/users/:userId/key-packages/claim?requesterId=<userId>
   * Claim (consume) one key package for the given user so that the requester
   * can add them to an MLS group.
   */
  app.get('/v1/users/:userId/key-packages/claim', (req, res) => {
    const { userId } = req.params;
    const requesterId = req.query.requesterId;

    if (!requesterId || !store.users.has(requesterId)) {
      return res.status(400).json({ error: 'requesterId must be a registered user' });
    }
    if (!store.users.has(userId)) {
      return res.status(404).json({ error: 'User not found' });
    }

    const kp = keyPackageSvc.claim(userId);
    if (!kp) {
      return res.status(404).json({ error: 'No key packages available for this user' });
    }

    return res.json({
      ...kp,
      remainingAvailable: keyPackageSvc.countAvailable(userId),
    });
  });

  /**
   * GET /v1/users/:userId/key-packages/count?requesterId=<userId>
   * Return the number of unclaimed key packages available for a user.
   */
  app.get('/v1/users/:userId/key-packages/count', (req, res) => {
    const { userId } = req.params;
    if (!store.users.has(userId)) {
      return res.status(404).json({ error: 'User not found' });
    }
    return res.json({ userId, available: keyPackageSvc.countAvailable(userId) });
  });

  // -------------------------------------------------------------------------
  // Conversations
  // -------------------------------------------------------------------------

  const directConversationSchema = z.object({
    memberA: z.string().min(1),
    memberB: z.string().min(1),
    mlsGroupId: z.string().min(1),
  });

  app.post('/v1/conversations/direct', validateBody(directConversationSchema), (req, res) => {
    const { memberA, memberB, mlsGroupId } = req.validatedBody;
    if (!store.users.has(memberA) || !store.users.has(memberB)) {
      return res.status(404).json({ error: 'Members must exist' });
    }

    const existing = [...store.conversations.values()].find(
      (c) =>
        c.type === 'direct' &&
        c.members.length === 2 &&
        c.members.includes(memberA) &&
        c.members.includes(memberB)
    );

    if (existing) {
      return res.status(200).json(existing);
    }

    const conversation = store.createConversation({ type: 'direct', members: [memberA, memberB], mlsGroupId });
    epochSvc.initGroup(conversation.mlsGroupId);
    return res.status(201).json(conversation);
  });

  const groupConversationSchema = z.object({
    name: z.string().min(1),
    members: z.array(z.string().min(1)).min(2),
    mlsGroupId: z.string().min(1),
  });

  app.post('/v1/conversations/group', validateBody(groupConversationSchema), (req, res) => {
    const { members } = req.validatedBody;
    const missing = members.find((member) => !store.users.has(member));
    if (missing) {
      return res.status(404).json({ error: `Unknown user: ${missing}` });
    }

    const conversation = store.createConversation({ type: 'group', ...req.validatedBody });
    epochSvc.initGroup(conversation.mlsGroupId);
    return res.status(201).json(conversation);
  });

  // -------------------------------------------------------------------------
  // Messages (ciphertext relay + replay protection + epoch validation + fan-out)
  // -------------------------------------------------------------------------

  const messageSchema = z.object({
    senderId: z.string().min(1),
    ciphertext: z.string().min(1),
    contentType: z.enum(['text', 'file', 'control']).default('text'),
    /** MLS epoch the message was encrypted under. Recommended. */
    epoch: z.number().int().nonnegative().optional(),
    /** Ed25519 signature over messageSigningPayload(conversationId, senderId, epoch, ciphertext).
     *  Required when REQUIRE_MESSAGE_SIGNATURES=true. */
    signature: z.string().min(1).optional(),
    metadata: z.record(z.string(), z.unknown()).optional(),
  });

  app.post('/v1/conversations/:conversationId/messages', validateBody(messageSchema), (req, res) => {
    const { conversationId } = req.params;
    const { senderId, ciphertext, contentType, epoch, signature, metadata } = req.validatedBody;

    const access = assertParticipant(store, conversationId, senderId);
    if (access.error) {
      return res.status(access.error.status).json({ error: access.error.message });
    }

    const conversation = access.conversation;

    // --- Signature verification ---
    if (runtimeConfig.requireMessageSignatures || signature) {
      if (!signature) {
        return res.status(400).json({ error: 'Message signature is required' });
      }
      const sender = store.users.get(senderId);
      const payload = messageSigningPayload(conversationId, senderId, epoch ?? 0, ciphertext);
      if (!verifyEd25519Signature(sender.identityKey, payload, signature)) {
        return res.status(403).json({ error: 'Invalid message signature' });
      }
    }

    // --- Epoch validation ---
    if (epoch != null) {
      const epochCheck = epochSvc.validateMessageEpoch(conversation.mlsGroupId, epoch);
      if (!epochCheck.valid) {
        return res.status(409).json({ error: epochCheck.reason });
      }
    }

    // --- Replay protection ---
    const ciphertextHash = sha256Hex(ciphertext);
    const seen = store.seenCiphertextHashes.get(conversationId) || new Set();
    if (seen.has(ciphertextHash)) {
      return res.status(409).json({ error: 'Duplicate ciphertext detected (replay attack)' });
    }
    seen.add(ciphertextHash);
    store.seenCiphertextHashes.set(conversationId, seen);

    // --- Store & fan-out ---
    const existingMessages = store.messages.get(conversationId) || [];
    const message = {
      id: randomUUID(),
      conversationId,
      senderId,
      ciphertext,
      contentType,
      epoch: epoch ?? null,
      sequenceNumber: existingMessages.length + 1,
      metadata: metadata || {},
      createdAt: new Date().toISOString(),
    };

    store.addMessage(conversationId, message);
    inboxSvc.fanOutMessage(conversationId, conversation.members, message);

    return res.status(201).json(message);
  });

  app.get('/v1/conversations/:conversationId/messages', (req, res) => {
    const { conversationId } = req.params;
    const requesterId = req.query.requesterId;
    const access = assertParticipant(store, conversationId, requesterId);
    if (access.error) {
      return res.status(access.error.status).json({ error: access.error.message });
    }

    const after = req.query.after;
    const messages = store.messages.get(conversationId) || [];
    const filtered = after ? messages.filter((m) => m.createdAt > after) : messages;
    return res.json({ items: filtered });
  });

  // -------------------------------------------------------------------------
  // MLS event transport (epoch state machine + fan-out)
  // -------------------------------------------------------------------------

  const mlsEventSchema = z
    .object({
      senderId: z.string().min(1),
      eventType: z.enum(['commit', 'proposal', 'welcome', 'key_package']),
      eventCiphertext: z.string().min(1),
      /** Required for commit, proposal, and welcome.  Optional for key_package. */
      epoch: z.number().int().nonnegative().optional(),
      /** Ed25519 signature over mlsEventSigningPayload(...).
       *  Required when REQUIRE_MESSAGE_SIGNATURES=true. */
      signature: z.string().min(1).optional(),
      /** Required for welcome events — the user being invited into the group. */
      targetUserId: z.string().min(1).optional(),
    })
    .refine((d) => d.eventType === 'key_package' || d.epoch != null, {
      message: 'epoch is required for commit, proposal, and welcome events',
      path: ['epoch'],
    })
    .refine((d) => d.eventType !== 'welcome' || d.targetUserId != null, {
      message: 'targetUserId is required for welcome events',
      path: ['targetUserId'],
    });

  app.post('/v1/conversations/:conversationId/mls/events', validateBody(mlsEventSchema), (req, res) => {
    const { conversationId } = req.params;
    const { senderId, eventType, eventCiphertext, epoch, signature, targetUserId } = req.validatedBody;

    const access = assertParticipant(store, conversationId, senderId);
    if (access.error) {
      return res.status(access.error.status).json({ error: access.error.message });
    }

    const conversation = access.conversation;
    const groupId = conversation.mlsGroupId;

    // --- Signature verification ---
    if (runtimeConfig.requireMessageSignatures || signature) {
      if (!signature) {
        return res.status(400).json({ error: 'MLS event signature is required' });
      }
      const sender = store.users.get(senderId);
      const payload = mlsEventSigningPayload(conversationId, senderId, eventType, epoch ?? 0, eventCiphertext);
      if (!verifyEd25519Signature(sender.identityKey, payload, signature)) {
        return res.status(403).json({ error: 'Invalid MLS event signature' });
      }
    }

    // --- Epoch state machine ---
    let epochResult = { valid: true };
    if (epoch != null) {
      switch (eventType) {
        case 'proposal':
          epochResult = epochSvc.processProposal(groupId, randomUUID(), epoch);
          break;
        case 'commit':
          epochResult = epochSvc.processCommit(groupId, randomUUID(), epoch);
          break;
        case 'welcome':
          epochResult = epochSvc.processWelcome(groupId, randomUUID(), epoch);
          break;
        default:
          break;
      }
      if (!epochResult.valid) {
        return res.status(409).json({ error: epochResult.reason });
      }
    }

    // --- targetUserId validation + membership update for welcome ---
    // Snapshot members BEFORE addMember so fan-out logic is unambiguous.
    const membersBeforeWelcome = [...conversation.members];
    if (eventType === 'welcome' && targetUserId) {
      if (!store.users.has(targetUserId)) {
        return res.status(404).json({ error: `Target user not found: ${targetUserId}` });
      }
      store.addMember(conversationId, targetUserId);
    }

    // --- Store event ---
    const existingEvents = store.mlsEvents.get(conversationId) || [];
    const event = {
      id: randomUUID(),
      conversationId,
      senderId,
      eventType,
      eventCiphertext,
      epoch: epoch ?? null,
      sequenceNumber: existingEvents.length + 1,
      targetUserId: targetUserId || null,
      createdAt: new Date().toISOString(),
    };

    store.addMlsEvent(conversationId, event);

    // --- Fan-out ---
    // For welcome: deliver only to targetUserId (using pre-welcome snapshot as
    // the broader members list for other event types).
    inboxSvc.fanOutMlsEvent(conversationId, membersBeforeWelcome, event, targetUserId);

    const response = { ...event };
    if (epochResult.currentEpoch != null) {
      response.groupEpoch = epochResult.currentEpoch;
    }
    return res.status(201).json(response);
  });

  app.get('/v1/conversations/:conversationId/mls/events', (req, res) => {
    const { conversationId } = req.params;
    const requesterId = req.query.requesterId;
    const access = assertParticipant(store, conversationId, requesterId);
    if (access.error) {
      return res.status(access.error.status).json({ error: access.error.message });
    }

    return res.json({ items: store.mlsEvents.get(conversationId) || [] });
  });

  /**
   * GET /v1/conversations/:conversationId/mls/epoch?requesterId=<userId>
   * Return the current MLS epoch state for the group.
   */
  app.get('/v1/conversations/:conversationId/mls/epoch', (req, res) => {
    const { conversationId } = req.params;
    const requesterId = req.query.requesterId;
    const access = assertParticipant(store, conversationId, requesterId);
    if (access.error) {
      return res.status(access.error.status).json({ error: access.error.message });
    }

    const conversation = access.conversation;
    const state = epochSvc.getState(conversation.mlsGroupId);
    return res.json({
      mlsGroupId: conversation.mlsGroupId,
      epoch: state.epoch,
      pendingProposals: state.pendingProposals.length,
      commitHistory: state.history,
    });
  });

  // -------------------------------------------------------------------------
  // Member inboxes (delivery service)
  // -------------------------------------------------------------------------

  /**
   * GET /v1/inbox?requesterId=<userId>[&conversationId=<id>][&type=application|mls_event]
   * Retrieve unread inbox entries for the requesting member.
   */
  app.get('/v1/inbox', (req, res) => {
    const requesterId = req.query.requesterId;
    if (!requesterId || !store.users.has(requesterId)) {
      return res.status(400).json({ error: 'requesterId must be a registered user' });
    }

    const filter = {};
    if (req.query.conversationId) filter.conversationId = req.query.conversationId;
    if (req.query.type) filter.messageType = req.query.type;

    const entries = inboxSvc.getInbox(requesterId, filter);
    return res.json({ items: entries });
  });

  /**
   * POST /v1/inbox/:inboxEntryId/ack?requesterId=<userId>
   * Acknowledge (mark as read) a specific inbox entry.
   */
  app.post('/v1/inbox/:inboxEntryId/ack', (req, res) => {
    const requesterId = req.query.requesterId;
    if (!requesterId || !store.users.has(requesterId)) {
      return res.status(400).json({ error: 'requesterId must be a registered user' });
    }

    const ok = inboxSvc.acknowledge(requesterId, req.params.inboxEntryId);
    if (!ok) {
      return res.status(404).json({ error: 'Inbox entry not found' });
    }
    return res.json({ acknowledged: true });
  });

  // -------------------------------------------------------------------------
  // File transfer (encrypted payload — key envelope tied to MLS epoch)
  // -------------------------------------------------------------------------

  const fileUploadSchema = z.object({
    conversationId: z.string().min(1),
    senderId: z.string().min(1),
    sha256: z.string().min(1),
    encryptedFileKeyEnvelope: z.string().min(1),
    /** MLS epoch under which the file key envelope was sealed.  Recommended. */
    epoch: z.coerce.number().int().nonnegative().optional(),
  });

  app.post('/v1/files/upload', upload.single('file'), async (req, res) => {
    if (!req.file) {
      return res.status(400).json({ error: 'Missing file' });
    }

    const parsed = fileUploadSchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: 'Invalid payload', details: parsed.error.issues });
    }

    const payload = parsed.data;
    const access = assertParticipant(store, payload.conversationId, payload.senderId);
    if (access.error) {
      return res.status(access.error.status).json({ error: access.error.message });
    }

    const mimeType = req.file.mimetype || 'application/octet-stream';
    if (!runtimeConfig.allowedMimeTypes.includes(mimeType)) {
      return res.status(415).json({ error: `Unsupported file mime type: ${mimeType}` });
    }

    const fileId = randomUUID();
    await fs.mkdir(runtimeConfig.uploadDir, { recursive: true });
    const filePath = path.join(runtimeConfig.uploadDir, `${fileId}.bin`);
    await fs.writeFile(filePath, req.file.buffer);

    const epochValue = payload.epoch ?? null;

    const metadata = {
      id: fileId,
      conversationId: payload.conversationId,
      senderId: payload.senderId,
      originalFileName: req.file.originalname,
      mimeType,
      byteLength: req.file.size,
      sha256: payload.sha256,
      encryptedFileKeyEnvelope: payload.encryptedFileKeyEnvelope,
      epoch: epochValue,
      storagePath: filePath,
      createdAt: new Date().toISOString(),
    };

    store.fileMetadata.set(fileId, metadata);

    return res.status(201).json({
      id: fileId,
      conversationId: metadata.conversationId,
      originalFileName: metadata.originalFileName,
      mimeType: metadata.mimeType,
      byteLength: metadata.byteLength,
      sha256: metadata.sha256,
      epoch: metadata.epoch,
      createdAt: metadata.createdAt,
    });
  });

  app.get('/v1/files/:fileId/metadata', (req, res) => {
    const requesterId = req.query.requesterId;
    const metadata = store.fileMetadata.get(req.params.fileId);
    if (!metadata) {
      return res.status(404).json({ error: 'File not found' });
    }

    const access = assertParticipant(store, metadata.conversationId, requesterId);
    if (access.error) {
      return res.status(access.error.status).json({ error: access.error.message });
    }

    const { storagePath, ...publicMetadata } = metadata;
    return res.json(publicMetadata);
  });

  app.get('/v1/files/:fileId/content', async (req, res) => {
    const requesterId = req.query.requesterId;
    const metadata = store.fileMetadata.get(req.params.fileId);
    if (!metadata) {
      return res.status(404).json({ error: 'File not found' });
    }

    const access = assertParticipant(store, metadata.conversationId, requesterId);
    if (access.error) {
      return res.status(access.error.status).json({ error: access.error.message });
    }

    const buffer = await fs.readFile(metadata.storagePath);
    res.setHeader('Content-Type', metadata.mimeType);
    res.setHeader('Content-Disposition', `attachment; filename="${metadata.originalFileName}"`);
    return res.send(buffer);
  });

  // -------------------------------------------------------------------------
  // Calling (placeholder)
  // -------------------------------------------------------------------------

  app.get('/v1/calling/capabilities', (_req, res) => {
    res.json({
      status: 'planned',
      supportedFutureCapabilities: ['1:1 voice', 'group voice', '1:1 video', 'group video'],
      note: 'Calling signaling and media keying will be added in a future phase.',
    });
  });

  // -------------------------------------------------------------------------
  // Error handler
  // -------------------------------------------------------------------------

  app.use((err, _req, res, _next) => {
    if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({ error: 'Uploaded file exceeds MAX_FILE_SIZE_BYTES' });
    }
    return res.status(500).json({ error: 'Internal server error' });
  });

  return app;
}

module.exports = { createApp };
