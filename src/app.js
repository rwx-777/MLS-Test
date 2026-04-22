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

function createApp({ store = new InMemoryStore(), runtimeConfig = config } = {}) {
  const app = express();

  const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: runtimeConfig.maxFileSizeBytes }
  });

  app.use(helmet());
  app.use(cors({ origin: false }));
  app.use(rateLimit({ windowMs: 60 * 1000, max: 240 }));
  app.use(express.json({ limit: '1mb' }));
  app.use(authMiddleware(runtimeConfig.apiKeys));

  app.get('/healthz', (_req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  const userSchema = z.object({
    id: z.string().min(1),
    displayName: z.string().min(1),
    identityKey: z.string().min(16)
  });

  app.post('/v1/users', validateBody(userSchema), (req, res) => {
    const { id } = req.validatedBody;
    if (store.users.has(id)) {
      return res.status(409).json({ error: 'User already exists' });
    }
    const user = store.createUser(req.validatedBody);
    return res.status(201).json(user);
  });

  const directConversationSchema = z.object({
    memberA: z.string().min(1),
    memberB: z.string().min(1),
    mlsGroupId: z.string().min(1)
  });

  app.post('/v1/conversations/direct', validateBody(directConversationSchema), (req, res) => {
    const { memberA, memberB, mlsGroupId } = req.validatedBody;
    if (!store.users.has(memberA) || !store.users.has(memberB)) {
      return res.status(404).json({ error: 'Members must exist' });
    }

    const existing = [...store.conversations.values()].find(
      (c) => c.type === 'direct' && c.members.length === 2 && c.members.includes(memberA) && c.members.includes(memberB)
    );

    if (existing) {
      return res.status(200).json(existing);
    }

    const conversation = store.createConversation({ type: 'direct', members: [memberA, memberB], mlsGroupId });
    return res.status(201).json(conversation);
  });

  const groupConversationSchema = z.object({
    name: z.string().min(1),
    members: z.array(z.string().min(1)).min(2),
    mlsGroupId: z.string().min(1)
  });

  app.post('/v1/conversations/group', validateBody(groupConversationSchema), (req, res) => {
    const { members } = req.validatedBody;
    const missing = members.find((member) => !store.users.has(member));
    if (missing) {
      return res.status(404).json({ error: `Unknown user: ${missing}` });
    }

    const conversation = store.createConversation({ type: 'group', ...req.validatedBody });
    return res.status(201).json(conversation);
  });

  const messageSchema = z.object({
    senderId: z.string().min(1),
    ciphertext: z.string().min(1),
    contentType: z.enum(['text', 'file', 'control']).default('text'),
    metadata: z.record(z.string(), z.unknown()).optional()
  });

  app.post('/v1/conversations/:conversationId/messages', validateBody(messageSchema), (req, res) => {
    const { conversationId } = req.params;
    const { senderId } = req.validatedBody;
    const access = assertParticipant(store, conversationId, senderId);
    if (access.error) {
      return res.status(access.error.status).json({ error: access.error.message });
    }

    const message = {
      id: randomUUID(),
      conversationId,
      senderId,
      ciphertext: req.validatedBody.ciphertext,
      contentType: req.validatedBody.contentType,
      metadata: req.validatedBody.metadata || {},
      createdAt: new Date().toISOString()
    };

    store.addMessage(conversationId, message);
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

  const mlsEventSchema = z.object({
    senderId: z.string().min(1),
    eventType: z.enum(['commit', 'proposal', 'welcome', 'key_package']),
    eventCiphertext: z.string().min(1)
  });

  app.post('/v1/conversations/:conversationId/mls/events', validateBody(mlsEventSchema), (req, res) => {
    const { conversationId } = req.params;
    const { senderId } = req.validatedBody;
    const access = assertParticipant(store, conversationId, senderId);
    if (access.error) {
      return res.status(access.error.status).json({ error: access.error.message });
    }

    const event = {
      id: randomUUID(),
      conversationId,
      ...req.validatedBody,
      createdAt: new Date().toISOString()
    };

    store.addMlsEvent(conversationId, event);
    return res.status(201).json(event);
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

  const fileUploadSchema = z.object({
    conversationId: z.string().min(1),
    senderId: z.string().min(1),
    sha256: z.string().min(1),
    encryptedFileKeyEnvelope: z.string().min(1)
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

    const metadata = {
      id: fileId,
      conversationId: payload.conversationId,
      senderId: payload.senderId,
      originalFileName: req.file.originalname,
      mimeType,
      byteLength: req.file.size,
      sha256: payload.sha256,
      encryptedFileKeyEnvelope: payload.encryptedFileKeyEnvelope,
      storagePath: filePath,
      createdAt: new Date().toISOString()
    };

    store.fileMetadata.set(fileId, metadata);

    return res.status(201).json({
      id: fileId,
      conversationId: metadata.conversationId,
      originalFileName: metadata.originalFileName,
      mimeType: metadata.mimeType,
      byteLength: metadata.byteLength,
      sha256: metadata.sha256,
      createdAt: metadata.createdAt
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

  app.get('/v1/calling/capabilities', (_req, res) => {
    res.json({
      status: 'planned',
      supportedFutureCapabilities: ['1:1 voice', 'group voice', '1:1 video', 'group video'],
      note: 'Calling signaling and media keying will be added in a future phase.'
    });
  });

  app.use((err, _req, res, _next) => {
    if (err instanceof multer.MulterError && err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({ error: 'Uploaded file exceeds MAX_FILE_SIZE_BYTES' });
    }
    return res.status(500).json({ error: 'Internal server error' });
  });

  return app;
}

module.exports = { createApp };
