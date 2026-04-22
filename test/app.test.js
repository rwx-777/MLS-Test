const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const crypto = require('crypto');
const { createApp } = require('../src/app');
const { InMemoryStore } = require('../src/store');

function buildTestApp(overrides = {}) {
  const store = new InMemoryStore();
  return createApp({
    store,
    runtimeConfig: {
      port: 0,
      apiKeys: ['test-key'],
      maxFileSizeBytes: 1024 * 1024,
      allowedMimeTypes: ['application/octet-stream', 'text/plain'],
      uploadDir: '/tmp/mls-files-test',
      requireMessageSignatures: false,
      epochWindowSize: 2,
      ...overrides,
    },
  });
}

const AUTH = { Authorization: 'Bearer test-key' };

/** Create alice + bob + a direct conversation. Returns { app, conversationId }. */
async function setupDirectConversation(app) {
  await request(app).post('/v1/users').set(AUTH)
    .send({ id: 'alice', displayName: 'Alice', identityKey: 'alice-identity-key-12345' });
  await request(app).post('/v1/users').set(AUTH)
    .send({ id: 'bob', displayName: 'Bob', identityKey: 'bob-identity-key-12345' });
  const res = await request(app).post('/v1/conversations/direct').set(AUTH)
    .send({ memberA: 'alice', memberB: 'bob', mlsGroupId: 'group-alice-bob' });
  return { app, conversationId: res.body.id };
}

// ---------------------------------------------------------------------------
// Existing tests (unchanged behaviour)
// ---------------------------------------------------------------------------

test('health endpoint requires authentication', async () => {
  const app = buildTestApp();
  await request(app).get('/healthz').expect(401);
});

test('create users, direct conversation, and encrypted message flow', async () => {
  const app = buildTestApp();

  await request(app)
    .post('/v1/users')
    .set(AUTH)
    .send({ id: 'alice', displayName: 'Alice', identityKey: 'alice-identity-key-12345' })
    .expect(201);

  await request(app)
    .post('/v1/users')
    .set(AUTH)
    .send({ id: 'bob', displayName: 'Bob', identityKey: 'bob-identity-key-12345' })
    .expect(201);

  const conversation = await request(app)
    .post('/v1/conversations/direct')
    .set(AUTH)
    .send({ memberA: 'alice', memberB: 'bob', mlsGroupId: 'group-alice-bob' })
    .expect(201);

  const conversationId = conversation.body.id;

  await request(app)
    .post(`/v1/conversations/${conversationId}/messages`)
    .set(AUTH)
    .send({
      senderId: 'alice',
      ciphertext: 'BASE64_ENCRYPTED_PAYLOAD',
      contentType: 'text',
      metadata: { epoch: 1 },
    })
    .expect(201);

  const messages = await request(app)
    .get(`/v1/conversations/${conversationId}/messages`)
    .query({ requesterId: 'bob' })
    .set(AUTH)
    .expect(200);

  assert.equal(messages.body.items.length, 1);
  assert.equal(messages.body.items[0].ciphertext, 'BASE64_ENCRYPTED_PAYLOAD');
});

// ---------------------------------------------------------------------------
// Key package distribution
// ---------------------------------------------------------------------------

test('key package upload, count, and claim lifecycle', async () => {
  const app = buildTestApp();
  await request(app).post('/v1/users').set(AUTH)
    .send({ id: 'alice', displayName: 'Alice', identityKey: 'alice-identity-key-12345' });
  await request(app).post('/v1/users').set(AUTH)
    .send({ id: 'bob', displayName: 'Bob', identityKey: 'bob-identity-key-12345' });

  // Upload 2 key packages for alice
  const uploadRes = await request(app)
    .post('/v1/users/alice/key-packages')
    .set(AUTH)
    .send({ keyPackages: [
      { keyPackageData: 'KP_DATA_1' },
      { keyPackageData: 'KP_DATA_2' },
    ]})
    .expect(201);

  assert.equal(uploadRes.body.uploaded.length, 2);
  assert.equal(uploadRes.body.available, 2);

  // Count
  const countRes = await request(app)
    .get('/v1/users/alice/key-packages/count')
    .set(AUTH)
    .expect(200);
  assert.equal(countRes.body.available, 2);

  // Bob claims one of alice's key packages
  const claimRes = await request(app)
    .get('/v1/users/alice/key-packages/claim')
    .query({ requesterId: 'bob' })
    .set(AUTH)
    .expect(200);

  assert.equal(claimRes.body.userId, 'alice');
  assert.ok(claimRes.body.keyPackageData.startsWith('KP_DATA_'));
  assert.equal(claimRes.body.remainingAvailable, 1);

  // Claim again — gets the other package
  const claim2Res = await request(app)
    .get('/v1/users/alice/key-packages/claim')
    .query({ requesterId: 'bob' })
    .set(AUTH)
    .expect(200);
  assert.equal(claim2Res.body.remainingAvailable, 0);

  // Third claim — nothing left
  await request(app)
    .get('/v1/users/alice/key-packages/claim')
    .query({ requesterId: 'bob' })
    .set(AUTH)
    .expect(404);
});

test('key package upload requires a registered user', async () => {
  const app = buildTestApp();
  await request(app)
    .post('/v1/users/no-such-user/key-packages')
    .set(AUTH)
    .send({ keyPackages: [{ keyPackageData: 'KP_DATA' }] })
    .expect(404);
});

// ---------------------------------------------------------------------------
// MLS epoch tracking
// ---------------------------------------------------------------------------

test('MLS epoch: proposal then commit advances epoch', async () => {
  const app = buildTestApp();
  const { conversationId } = await setupDirectConversation(app);

  // Check initial epoch is 0
  const epochRes0 = await request(app)
    .get(`/v1/conversations/${conversationId}/mls/epoch`)
    .query({ requesterId: 'alice' })
    .set(AUTH)
    .expect(200);
  assert.equal(epochRes0.body.epoch, 0);

  // Send a proposal at epoch 0
  await request(app)
    .post(`/v1/conversations/${conversationId}/mls/events`)
    .set(AUTH)
    .send({ senderId: 'alice', eventType: 'proposal', eventCiphertext: 'PROPOSAL_CT', epoch: 0 })
    .expect(201);

  // Epoch still 0, 1 pending proposal
  const epochRes1 = await request(app)
    .get(`/v1/conversations/${conversationId}/mls/epoch`)
    .query({ requesterId: 'alice' })
    .set(AUTH)
    .expect(200);
  assert.equal(epochRes1.body.epoch, 0);
  assert.equal(epochRes1.body.pendingProposals, 1);

  // Commit at epoch 0 advances to epoch 1
  const commitRes = await request(app)
    .post(`/v1/conversations/${conversationId}/mls/events`)
    .set(AUTH)
    .send({ senderId: 'alice', eventType: 'commit', eventCiphertext: 'COMMIT_CT', epoch: 0 })
    .expect(201);
  assert.equal(commitRes.body.groupEpoch, 1);

  const epochRes2 = await request(app)
    .get(`/v1/conversations/${conversationId}/mls/epoch`)
    .query({ requesterId: 'alice' })
    .set(AUTH)
    .expect(200);
  assert.equal(epochRes2.body.epoch, 1);
  assert.equal(epochRes2.body.pendingProposals, 0);
  assert.equal(epochRes2.body.commitHistory.length, 1);
});

test('MLS epoch: commit at wrong epoch is rejected', async () => {
  const app = buildTestApp();
  const { conversationId } = await setupDirectConversation(app);

  // Epoch is 0; commit claiming epoch 1 must fail
  const res = await request(app)
    .post(`/v1/conversations/${conversationId}/mls/events`)
    .set(AUTH)
    .send({ senderId: 'alice', eventType: 'commit', eventCiphertext: 'COMMIT_CT', epoch: 1 })
    .expect(409);
  assert.ok(res.body.error.includes('epoch'));
});

test('MLS epoch: stale application message is rejected', async () => {
  const app = buildTestApp();
  const { conversationId } = await setupDirectConversation(app);

  // Advance to epoch 3 with three commits
  for (let e = 0; e < 3; e++) {
    await request(app)
      .post(`/v1/conversations/${conversationId}/mls/events`)
      .set(AUTH)
      .send({ senderId: 'alice', eventType: 'commit', eventCiphertext: `COMMIT_${e}`, epoch: e })
      .expect(201);
  }

  // Message from epoch 0 is now 3 epochs old — outside window of 2 → reject
  await request(app)
    .post(`/v1/conversations/${conversationId}/messages`)
    .set(AUTH)
    .send({ senderId: 'alice', ciphertext: 'OLD_CT', epoch: 0 })
    .expect(409);
});

// ---------------------------------------------------------------------------
// Replay protection
// ---------------------------------------------------------------------------

test('duplicate ciphertext is rejected as a replay attack', async () => {
  const app = buildTestApp();
  const { conversationId } = await setupDirectConversation(app);

  await request(app)
    .post(`/v1/conversations/${conversationId}/messages`)
    .set(AUTH)
    .send({ senderId: 'alice', ciphertext: 'UNIQUE_CIPHERTEXT_ABC' })
    .expect(201);

  // Identical ciphertext must be rejected
  const res = await request(app)
    .post(`/v1/conversations/${conversationId}/messages`)
    .set(AUTH)
    .send({ senderId: 'alice', ciphertext: 'UNIQUE_CIPHERTEXT_ABC' })
    .expect(409);
  assert.ok(res.body.error.toLowerCase().includes('replay'));
});

// ---------------------------------------------------------------------------
// Fan-out inbox delivery
// ---------------------------------------------------------------------------

test('message is delivered to all members inboxes', async () => {
  const app = buildTestApp();
  const { conversationId } = await setupDirectConversation(app);

  await request(app)
    .post(`/v1/conversations/${conversationId}/messages`)
    .set(AUTH)
    .send({ senderId: 'alice', ciphertext: 'FANOUT_CT_1' })
    .expect(201);

  // Bob's inbox should have the message
  const bobInbox = await request(app)
    .get('/v1/inbox')
    .query({ requesterId: 'bob' })
    .set(AUTH)
    .expect(200);
  assert.equal(bobInbox.body.items.length, 1);
  assert.equal(bobInbox.body.items[0].payload.ciphertext, 'FANOUT_CT_1');

  // Alice's inbox also receives a copy (multi-device support)
  const aliceInbox = await request(app)
    .get('/v1/inbox')
    .query({ requesterId: 'alice' })
    .set(AUTH)
    .expect(200);
  assert.equal(aliceInbox.body.items.length, 1);
});

test('inbox acknowledge marks entry as read', async () => {
  const app = buildTestApp();
  const { conversationId } = await setupDirectConversation(app);

  await request(app)
    .post(`/v1/conversations/${conversationId}/messages`)
    .set(AUTH)
    .send({ senderId: 'alice', ciphertext: 'ACK_CT_1' })
    .expect(201);

  const inboxRes = await request(app)
    .get('/v1/inbox')
    .query({ requesterId: 'bob' })
    .set(AUTH)
    .expect(200);
  const entryId = inboxRes.body.items[0].inboxEntryId;

  await request(app)
    .post(`/v1/inbox/${entryId}/ack`)
    .query({ requesterId: 'bob' })
    .set(AUTH)
    .expect(200);

  // Inbox is now empty
  const afterAck = await request(app)
    .get('/v1/inbox')
    .query({ requesterId: 'bob' })
    .set(AUTH)
    .expect(200);
  assert.equal(afterAck.body.items.length, 0);
});

// ---------------------------------------------------------------------------
// MLS Welcome fan-out and member auto-add
// ---------------------------------------------------------------------------

test('welcome event is delivered only to targetUserId and adds them to conversation', async () => {
  const app = buildTestApp();
  const { conversationId } = await setupDirectConversation(app);

  // charlie is not yet in the conversation
  await request(app).post('/v1/users').set(AUTH)
    .send({ id: 'charlie', displayName: 'Charlie', identityKey: 'charlie-identity-key-12345' });

  // First: commit epoch 0 → epoch 1, then send welcome at epoch 1
  await request(app)
    .post(`/v1/conversations/${conversationId}/mls/events`)
    .set(AUTH)
    .send({ senderId: 'alice', eventType: 'commit', eventCiphertext: 'COMMIT_ADD_CHARLIE', epoch: 0 })
    .expect(201);

  await request(app)
    .post(`/v1/conversations/${conversationId}/mls/events`)
    .set(AUTH)
    .send({
      senderId: 'alice',
      eventType: 'welcome',
      eventCiphertext: 'WELCOME_FOR_CHARLIE',
      epoch: 1,
      targetUserId: 'charlie',
    })
    .expect(201);

  // Charlie's inbox has the welcome event
  const charlieInbox = await request(app)
    .get('/v1/inbox')
    .query({ requesterId: 'charlie' })
    .set(AUTH)
    .expect(200);
  assert.equal(charlieInbox.body.items.length, 1);
  assert.equal(charlieInbox.body.items[0].eventType, 'welcome');

  // Alice's inbox does NOT have the welcome (sender excluded from welcome fan-out)
  const aliceInbox = await request(app)
    .get('/v1/inbox')
    .query({ requesterId: 'alice' })
    .set(AUTH)
    .expect(200);
  const aliceWelcomes = aliceInbox.body.items.filter((i) => i.eventType === 'welcome');
  assert.equal(aliceWelcomes.length, 0);

  // Charlie is now a member — can send messages
  await request(app)
    .post(`/v1/conversations/${conversationId}/messages`)
    .set(AUTH)
    .send({ senderId: 'charlie', ciphertext: 'CHARLIE_MSG', epoch: 1 })
    .expect(201);
});

test('welcome event requires targetUserId', async () => {
  const app = buildTestApp();
  const { conversationId } = await setupDirectConversation(app);

  // Advance to epoch 1 first
  await request(app)
    .post(`/v1/conversations/${conversationId}/mls/events`)
    .set(AUTH)
    .send({ senderId: 'alice', eventType: 'commit', eventCiphertext: 'COMMIT_CT', epoch: 0 })
    .expect(201);

  const res = await request(app)
    .post(`/v1/conversations/${conversationId}/mls/events`)
    .set(AUTH)
    .send({ senderId: 'alice', eventType: 'welcome', eventCiphertext: 'WELCOME_CT', epoch: 1 })
    .expect(400);
  assert.ok(res.body.error || res.body.details);
});

// ---------------------------------------------------------------------------
// Commit fan-out (not delivered back to sender)
// ---------------------------------------------------------------------------

test('commit is fan-out to all members except the sender', async () => {
  const app = buildTestApp();
  const { conversationId } = await setupDirectConversation(app);

  await request(app)
    .post(`/v1/conversations/${conversationId}/mls/events`)
    .set(AUTH)
    .send({ senderId: 'alice', eventType: 'commit', eventCiphertext: 'COMMIT_CT', epoch: 0 })
    .expect(201);

  // Bob should receive the commit in his inbox
  const bobInbox = await request(app)
    .get('/v1/inbox')
    .query({ requesterId: 'bob' })
    .set(AUTH)
    .expect(200);
  const bobCommits = bobInbox.body.items.filter((i) => i.eventType === 'commit');
  assert.equal(bobCommits.length, 1);

  // Alice (sender) should NOT receive her own commit in inbox
  const aliceInbox = await request(app)
    .get('/v1/inbox')
    .query({ requesterId: 'alice' })
    .set(AUTH)
    .expect(200);
  const aliceCommits = aliceInbox.body.items.filter((i) => i.eventType === 'commit');
  assert.equal(aliceCommits.length, 0);
});

// ---------------------------------------------------------------------------
// Ed25519 signature verification (requireMessageSignatures=true)
// ---------------------------------------------------------------------------

test('message signature is verified when requireMessageSignatures is enabled', async () => {
  // Generate a real Ed25519 key pair
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const identityKeyBase64 = publicKey.export({ format: 'der', type: 'spki' }).toString('base64');

  const app = buildTestApp({ requireMessageSignatures: true });

  await request(app).post('/v1/users').set(AUTH)
    .send({ id: 'signer', displayName: 'Signer', identityKey: identityKeyBase64 });
  await request(app).post('/v1/users').set(AUTH)
    .send({ id: 'receiver', displayName: 'Receiver', identityKey: 'receiver-identity-key-12345' });

  const convRes = await request(app).post('/v1/conversations/direct').set(AUTH)
    .send({ memberA: 'signer', memberB: 'receiver', mlsGroupId: 'sig-test-group' });
  const conversationId = convRes.body.id;

  const ciphertext = 'SIGNED_PAYLOAD';
  const epoch = 0;
  const payload = JSON.stringify({ conversationId, senderId: 'signer', epoch, ciphertext });
  const sig = crypto.sign(null, Buffer.from(payload, 'utf8'), privateKey).toString('base64');

  // Valid signature → accepted
  await request(app)
    .post(`/v1/conversations/${conversationId}/messages`)
    .set(AUTH)
    .send({ senderId: 'signer', ciphertext, epoch, signature: sig })
    .expect(201);

  // No signature → rejected
  await request(app)
    .post(`/v1/conversations/${conversationId}/messages`)
    .set(AUTH)
    .send({ senderId: 'signer', ciphertext: 'OTHER_CT', epoch })
    .expect(400);

  // Bad signature → rejected
  const badSig = Buffer.alloc(64).toString('base64');
  await request(app)
    .post(`/v1/conversations/${conversationId}/messages`)
    .set(AUTH)
    .send({ senderId: 'signer', ciphertext: 'THIRD_CT', epoch, signature: badSig })
    .expect(403);
});

// ---------------------------------------------------------------------------
// Message sequence numbers
// ---------------------------------------------------------------------------

test('messages are assigned monotonically increasing sequence numbers', async () => {
  const app = buildTestApp();
  const { conversationId } = await setupDirectConversation(app);

  for (let i = 1; i <= 3; i++) {
    const res = await request(app)
      .post(`/v1/conversations/${conversationId}/messages`)
      .set(AUTH)
      .send({ senderId: 'alice', ciphertext: `CT_SEQ_${i}` })
      .expect(201);
    assert.equal(res.body.sequenceNumber, i);
  }
});

