const test = require('node:test');
const assert = require('node:assert/strict');
const request = require('supertest');
const { createApp } = require('../src/app');
const { InMemoryStore } = require('../src/store');

function buildTestApp() {
  const store = new InMemoryStore();
  return createApp({
    store,
    runtimeConfig: {
      port: 0,
      apiKeys: ['test-key'],
      maxFileSizeBytes: 1024 * 1024,
      allowedMimeTypes: ['application/octet-stream', 'text/plain'],
      uploadDir: '/tmp/mls-files-test'
    }
  });
}

test('health endpoint requires authentication', async () => {
  const app = buildTestApp();
  await request(app).get('/healthz').expect(401);
});

test('create users, direct conversation, and encrypted message flow', async () => {
  const app = buildTestApp();
  const auth = { Authorization: 'Bearer test-key' };

  await request(app)
    .post('/v1/users')
    .set(auth)
    .send({ id: 'alice', displayName: 'Alice', identityKey: 'alice-identity-key-12345' })
    .expect(201);

  await request(app)
    .post('/v1/users')
    .set(auth)
    .send({ id: 'bob', displayName: 'Bob', identityKey: 'bob-identity-key-12345' })
    .expect(201);

  const conversation = await request(app)
    .post('/v1/conversations/direct')
    .set(auth)
    .send({ memberA: 'alice', memberB: 'bob', mlsGroupId: 'group-alice-bob' })
    .expect(201);

  const conversationId = conversation.body.id;

  await request(app)
    .post(`/v1/conversations/${conversationId}/messages`)
    .set(auth)
    .send({
      senderId: 'alice',
      ciphertext: 'BASE64_ENCRYPTED_PAYLOAD',
      contentType: 'text',
      metadata: { epoch: 1 }
    })
    .expect(201);

  const messages = await request(app)
    .get(`/v1/conversations/${conversationId}/messages`)
    .query({ requesterId: 'bob' })
    .set(auth)
    .expect(200);

  assert.equal(messages.body.items.length, 1);
  assert.equal(messages.body.items[0].ciphertext, 'BASE64_ENCRYPTED_PAYLOAD');
});
