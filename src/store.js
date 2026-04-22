const { randomUUID } = require('crypto');

class InMemoryStore {
  constructor() {
    // Core messaging
    this.users = new Map();
    this.conversations = new Map();
    this.messages = new Map();
    this.fileMetadata = new Map();
    this.mlsEvents = new Map();

    // MLS key distribution — RFC 9420 §10
    this.keyPackages = new Map();      // id -> KeyPackage record
    this.userKeyPackages = new Map();  // userId -> unclaimed id[]

    // MLS group epoch state
    this.groupEpochs = new Map();      // mlsGroupId -> EpochState

    // Delivery service per-member inboxes
    this.memberInboxes = new Map();    // userId -> InboxEntry[]

    // Replay protection: track SHA-256 hashes of seen ciphertexts per conversation
    this.seenCiphertextHashes = new Map(); // conversationId -> Set<string>
  }

  createUser(input) {
    const user = {
      id: input.id,
      displayName: input.displayName,
      identityKey: input.identityKey,
      createdAt: new Date().toISOString()
    };
    this.users.set(user.id, user);
    return user;
  }

  createConversation(input) {
    const id = randomUUID();
    const conversation = {
      id,
      type: input.type,
      name: input.name || null,
      members: [...new Set(input.members)],
      mlsGroupId: input.mlsGroupId,
      createdAt: new Date().toISOString()
    };
    this.conversations.set(id, conversation);
    this.messages.set(id, []);
    this.mlsEvents.set(id, []);
    this.seenCiphertextHashes.set(id, new Set());
    return conversation;
  }

  addMessage(conversationId, message) {
    const messages = this.messages.get(conversationId) || [];
    messages.push(message);
    this.messages.set(conversationId, messages);
    return message;
  }

  addMlsEvent(conversationId, event) {
    const events = this.mlsEvents.get(conversationId) || [];
    events.push(event);
    this.mlsEvents.set(conversationId, events);
    return event;
  }

  /**
   * Add a user to an existing conversation's member list.
   * Idempotent — calling with an existing member is a no-op.
   *
   * @param {string} conversationId
   * @param {string} userId
   * @returns {boolean}  false if the conversation does not exist
   */
  addMember(conversationId, userId) {
    const conversation = this.conversations.get(conversationId);
    if (!conversation) return false;
    if (!conversation.members.includes(userId)) {
      conversation.members.push(userId);
      this.conversations.set(conversationId, conversation);
    }
    return true;
  }
}

module.exports = { InMemoryStore };
