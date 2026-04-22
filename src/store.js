const { randomUUID } = require('crypto');

class InMemoryStore {
  constructor() {
    this.users = new Map();
    this.conversations = new Map();
    this.messages = new Map();
    this.fileMetadata = new Map();
    this.mlsEvents = new Map();
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
}

module.exports = { InMemoryStore };
