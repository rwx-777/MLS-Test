'use strict';

const { randomUUID } = require('crypto');

/**
 * Member Inbox Service — Delivery Service fan-out
 *
 * When a message or MLS event arrives the server pushes a copy into each
 * recipient's personal inbox.  Members poll their inbox to retrieve items in
 * strict delivery order.  Items remain in the inbox until acknowledged.
 *
 * Fan-out routing rules:
 *   application message  → all conversation members (including sender, for
 *                           multi-device support)
 *   commit / proposal    → all members except the sender (sender already holds
 *                           the event locally)
 *   welcome              → only the targetUserId being invited into the group
 *   key_package          → all members
 */
class InboxService {
  /**
   * @param {import('../store').InMemoryStore} store
   */
  constructor(store) {
    this.store = store;
  }

  /**
   * Fan-out an application message to all conversation members.
   *
   * @param {string}   conversationId
   * @param {string[]} members
   * @param {object}   message  Stored message record
   */
  fanOutMessage(conversationId, members, message) {
    for (const memberId of members) {
      this._push(memberId, {
        inboxEntryId: randomUUID(),
        conversationId,
        messageType: 'application',
        payload: message,
        deliveredAt: new Date().toISOString(),
      });
    }
  }

  /**
   * Fan-out an MLS event to the appropriate recipients.
   *
   * @param {string}   conversationId
   * @param {string[]} members       Current conversation members
   * @param {object}   event         Stored MLS event record
   * @param {string}   [targetUserId]  Required for welcome events
   */
  fanOutMlsEvent(conversationId, members, event, targetUserId) {
    let recipients;
    switch (event.eventType) {
      case 'welcome':
        recipients = targetUserId ? [targetUserId] : [];
        break;
      case 'commit':
      case 'proposal':
        recipients = members.filter((m) => m !== event.senderId);
        break;
      default:
        recipients = members;
        break;
    }

    for (const memberId of recipients) {
      this._push(memberId, {
        inboxEntryId: randomUUID(),
        conversationId,
        messageType: 'mls_event',
        eventType: event.eventType,
        payload: event,
        deliveredAt: new Date().toISOString(),
      });
    }
  }

  /**
   * Retrieve unread inbox entries for a member, optionally filtered.
   *
   * @param {string} userId
   * @param {{ conversationId?: string, messageType?: string }} [filter]
   * @returns {object[]}
   */
  getInbox(userId, filter = {}) {
    let entries = (this.store.memberInboxes.get(userId) || []).filter((e) => !e.read);
    if (filter.conversationId) {
      entries = entries.filter((e) => e.conversationId === filter.conversationId);
    }
    if (filter.messageType) {
      entries = entries.filter((e) => e.messageType === filter.messageType);
    }
    return entries;
  }

  /**
   * Acknowledge (mark as read) a specific inbox entry.
   *
   * @param {string} userId
   * @param {string} inboxEntryId
   * @returns {boolean}  true if found and updated
   */
  acknowledge(userId, inboxEntryId) {
    const entries = this.store.memberInboxes.get(userId) || [];
    const entry = entries.find((e) => e.inboxEntryId === inboxEntryId);
    if (!entry) return false;
    entry.read = true;
    this.store.memberInboxes.set(userId, entries);
    return true;
  }

  /** @private */
  _push(userId, entry) {
    const entries = this.store.memberInboxes.get(userId) || [];
    entries.push({ ...entry, read: false });
    this.store.memberInboxes.set(userId, entries);
  }
}

module.exports = { InboxService };
