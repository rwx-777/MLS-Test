'use strict';

/**
 * MLS Group Epoch Service
 *
 * Tracks the epoch state for each MLS group and enforces the strict ordering
 * rules required by RFC 9420:
 *
 *  - Proposals reference the current epoch and are queued.
 *  - A Commit references the current epoch, clears pending proposals,
 *    and advances the epoch by exactly 1.
 *  - Application messages must reference an epoch within a sliding window
 *    of recent epochs to tolerate transient key-update transitions.
 *  - Welcome messages reference the epoch a newly-invited member joins at.
 *
 * The server cannot verify the cryptographic contents of MLS messages because
 * it holds no group secrets.  It enforces ordering invariants and relays the
 * opaque encrypted envelopes unchanged.
 */
class EpochService {
  /**
   * @param {import('../store').InMemoryStore} store
   * @param {number} epochWindowSize  How many past epochs application messages are accepted from
   */
  constructor(store, epochWindowSize = 2) {
    this.store = store;
    this.epochWindowSize = epochWindowSize;
  }

  /**
   * Return the current epoch state for a group, defaulting to epoch 0 if
   * the group has not been initialised yet.
   *
   * @param {string} groupId
   * @returns {{ epoch: number, pendingProposals: Array, history: Array }}
   */
  getState(groupId) {
    return (
      this.store.groupEpochs.get(groupId) || {
        epoch: 0,
        pendingProposals: [],
        history: [],
      }
    );
  }

  /**
   * Initialise epoch state for a newly-created group.
   * Idempotent: a second call for the same group is a no-op.
   *
   * @param {string} groupId
   * @returns {{ epoch: number }}
   */
  initGroup(groupId) {
    if (!this.store.groupEpochs.has(groupId)) {
      this.store.groupEpochs.set(groupId, { epoch: 0, pendingProposals: [], history: [] });
    }
    return { epoch: this.getState(groupId).epoch };
  }

  /**
   * Process a Proposal event.
   * The proposal must reference the current group epoch.
   *
   * @param {string} groupId
   * @param {string} eventId
   * @param {number} epoch
   * @returns {{ valid: boolean, currentEpoch?: number, reason?: string }}
   */
  processProposal(groupId, eventId, epoch) {
    const state = this.getState(groupId);
    if (epoch !== state.epoch) {
      return {
        valid: false,
        reason: `Proposal epoch ${epoch} does not match group epoch ${state.epoch}`,
      };
    }
    state.pendingProposals.push({ eventId, epoch, receivedAt: new Date().toISOString() });
    this.store.groupEpochs.set(groupId, state);
    return { valid: true, currentEpoch: state.epoch };
  }

  /**
   * Process a Commit event.
   * The commit must reference the current epoch; on success the epoch advances
   * by 1 and all pending proposals are cleared.
   *
   * @param {string} groupId
   * @param {string} eventId
   * @param {number} epoch
   * @returns {{ valid: boolean, previousEpoch?: number, currentEpoch?: number, reason?: string }}
   */
  processCommit(groupId, eventId, epoch) {
    const state = this.getState(groupId);
    if (epoch !== state.epoch) {
      return {
        valid: false,
        reason: `Commit epoch ${epoch} does not match group epoch ${state.epoch}`,
      };
    }
    const newEpoch = epoch + 1;
    state.history.push({
      eventId,
      fromEpoch: epoch,
      toEpoch: newEpoch,
      proposalsCommitted: state.pendingProposals.length,
      committedAt: new Date().toISOString(),
    });
    state.pendingProposals = [];
    state.epoch = newEpoch;
    this.store.groupEpochs.set(groupId, state);
    return { valid: true, previousEpoch: epoch, currentEpoch: newEpoch };
  }

  /**
   * Process a Welcome event.
   * The welcome must reference the current epoch (the one the new member joins).
   *
   * @param {string} groupId
   * @param {string} eventId
   * @param {number} epoch
   * @returns {{ valid: boolean, currentEpoch?: number, reason?: string }}
   */
  processWelcome(groupId, eventId, epoch) {
    const state = this.getState(groupId);
    if (epoch !== state.epoch) {
      return {
        valid: false,
        reason: `Welcome epoch ${epoch} does not match group epoch ${state.epoch}`,
      };
    }
    return { valid: true, currentEpoch: state.epoch };
  }

  /**
   * Validate the epoch on an application message.
   * Messages are accepted from any epoch in the window
   * [currentEpoch - windowSize, currentEpoch].
   *
   * @param {string} groupId
   * @param {number} epoch
   * @returns {{ valid: boolean, currentEpoch?: number, reason?: string }}
   */
  validateMessageEpoch(groupId, epoch) {
    const state = this.getState(groupId);
    if (epoch > state.epoch) {
      return {
        valid: false,
        reason: `Message epoch ${epoch} is ahead of group epoch ${state.epoch}`,
      };
    }
    if (state.epoch - epoch > this.epochWindowSize) {
      return {
        valid: false,
        reason: `Message epoch ${epoch} is outside the acceptance window (current: ${state.epoch}, window: ${this.epochWindowSize})`,
      };
    }
    return { valid: true, currentEpoch: state.epoch };
  }
}

module.exports = { EpochService };
