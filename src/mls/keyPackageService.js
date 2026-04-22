'use strict';

const { randomUUID } = require('crypto');
const { verifyEd25519Signature, keyPackageSigningPayload } = require('./crypto');

/**
 * Key Package Distribution Service
 *
 * Manages one-time-use key packages for MLS group membership operations.
 * Each key package contains the cryptographic material (HPKE public key +
 * credential + self-signature) needed for another member to add this user to
 * an MLS group (RFC 9420 §10).
 *
 * Key packages are claimed (consumed) exactly once. When requireSignatures is
 * enabled the server validates the self-signature before storing the package.
 */
class KeyPackageService {
  /**
   * @param {import('../store').InMemoryStore} store
   */
  constructor(store) {
    this.store = store;
  }

  /**
   * Upload one or more key packages for a user.
   *
   * @param {string} userId
   * @param {Array<{keyPackageData: string, signature?: string}>} keyPackages
   * @param {string} identityKey         User's identity public key (base64 DER)
   * @param {boolean} requireSignatures  Enforce self-signature verification
   * @returns {{ uploaded: Array<{id: string, createdAt: string}>, skipped: number }}
   */
  upload(userId, keyPackages, identityKey, requireSignatures) {
    const uploaded = [];
    let skipped = 0;

    for (const kp of keyPackages) {
      if (requireSignatures) {
        const payload = keyPackageSigningPayload(userId, kp.keyPackageData);
        if (!verifyEd25519Signature(identityKey, payload, kp.signature || '')) {
          skipped++;
          continue;
        }
      }

      const id = randomUUID();
      const record = {
        id,
        userId,
        keyPackageData: kp.keyPackageData,
        signature: kp.signature || null,
        createdAt: new Date().toISOString(),
        claimed: false,
      };
      this.store.keyPackages.set(id, record);
      const ids = this.store.userKeyPackages.get(userId) || [];
      ids.push(id);
      this.store.userKeyPackages.set(userId, ids);
      uploaded.push({ id, createdAt: record.createdAt });
    }

    return { uploaded, skipped };
  }

  /**
   * Claim (consume) one key package for a user.
   * Once claimed the package is marked consumed and cannot be reused.
   *
   * @param {string} userId  User whose key package to claim
   * @returns {object|null}  The claimed key package record, or null if none available
   */
  claim(userId) {
    const ids = this.store.userKeyPackages.get(userId) || [];
    const availableId = ids.find((id) => {
      const kp = this.store.keyPackages.get(id);
      return kp && !kp.claimed;
    });

    if (!availableId) {
      return null;
    }

    const kp = this.store.keyPackages.get(availableId);
    kp.claimed = true;
    kp.claimedAt = new Date().toISOString();
    this.store.keyPackages.set(availableId, kp);

    // Rebuild the unclaimed list (exclude the just-claimed id)
    const remaining = ids.filter((id) => {
      const k = this.store.keyPackages.get(id);
      return k && !k.claimed;
    });
    this.store.userKeyPackages.set(userId, remaining);

    return {
      id: kp.id,
      userId: kp.userId,
      keyPackageData: kp.keyPackageData,
      signature: kp.signature,
      createdAt: kp.createdAt,
    };
  }

  /**
   * Count unclaimed key packages available for a user.
   *
   * @param {string} userId
   * @returns {number}
   */
  countAvailable(userId) {
    const ids = this.store.userKeyPackages.get(userId) || [];
    return ids.filter((id) => {
      const kp = this.store.keyPackages.get(id);
      return kp && !kp.claimed;
    }).length;
  }
}

module.exports = { KeyPackageService };
