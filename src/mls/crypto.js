'use strict';

const crypto = require('crypto');

/**
 * Verify an Ed25519 digital signature.
 *
 * @param {string} publicKeyBase64  Base64-encoded DER SubjectPublicKeyInfo for an Ed25519 key
 * @param {Buffer|string} data      Data that was signed (UTF-8 encoded when a string)
 * @param {string} signatureBase64  Base64-encoded raw 64-byte Ed25519 signature
 * @returns {boolean}
 */
function verifyEd25519Signature(publicKeyBase64, data, signatureBase64) {
  try {
    const keyDer = Buffer.from(publicKeyBase64, 'base64');
    const publicKey = crypto.createPublicKey({ key: keyDer, format: 'der', type: 'spki' });
    const sig = Buffer.from(signatureBase64, 'base64');
    const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
    return crypto.verify(null, buf, publicKey, sig);
  } catch {
    return false;
  }
}

/**
 * Return the SHA-256 digest of data as a hex string.
 *
 * @param {Buffer|string} data
 * @returns {string}
 */
function sha256Hex(data) {
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  return crypto.createHash('sha256').update(buf).digest('hex');
}

/**
 * Canonical deterministic JSON signing payload for an application message.
 * Clients must sign exactly this string (UTF-8) to produce the message signature.
 *
 * @param {string} conversationId
 * @param {string} senderId
 * @param {number} epoch
 * @param {string} ciphertext
 * @returns {string}
 */
function messageSigningPayload(conversationId, senderId, epoch, ciphertext) {
  return JSON.stringify({ conversationId, senderId, epoch, ciphertext });
}

/**
 * Canonical deterministic JSON signing payload for an MLS event envelope.
 *
 * @param {string} conversationId
 * @param {string} senderId
 * @param {string} eventType
 * @param {number} epoch
 * @param {string} eventCiphertext
 * @returns {string}
 */
function mlsEventSigningPayload(conversationId, senderId, eventType, epoch, eventCiphertext) {
  return JSON.stringify({ conversationId, senderId, eventType, epoch, eventCiphertext });
}

/**
 * Canonical deterministic JSON signing payload for a key package upload.
 * The user self-signs each key package with their identity key.
 *
 * @param {string} userId
 * @param {string} keyPackageData  Base64-encoded raw key package bytes
 * @returns {string}
 */
function keyPackageSigningPayload(userId, keyPackageData) {
  return JSON.stringify({ userId, keyPackageData });
}

module.exports = {
  verifyEd25519Signature,
  sha256Hex,
  messageSigningPayload,
  mlsEventSigningPayload,
  keyPackageSigningPayload,
};
