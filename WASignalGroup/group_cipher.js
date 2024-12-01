const queue_job = require('./queue_job');
const SenderKeyMessage = require('./sender_key_message');
const crypto = require('libsignal/src/crypto');

class GroupCipher {
  constructor(senderKeyStore, senderKeyName) {
    this.senderKeyStore = senderKeyStore;
    this.senderKeyName = senderKeyName;
  }

  queueJob(awaitable) {
    return queue_job(this.senderKeyName.toString(), awaitable)
  }

  async encrypt(paddedPlaintext) {
    return await this.queueJob(async () => {
      const record = await this.senderKeyStore.loadSenderKey(this.senderKeyName);
      const senderKeyState = record.getSenderKeyState();
      const iteration = senderKeyState.getSenderChainKey().getIteration()
      const senderKey = this.getSenderKey(senderKeyState, iteration === 0 ? 0 : iteration + 1)

      const ciphertext = await this.getCipherText(
        senderKey.getIv(),
        senderKey.getCipherKey(),
        paddedPlaintext
      );

      const senderKeyMessage = new SenderKeyMessage(
        senderKeyState.getKeyId(),
        senderKey.getIteration(),
        ciphertext,
        senderKeyState.getSigningKeyPrivate()
      );
      await this.senderKeyStore.storeSenderKey(this.senderKeyName, record);
      return senderKeyMessage.serialize()
    })
  }

  async decrypt(senderKeyMessageBytes) {
    return await this.queueJob(async () => {
      const record = await this.senderKeyStore.loadSenderKey(this.senderKeyName);
      const senderKeyMessage = new SenderKeyMessage(null, null, null, null, senderKeyMessageBytes);
      const senderKeyState = record.getSenderKeyState(senderKeyMessage.getKeyId());
      senderKeyMessage.verifySignature(senderKeyState.getSigningKeyPublic());
      const senderKey = this.getSenderKey(senderKeyState, senderKeyMessage.getIteration());
      const plaintext = await this.getPlainText(
        senderKey.getIv(),
        senderKey.getCipherKey(),
        senderKeyMessage.getCipherText()
      );

      await this.senderKeyStore.storeSenderKey(this.senderKeyName, record);

      return plaintext;
    })
  }

  getSenderKey(senderKeyState, iteration) {
    let senderChainKey = senderKeyState.getSenderChainKey();
    if (senderChainKey.getIteration() > iteration) if (senderKeyState.hasSenderMessageKey(iteration)) return senderKeyState.removeSenderMessageKey(iteration);

    while (senderChainKey.getIteration() < iteration) {
      senderKeyState.addSenderMessageKey(senderChainKey.getSenderMessageKey());
      senderChainKey = senderChainKey.getNext();
    }

    senderKeyState.setSenderChainKey(senderChainKey.getNext());
    return senderChainKey.getSenderMessageKey();
  }

  getPlainText(iv, key, ciphertext) {
    try {
      const plaintext = crypto.decrypt(key, ciphertext, iv);
      return plaintext;
    } catch { }
  }

  getCipherText(iv, key, plaintext) {
    try {
      iv = typeof iv === 'string' ? Buffer.from(iv, 'base64') : iv;
      key = typeof key === 'string' ? Buffer.from(key, 'base64') : key;
      const crypted = crypto.encrypt(key, Buffer.from(plaintext), iv);
      return crypted;
    } catch { }
  }
}

module.exports = GroupCipher;