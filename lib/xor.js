const sodium = require('sodium-universal')

module.exports = class XOR {
  constructor (nonces, split) {
    this.rnonce = nonces.rnonce
    this.tnonce = nonces.tnonce
    this.rx = sodium.crypto_stream_xor_instance(this.rnonce, split.rx.slice(0, 32))
    this.tx = sodium.crypto_stream_xor_instance(this.tnonce, split.tx.slice(0, 32))
  }

  encrypt (data) {
    this.tx.update(data, data)
    return data
  }

  decrypt (data) {
    this.rx.update(data, data)
    return data
  }

  destroy () {
    this.tx.final()
    this.rx.final()
  }

  static nonce () {
    const buf = Buffer.allocUnsafe(24)
    sodium.randombytes_buf(buf)
    return buf
  }
}
