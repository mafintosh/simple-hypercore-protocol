const Handshake = require('./lib/handshake')
const messages = require('./messages')
const XOR = require('./lib/xor')
const SMC = require('simple-message-channels')
const sodium = require('sodium-universal')

const CAP_NS_BUF = Buffer.from('capability')

module.exports = class SimpleProtocol {
  constructor (initiator, options) {
    this.options = options || {}
    this.remotePayload = null
    this.destroyed = false

    this._payload = { nonce: XOR.nonce() }
    this._pending = []
    this._handshake = new Handshake(initiator, messages.NoisePayload.encode(this._payload), options, this._onhandshake.bind(this))
    this._split = null
    this._encryption = null

    this._messages = new SMC({
      types: [
        { context: this, onmessage: onopen, encoding: messages.Open },
        { context: this, onmessage: onhandshake, encoding: messages.Handshake },
        { context: this, onmessage: oninfo, encoding: messages.Info },
        { context: this, onmessage: onhave, encoding: messages.Have },
        { context: this, onmessage: onunhave, encoding: messages.Unhave },
        { context: this, onmessage: onwant, encoding: messages.Want },
        { context: this, onmessage: onunwant, encoding: messages.Unwant },
        { context: this, onmessage: onrequest, encoding: messages.Request },
        { context: this, onmessage: oncancel, encoding: messages.Cancel },
        { context: this, onmessage: ondata, encoding: messages.Data }
      ]
    })
  }

  open (ch, message) {
    return this._send(ch, 0, message)
  }

  handshake (ch, message) {
    return this._send(ch, 1, message)
  }

  info (ch, message) {
    return this._send(ch, 2, message)
  }

  have (ch, message) {
    return this._send(ch, 3, message)
  }

  unhave (ch, message) {
    return this._send(ch, 4, message)
  }

  want (ch, message) {
    return this._send(ch, 5, message)
  }

  unwant (ch, message) {
    return this._send(ch, 6, message)
  }

  request (ch, message) {
    return this._send(ch, 7, message)
  }

  cancel (ch, message) {
    return this._send(ch, 8, message)
  }

  data (ch, message) {
    return this._send(ch, 9, message)
  }

  _onhandshake (err, remotePayload, split, overflow) {
    if (err) return this.destroy(err)
    if (!remotePayload) return this.destroy(new Error('Remote did not include a handshake payload'))

    try {
      remotePayload = messages.NoisePayload.decode(remotePayload)
    } catch (_) {
      return this.destroy(new Error('Could not parse remote payload'))
    }

    this._handshake = null
    this._split = split
    this._encryption = new XOR({ rnonce: remotePayload.nonce, tnonce: this._payload.nonce }, split)
    this.remotePayload = remotePayload

    if (overflow) this.recv(overflow)
    while (this._pending.length && !this.destroyed) {
      this._sendNow(...this._pending.shift())
    }
  }

  _send (channel, type, message) {
    if (this._handshake || this._pending.length) {
      this._pending.push([channel, type, message])
      return false
    }

    return this._sendNow(channel, type, message)
  }

  _sendNow (channel, type, message) {
    if (type === 0 && message.key && !message.capability) {
      message.capability = this.capability(message.key)
      message.key = null
    }

    let data = this._messages.send(channel, type, message)

    if (this._encryption !== null) {
      data = this._encryption.encrypt(data)
    }

    return this.options.send(data)
  }

  capability (key) {
    if (!this._split) return null
    const out = Buffer.allocUnsafe(32)
    sodium.crypto_generichash_batch(out, [
      CAP_NS_BUF,
      this._split.tx.slice(0, 32),
      key
    ], this._split.rx.slice(0, 32))
    return out
  }

  remoteCapability (key) {
    if (!this._split) return null
    const out = Buffer.allocUnsafe(32)
    sodium.crypto_generichash_batch(out, [
      CAP_NS_BUF,
      this._split.rx.slice(0, 32),
      key
    ], this._split.tx.slice(0, 32))
    return out
  }

  recv (data) {
    if (this.destroyed) return

    if (this._handshake !== null) {
      this._handshake.recv(data)
      return
    }

    if (this._encryption !== null) {
      data = this._encryption.decrypt(data)
    }

    if (!this._messages.recv(data)) {
      this.destroy(this._messages.error)
    }
  }

  destroy (err) {
    if (this.destroyed) return
    this.destroyed = true
    if (this._encryption) this._encryption.final()
    if (this.options.destroy) this.options.destroy(err)
  }
}

function onopen (ch, message, self) {
  if (self.options.onopen) self.options.onopen(ch, message)
}

function onhandshake (ch, message, self) {
  if (self.options.onhandshake) self.options.onhandshake(ch, message)
}

function oninfo (ch, message, self) {
  if (self.options.oninfo) self.options.oninfo(ch, message)
}

function onhave (ch, message, self) {
  if (self.options.onhave) self.options.onhave(ch, message)
}

function onunhave (ch, message, self) {
  if (self.options.onunhave) self.options.onunhave(ch, message)
}

function onwant (ch, message, self) {
  if (self.options.onwant) self.options.onwant(ch, message)
}

function onunwant (ch, message, self) {
  if (self.options.onunwant) self.options.onunwant(ch, message)
}

function onrequest (ch, message, self) {
  if (self.options.onrequest) self.options.onrequest(ch, message)
}

function oncancel (ch, message, self) {
  if (self.options.oncancel) self.options.oncancel(ch, message)
}

function ondata (ch, message, self) {
  if (self.options.ondata) self.options.ondata(ch, message)
}
