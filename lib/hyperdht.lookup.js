'use strict'

const crypto = require('crypto')
const HyperDHT = require('hyperdht')
const LRU = require('lru')

const CRYPTO_ALGOS = Object.freeze([
  'hmac-sha256',
  'hmac-sha384'
])

/**
 * @typedef {Object} KeyPair
 * @property {Buffer} publicKey
 * @property {Buffer} secretKey
 */

/**
 * @typedef {Object} LookupCrypto
 * @property {string} algo
 * @property {any} key
 */

class HyperDHTLookup {
  /**
   * @param {Object} opts
   * @param {HyperDHT} opts.dht
   * @param {KeyPair} opts.keyPair
   * @param {number} [opts.cachelTTL]
   * @param {number} [opts.cacheLength]
   * @param {number} [opts.announceTTL]
   * @param {LookupCrypto} [opts.crypto]
   * @param {Buffer} [opts.capability]
   */
  constructor (opts) {
    this._dht = opts.dht
    this._keyPair = opts.keyPair
    this._cache = new LRU({
      max: opts.cacheLength || 1024,
      maxAge: opts.cachelTTL || 5 * 60 * 1000
    })

    if (opts.crypto && !CRYPTO_ALGOS.includes(opts.crypto.algo)) {
      throw new Error('ERR_CRYPTO_ALGO_NOT_SUPPORTED')
    }
    this._cryptoOpts = opts.crypto

    if (opts.capability && !Buffer.isBuffer(opts.capability)) {
      throw new Error('ERR_CAPABILITY_INALID')
    }
    this._requestOpts = { capability: opts.capability }

    /** @type {Map<string, { topic: string, keyPair: KeyPair|null }>} */
    this._topicMap = new Map()
    this._announceTTL = opts.announceTTL || 5 * 60 * 1000
    this._announceItvRunning = false
  }

  start () {
    if (this._announceItv) {
      throw new Error('ERR_LOOKUP_ALREADY_STARTED')
    }
    this._announceItv = setInterval(async () => {
      if (this._announceItvRunning) {
        return
      }

      this._announceItvRunning = true
      for (const { topic, keyPair } of this._topicMap.values()) {
        await this.announce(topic, keyPair).catch(() => { })
      }
      this._announceItvRunning = false
    }, this._announceTTL)
  }

  async stop () {
    clearInterval(this._announceItv)
    this._announceItv = null
    for (const { topic, keyPair } of this._topicMap.values()) {
      await this.unnannounce(topic, keyPair).catch(() => { })
    }
    this._topicMap.clear()
    this._announceItvRunning = false
    this._cache.clear()
  }

  /**
   * Encodes a user friendly topic in format acceptable by DHTs
   * @param {string} topic
   * @returns {Buffer}
   */
  encodeTopic (topic) {
    let buff = Buffer.from(topic, 'utf-8')

    switch (this._cryptoOpts?.algo) {
      case 'hmac-sha256':
        buff = crypto.createHmac('sha256', this._cryptoOpts.key).update(buff).digest()
        break
      case 'hmac-sha384':
        buff = crypto.createHmac('sha384', this._cryptoOpts.key).update(buff).digest()
        break
    }

    return HyperDHT.hash(buff)
  }

  /**
   * @returns {{ capability?: Buffer }}
   */
  reqOpts () {
    return this._requestOpts
  }

  /**
   * Announces a topic once for key pair
   * @param {string} topic
   * @param {KeyPair} [keyPair]
   */
  async announce (topic, keyPair = null) {
    keyPair ??= this._keyPair
    const topicHash = this.encodeTopic(topic)
    await this._dht.announce(topicHash, keyPair).finished()
  }

  /**
   * Announces topic for key pair on regular interval
   * @param {string} topic
   * @param {KeyPair} [keyPair]
   */
  async announceInterval (topic, keyPair = null) {
    keyPair ??= this._keyPair
    const key = `${topic}:${keyPair.publicKey.toString()}`
    if (this._topicMap.has(key)) {
      return
    }

    this._topicMap.set(key, { topic, keyPair })
    await this.announce(topic, keyPair)
  }

  /**
   * Unannounces a topic once for key pair
   * @param {string} topic
   * @param {KeyPair} [keyPair]
   */
  async unnannounce (topic, keyPair = null) {
    keyPair ??= this._keyPair
    const topicHash = this.encodeTopic(topic)
    await this._dht.unannounce(topicHash, keyPair)
  }

  /**
   * Removes topic for key pair from interval announcements
   * @param {string} topic
   * @param {KeyPair} [keyPair]
   */
  async unnannounceInterval (topic, keyPair = null) {
    keyPair ??= this._keyPair
    const key = `${topic}:${keyPair.publicKey.toString()}`
    if (!this._topicMap.has(key)) {
      return
    }

    this._topicMap.delete(key)
    await this.unnannounce(topic, keyPair)
  }

  /**
   * @param {string} topic
   * @param {boolean} [cached]
   * @returns {Promise<Array<string>>}
   */
  async lookup (topic, cached = true) {
    const topicHash = this.encodeTopic(topic)
    const ckey = `dht:lookup:${topicHash.toString('hex')}`
    if (cached) {
      const cval = this._cache.get(ckey)
      if (cval) {
        return cval
      }
    }

    const stream = this._dht.lookup(topicHash)
    const set = new Set()

    for await (const entry of stream) {
      for (const p of entry.peers) {
        set.add(p.publicKey.toString('hex'))
      }
    }

    const res = Array.from(set)
    this._cache.set(ckey, res)
    return res
  }
}

module.exports = HyperDHTLookup
