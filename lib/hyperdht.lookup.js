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
   * @param {LookupCrypto} [opts.crypto]
   */
  constructor (opts) {
    this.dht = opts.dht
    this.keyPair = opts.keyPair
    this.cache = new LRU({
      max: opts.cacheLength || 1024,
      maxAge: opts.cachelTTL || 5 * 60 * 1000
    })

    if (opts.crypto && !CRYPTO_ALGOS.includes(opts.crypto.algo)) {
      throw new Error('ERR_CRYPTO_ALGO_NOT_SUPPORTED')
    }
    this.cryptoOpts = opts.crypto
  }

  /**
   * @param {string} topic
   * @returns {Buffer}
   */
  encodeTopic (topic) {
    let buff = Buffer.from(topic, 'utf-8')

    switch (this.cryptoOpts?.algo) {
      case 'hmac-sha256':
        buff = crypto.createHmac('sha256', this.cryptoOpts.key).update(buff).digest()
        break
      case 'hmac-sha384':
        buff = crypto.createHmac('sha384', this.cryptoOpts.key).update(buff).digest()
        break
    }

    return HyperDHT.hash(buff)
  }

  /**
   * @param {string} topic
   * @param {KeyPair} [keyPair]
   */
  async announce (topic, keyPair = null) {
    const topicHash = this.encodeTopic(topic)
    await this.dht.announce(topicHash, keyPair ?? this.keyPair).finished()
  }

  /**
   * @param {string} topic
   * @param {KeyPair} [keyPair]
   */
  async unnannounce (topic, keyPair = null) {
    const topicHash = this.encodeTopic(topic)
    await this.dht.unannounce(topicHash, keyPair ?? this.keyPair)
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
      const cval = this.cache.get(ckey)
      if (cval) {
        return cval
      }
    }

    const stream = this.dht.lookup(topicHash)
    const set = new Set()

    for await (const entry of stream) {
      for (const p of entry.peers) {
        set.add(p.publicKey.toString('hex'))
      }
    }

    const res = Array.from(set)
    this.cache.set(ckey, res)
    return res
  }
}

module.exports = HyperDHTLookup
