'use strict'

const async = require('async')
const RPC = require('@hyperswarm/rpc')
const Base = require('@bitfinex/bfx-facs-base')
const libKeys = require('hyper-cmd-lib-keys')
const DHT = require('hyperdht')
const Hyperswarm = require('hyperswarm')
const os = require('os')
const { setTimeout: sleep } = require('timers/promises')

const HyperDHTLookup = require('./lib/hyperdht.lookup')

/**
 * @typedef {Object} KeyPair
 * @property {Buffer} publicKey
 * @property {Buffer} secretKey
 */

/**
 * @typedef {Object} NetFacilityOpts
 * @property {number} [timeout] - default RPC request timeout in ms (default: 30000)
 * @property {number} [poolLinger] - RPC pool linger time in ms (default: 300000)
 * @property {number} [autoRetryDelay] - default sleep between autoRetry attempts in ms (default: 200)
 * @property {import('@tetherto/hp-svc-facs-store')} [fac_store] - hp-svc-facs-store instance used to persist seeds; falls back to caller.store_s0
 */

/**
 * @typedef {Object} RequestOpts
 * @property {number} [timeout] - per-call request timeout in ms; falls back to fac.opts.timeout
 * @property {number} [autoRetryDelay] - per-call sleep between autoRetry attempts in ms; falls back to fac.opts.autoRetryDelay
 * @property {Buffer} [capability] - RPC handshake capability
 */

class NetFacility extends Base {
  /**
   * @param {Object} caller - parent worker exposing RPC handler methods and facilities (e.g. store_s0)
   * @param {NetFacilityOpts} opts
   * @param {Object} ctx
   */
  constructor (caller, opts, ctx) {
    super(caller, opts, ctx)

    this.name = 'net'
    this._hasConf = true

    if (!this.opts.timeout) {
      this.opts.timeout = 30000
    }

    if (!this.opts.poolLinger) {
      this.opts.poolLinger = 300000
    }

    if (!this.opts.autoRetryDelay) {
      this.opts.autoRetryDelay = 200
    }

    this.init()
  }

  /**
   * Decodes a Buffer/string payload as JSON.
   * @param {Buffer|string} data
   * @returns {any}
   * @throws {Error} ERR_FACS_NET_DATA_FORMAT when the payload is not valid JSON
   */
  parseInputJSON (data) {
    data = data.toString()

    try {
      data = JSON.parse(data)
    } catch (e) {
      throw new Error('ERR_FACS_NET_DATA_FORMAT')
    }

    return data
  }

  /**
   * Throws an Error when the decoded payload is an `[HRPC_ERR]=...` error string.
   * Otherwise returns silently.
   * @param {string} data
   */
  handleInputError (data) {
    if (typeof data !== 'string' && !(data instanceof String)) {
      return
    }

    let isErr = false

    if (data.slice(0, 15).includes('[HRPC_ERR]=')) {
      isErr = true
    }

    if (!isErr) {
      return
    }

    throw new Error(data)
  }

  /**
   * Encodes a value as a JSON Buffer suitable for RPC transport.
   * @param {any} data
   * @returns {Buffer}
   */
  toOutJSON (data) {
    return Buffer.from(JSON.stringify(data))
  }

  /**
   * Encodes a value as a Buffer using its string representation.
   * @param {any} data
   * @returns {Buffer}
   */
  toOut (data) {
    return Buffer.from(data.toString())
  }

  async _request (key, method, data, opts) {
    let res = await this.rpc.request(
      Buffer.from(key, 'hex'), method,
      this.toOutJSON(data), opts
    )

    res = this.parseInputJSON(res)
    this.handleInputError(res)

    return res
  }

  /**
   * Performs a JSON RPC request to a peer, optionally retrying on `RPC client closed`.
   * On retry it sleeps `opts.autoRetryDelay ?? fac.opts.autoRetryDelay` ms between attempts.
   * Does not mutate `opts`.
   * @param {Buffer|string} key - peer RPC publicKey (Buffer or hex string)
   * @param {string} method - remote handler name
   * @param {any} data - JSON-serialisable payload
   * @param {RequestOpts} [opts]
   * @param {number} [autoRetry=0] - retry count for `RPC client closed` errors
   * @returns {Promise<any>}
   * @throws {Error} ERR_FACS_NET_RPC_NOTFOUND when the RPC client is not initialized
   */
  async jRequest (key, method, data, opts = {}, autoRetry = 0) {
    if (!this.rpc) {
      throw new Error('ERR_FACS_NET_RPC_NOTFOUND')
    }

    if (!opts.timeout) {
      opts.timeout = this.opts.timeout
    }
    const autoRetryDelay = opts.autoRetryDelay || this.opts.autoRetryDelay

    try {
      return await this._request(key, method, data, opts)
    } catch (err) {
      if (autoRetry > 0 && err.message.includes('RPC client closed')) {
        await sleep(autoRetryDelay)
        return this.jRequest(key, method, data, opts, autoRetry - 1)
      }
      throw err
    }
  }

  /**
   * Looks up a random peer announcing `topic` and performs a JSON RPC request.
   * On `RPC client closed` it retries with a freshly resolved (uncached) peer.
   * @param {string} topic
   * @param {string} method
   * @param {any} data
   * @param {RequestOpts} [opts]
   * @param {boolean} [cached=true] - reuse cached topic lookup result on the first attempt
   * @param {number} [autoRetry=0]
   * @returns {Promise<any>}
   */
  async jTopicRequest (topic, method, data, opts = {}, cached = true, autoRetry = 0) {
    const key = await this.lookupTopicKey(topic, cached)
    try {
      return await this.jRequest(key, method, data, { ...this.lookup.reqOpts(), ...opts })
    } catch (err) {
      if (autoRetry > 0 && (err.message.includes('RPC client closed') || err.code === 'CHANNEL_CLOSED')) {
        // force invalidate cache (false = not cached)
        return this.jTopicRequest(topic, method, data, opts, false, autoRetry - 1)
      }
      throw err
    }
  }

  /**
   * Fans out a JSON RPC request to every key. Each result is returned as a tuple
   * `[err, res, key]` so failures don't reject the whole batch.
   * @param {Array<Buffer|string>} keys
   * @param {string} method
   * @param {any} data
   * @param {RequestOpts} [opts]
   * @param {number|null} [concurrency=null] - if set, limits parallelism via async.mapLimit
   * @param {number} [autoRetry=0]
   * @returns {Promise<Array<[Error|null, any, Buffer|string]>>}
   */
  async jRequestAll (keys, method, data, opts = {}, concurrency = null, autoRetry = 0) {
    const call = async (key) => {
      try {
        const res = await this.jRequest(key, method, data, opts, autoRetry)
        return [null, res, key]
      } catch (err) {
        return [err, null, key]
      }
    }
    if (!concurrency) {
      return Promise.all(keys.map(call))
    }
    return async.mapLimit(keys, concurrency, call)
  }

  /**
   * Fans out a JSON RPC request to every peer announcing `topic`.
   * @param {string} topic
   * @param {string} method
   * @param {any} data
   * @param {RequestOpts} [opts]
   * @param {number|null} [concurrency=null]
   * @param {boolean} [cached=true]
   * @param {number} [autoRetry=0]
   * @returns {Promise<Array<[Error|null, any, Buffer|string]>>}
   */
  async jTopicRequestAll (topic, method, data, opts = {}, concurrency = null, cached = true, autoRetry = 0) {
    const keys = await this.lookupTopicKeyAll(topic, cached)
    return this.jRequestAll(keys, method, data, { ...this.lookup.reqOpts(), ...opts }, concurrency, autoRetry)
  }

  /**
   * Fires a JSON RPC event (fire-and-forget, no response) to a peer.
   * @param {Buffer|string} key
   * @param {string} method
   * @param {any} data
   * @param {Object} [opts]
   * @throws {Error} ERR_FACS_NET_RPC_NOTFOUND when the RPC client is not initialized
   */
  async jEvent (key, method, data, opts) {
    if (!this.rpc) {
      throw new Error('ERR_FACS_NET_RPC_NOTFOUND')
    }

    this.rpc.event(
      Buffer.from(key, 'hex'), method,
      this.toOutJSON(data), opts
    )
  }

  /**
   * Looks up a random peer announcing `topic` and fires a JSON RPC event.
   * @param {string} topic
   * @param {string} method
   * @param {any} data
   * @param {Object} [opts]
   * @param {boolean} [cached=true]
   */
  async jTopicEvent (topic, method, data, opts = {}, cached = true) {
    const key = await this.lookupTopicKey(topic, cached)
    return this.jEvent(key, method, data, { ...this.lookup.reqOpts(), ...opts })
  }

  /**
   * Dispatches an inbound RPC request to the matching handler on `this.caller`,
   * encoding the result (or any thrown error as `[HRPC_ERR]=<message>`) as a JSON Buffer.
   * @param {string} met - handler/method name to invoke on `this.caller`
   * @param {Buffer} data
   * @returns {Promise<Buffer>}
   */
  async handleReply (met, data) {
    try {
      data = this.parseInputJSON(data)
    } catch (e) {
      return this.toOutJSON(`[HRPC_ERR]=${e.message}`)
    }

    try {
      const res = await this.caller[met](data)
      return this.toOutJSON(res)
    } catch (e) {
      return this.toOutJSON(`[HRPC_ERR]=${e.message}`)
    }
  }

  /**
   * Loads a named seed from the facility's storage bee, creating a fresh 32-byte
   * random seed (and persisting it) if missing.
   * @param {string} name
   * @returns {Promise<Buffer>}
   */
  async getSeed (name) {
    const store = this.opts.fac_store || this.caller.store_s0

    const confBee = await store.getBee(
      { name: 'storeConf' },
      { keyEncoding: 'utf-8' }
    )
    await confBee.ready()

    let seed = await confBee.get(name)

    if (seed) {
      seed = seed.value
    } else {
      seed = libKeys.randomBytes(32)
      await confBee.put(name, seed)
    }

    return seed
  }

  /**
   * Builds a `@hyperswarm/rpc` firewall predicate. The returned function returns
   * `true` to reject a peer and `false` to allow it.
   * @param {Array<Buffer|string>|null} allowed - allow-list of peer publicKeys; `null` disables filtering
   * @param {boolean} [allowLocal=false] - additionally allow peers connecting from the host's local IPv4
   * @returns {function(Buffer, Object): boolean}
   */
  buildFirewall (allowed, allowLocal = false) {
    // convert keys to Buffer if string
    allowed = allowed?.map(k => typeof k === 'string' ? Buffer.from(k, 'hex') : k)

    // if firewall enabled, allow from local ip
    const localIp = allowLocal ? this.getLocalIPAddress() : null

    return (remotePublicKey, remoteHandshakePayload) => {
      if (allowed && !libKeys.checkAllowList(allowed, remotePublicKey)) {
        if (allowLocal && localIp && remoteHandshakePayload?.addresses4) {
          for (const remoteHost of remoteHandshakePayload.addresses4) {
            if (remoteHost.host === localIp) return false
          }
        }

        return true
      }

      return false
    }
  }

  /**
   * @returns {string} primary non-internal IPv4 address of the host, or '127.0.0.1' as fallback
   */
  getLocalIPAddress () {
    for (const devices of Object.values(os.networkInterfaces())) {
      const device = devices.find(d => d.family === 'IPv4' && d.address !== '127.0.0.1' && !d.internal)
      if (device) return device.address
    }

    return '127.0.0.1'
  }

  /**
   * Returns every peer publicKey announcing `topic`.
   * @param {string} topic
   * @param {boolean} [cached=true]
   * @returns {Promise<Array<string>>} - hex-encoded peer publicKeys
   * @throws {Error} ERR_FACS_NET_LOOKUP_NOTFOUND when the lookup helper is not initialized
   * @throws {Error} ERR_TOPIC_LOOKUP_EMPTY when no peers announce the topic
   */
  async lookupTopicKeyAll (topic, cached = true) {
    if (!this.lookup) {
      throw new Error('ERR_FACS_NET_LOOKUP_NOTFOUND')
    }

    const keys = await this.lookup.lookup(topic, cached)
    if (!keys.length) {
      throw new Error('ERR_TOPIC_LOOKUP_EMPTY')
    }
    return keys
  }

  /**
   * Returns a single, random peer publicKey announcing `topic`.
   * @param {string} topic
   * @param {boolean} [cached=true]
   * @returns {Promise<string>} - hex-encoded peer publicKey
   */
  async lookupTopicKey (topic, cached = true) {
    const keys = await this.lookupTopicKeyAll(topic, cached)
    const index = Math.floor(Math.random() * keys.length)
    return keys[index]
  }

  /**
   * Boots the RPC server for this facility (with a firewall derived from `this.conf`).
   * Idempotent — a second call resolves without recreating the server.
   * @param {KeyPair|null} [keyPair] - optional explicit keypair; defaults to one derived from the seedRpc seed
   * @param {Object} [serverOpts] - extra options forwarded to `rpc.createServer`
   * @returns {Promise<void>}
   */
  async startRpcServer (keyPair = null, serverOpts = {}) {
    if (this.rpcServer) {
      return
    }

    await this.startRpc(keyPair)

    const { allow, allowReadOnly, allowLocal } = this.conf
    const allowedPeers = (allow || allowReadOnly)
      ? [...(allow || []), ...(allowReadOnly || [])]
      : null

    const server = this.rpc.createServer({
      firewall: this.buildFirewall(allowedPeers, allowLocal),
      ...serverOpts
    })

    await server.listen()

    this.rpcServer = server
  }

  /**
   * Boots the underlying `@hyperswarm/rpc` client. Idempotent.
   * @param {KeyPair} [keyPair] - optional explicit keypair; defaults to one derived from the seedRpc seed
   * @returns {Promise<void>}
   */
  async startRpc (keyPair) {
    if (this.rpc) {
      return
    }

    const rpcOpts = {
      dht: this.dht,
      poolLinger: this.opts.poolLinger
    }

    if (keyPair) {
      rpcOpts.keyPair = keyPair
    } else {
      rpcOpts.seed = await this.getSeed('seedRpc')
    }

    const rpc = new RPC(rpcOpts)

    this.rpc = rpc
  }

  /**
   * Boots a Hyperswarm instance backed by this facility's DHT.
   * @returns {Promise<void>}
   */
  async startSwarm () {
    const seed = await this.getSeed('seedSwarm')

    const swarm = new Hyperswarm({
      seed,
      dht: this.dht
    })

    this.swarm = swarm
  }

  /**
   * Boots the topic lookup helper (HyperDHTLookup) bound to this RPC keypair.
   * Requires `startRpc` / `startRpcServer` to have run first.
   * @param {Partial<import('./lib/hyperdht.lookup').HyperDHTLookupOpts>} [opts] - forwarded to the HyperDHTLookup constructor; `dht` and `keyPair` are provided by the facility when omitted
   * @throws {Error} ERR_FACS_NET_RPC_NOTFOUND when the RPC client is not initialized
   */
  startLookup (opts) {
    if (!this.rpc) {
      throw new Error('ERR_FACS_NET_RPC_NOTFOUND')
    }

    this.lookup = new HyperDHTLookup({
      dht: this.dht,
      keyPair: this.rpc._defaultKeyPair,
      ...opts
    })
    this.lookup.start()
  }

  _start (cb) {
    async.series([
      next => { super._start(next) },
      async () => {
        const seed = await this.getSeed('seedDht')
        const keyPair = DHT.keyPair(seed)

        this.dht = new DHT({ keyPair })
      }
    ], cb)
  }

  _stop (cb) {
    async.series([
      next => { super._stop(next) },
      async () => {
        if (this.lookup) {
          await this.lookup.stop()
        }

        if (this.rpcServer) {
          await this.rpcServer.close()
        }

        if (this.rpc) {
          await this.rpc.destroy()
        }

        if (this.swarm) {
          await this.swarm.destroy()
        }

        await this.dht.destroy()
      }
    ], cb)
  }
}

module.exports = NetFacility
