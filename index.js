'use strict'

const async = require('async')
const RPC = require('@hyperswarm/rpc')
const Base = require('bfx-facs-base')
const libKeys = require('hyper-cmd-lib-keys')
const DHT = require('hyperdht')
const Hyperswarm = require('hyperswarm')
const os = require('os')

const HyperDHTLookup = require('./lib/hyperdht.lookup')

class NetFacility extends Base {
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

    this.init()
  }

  parseInputJSON (data) {
    data = data.toString()

    try {
      data = JSON.parse(data)
    } catch (e) {
      throw new Error('ERR_FACS_NET_DATA_FORMAT')
    }

    return data
  }

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

  toOutJSON (data) {
    return Buffer.from(JSON.stringify(data))
  }

  toOut (data) {
    return Buffer.from(data.toString())
  }

  async jRequest (key, method, data, opts = {}) {
    if (!this.rpc) {
      throw new Error('ERR_FACS_NET_RPC_NOTFOUND')
    }

    if (!opts.timeout) {
      opts.timeout = this.opts.timeout
    }

    let res = await this.rpc.request(
      Buffer.from(key, 'hex'), method,
      this.toOutJSON(data), opts
    )

    res = this.parseInputJSON(res)
    this.handleInputError(res)

    return res
  }

  async jTopicRequest (topic, method, data, opts = {}, cached = true) {
    const key = await this.lookupTopicKey(topic, cached)
    return this.jRequest(key, method, data, { ...this.lookup.reqOpts(), ...opts })
  }

  async jRequestAll (keys, method, data, opts = {}, concurrency = null) {
    const call = async (key) => {
      try {
        const res = await this.jRequest(key, method, data, opts)
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

  async jTopicRequestAll (topic, method, data, opts = {}, concurrency = null, cached = true) {
    const keys = await this.lookupTopicKeyAll(topic, cached)
    return this.jRequestAll(keys, method, data, { ...this.lookup.reqOpts(), ...opts }, concurrency)
  }

  async jEvent (key, method, data, opts) {
    if (!this.rpc) {
      throw new Error('ERR_FACS_NET_RPC_NOTFOUND')
    }

    this.rpc.event(
      Buffer.from(key, 'hex'), method,
      this.toOutJSON(data), opts
    )
  }

  async jTopicEvent (topic, method, data, opts = {}, cached = true) {
    const key = await this.lookupTopicKey(topic, cached)
    return this.jEvent(key, method, data, { ...this.lookup.reqOpts(), ...opts })
  }

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

  getLocalIPAddress () {
    for (const devices of Object.values(os.networkInterfaces())) {
      const device = devices.find(d => d.family === 'IPv4' && d.address !== '127.0.0.1' && !d.internal)
      if (device) return device.address
    }

    return '127.0.0.1'
  }

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

  async lookupTopicKey (topic, cached = true) {
    const keys = await this.lookupTopicKeyAll(topic, cached)
    const index = Math.floor(Math.random() * keys.length)
    return keys[index]
  }

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

  async startSwarm () {
    const seed = await this.getSeed('seedSwarm')

    const swarm = new Hyperswarm({
      seed,
      dht: this.dht
    })

    this.swarm = swarm
  }

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
