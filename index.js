'use strict'

const async = require('async')
const RPC = require('@hyperswarm/rpc')
const Base = require('bfx-facs-base')
const libKeys = require('@hyper-cmd/lib-keys')
const DHT = require('hyperdht')
const Hyperswarm = require('hyperswarm')
const debug = require('debug')('hp:net')

class NetFacility extends Base {
  constructor (caller, opts, ctx) {
    super(caller, opts, ctx)

    this.name = 'net'
    this._hasConf = true

    if (!this.opts.timeout) {
      this.opts.timeout = 30000
    }

    if (!this.opts.poolLinger) {
      this.opts.poolLinger = 30000
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

  async jEvent (k, m, d) {
    if (!this.rpc) {
      throw new Error('ERR_FACS_NET_RPC_NOTFOUND')
    }

    await this.rpc.event(
      Buffer.from(k, 'hex'), m,
      this.toOutJSON(d)
    )
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

  buildFirewall (allowed) {
    return (remotePublicKey, remoteHandshakePayload) => {
      if (allowed && !libKeys.checkAllowList(allowed, remotePublicKey)) {
        return true
      }

      return false
    }
  }

  async startRpcServer () {
    if (this.rpcServer) {
      return
    }

    await this.startRpc()

    const server = this.rpc.createServer({
      firewall: this.buildFirewall(this.conf.allow)
    })

    await server.listen()

    this.rpcServer = server
  }

  async startRpc () {
    if (this.rpc) {
      return
    }

    const seed = await this.getSeed('seedRpc')

    const rpc = new RPC({
      seed,
      dht: this.dht,
      poolLinger: this.opts.poolLinger
    })

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
        if (this.rpcServer) {
          await this.rpcServer.end()
        }

        if (this.rpc) {
          await this.rpc.destroy()
        }

        await this.dht.destroy()
      }
    ], cb)
  }
}

module.exports = NetFacility
