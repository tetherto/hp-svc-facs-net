'use strict'

const async = require('async')
const RPC = require('@hyperswarm/rpc')
const Base = require('bfx-facs-base')
const libKeys = require('@hyper-cmd/lib-keys')
const DHT = require('hyperdht')
const Hyperswarm = require('hyperswarm')
const debug = require('debug')('hp:rpc')

class NetFacility extends Base {
  constructor (caller, opts, ctx) {
    super(caller, opts, ctx)

    this.name = 'rpc'
    this.mode = opts.mode
    this._hasConf = true

    this.init()
  }

  parseInputJSON (data) {
    data = data.toString()

    try {
      data = JSON.parse(data)
    } catch (e) {
      throw new Error('ERR_DATA_FORMAT')
    }

    return data
  }

  toOutJSON (data) {
    return Buffer.from(JSON.stringify(data))
  }

  toOut (data) {
    return Buffer.from(data.toString())
  }

  async handleReply (met, data) {
    try {
      data = this.parseInputJSON(data)
    } catch (e) {
      return this.toOut(e.message)
    }

    try {
      const res = this.caller[met](data)
      return this.toOutJSON(res)
    } catch (e) {
      return this.toOutJSON(`[HRPC_ERR]=${e.message}`)
    }
  }

  async getSeed (name) {
    const store = this.caller.store_s0

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
      dht: this.dht
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
