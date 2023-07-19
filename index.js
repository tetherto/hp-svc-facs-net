'use strict'

const async = require('async')
const _ = require('lodash')
const RPC = require('@hyperswarm/rpc')
const Base = require('bfx-facs-base')
const libKeys = require('@hyper-cmd/lib-keys')
const { promisify } = require('util')

const buildServer = async (conf) => {
  let allowed = null

  if (conf.allow) {
    allowed = libKeys.prepKeyList(conf.allow)
  }

  const rpc = new RPC({
    seed: conf.seed ? conf.seed : undefined
  })

  const server = rpc.createServer({
    firewall: (remotePublicKey, remoteHandshakePayload) => {
      if (allowed && !libKeys.checkAllowList(allowed, remotePublicKey)) {
        return true
      }

      return false
    }
  })

  await server.listen()

  return { rpc, server }
}

const buildClient = async (conf) => {
  let keyPair = null

  if (conf.idFile) {
    keyPair = libUtils.resolveIdentity([], conf.idFile)

    if (!keyPair) {
      throw new Error('ERR_KEYPAIR_FILE_INVALID')
    }

    keyPair = libKeys.parseKeyPair(keyPair) 
  }

  const rpc = new RPC({
    keyPair 
  })

  return { rpc }
}

class RpcFacility extends Base {
  constructor (caller, opts, ctx) {
    super(caller, opts, ctx)

    this.name = 'rpc'
    this.mode = opts.mode
    this._hasConf = true

    this.init()
  }

  _start (cb) {
    async.series([
      next => { super._start(next) },
      async () => {
        switch (this.mode) {
          case 'server':
            {
              const serverOpts = _.pick(this.conf, ['allow'])

              const store = this.caller.store_s0

              let confBee = await store.getBee({ name: 'conf' })
              await confBee.ready()

              let seed = await confBee.get('seed')

              if (seed) {
                seed = seed.value
              } else {
                seed = libKeys.randomBytes(32)
                confBee.put('seed', seed)
              }

              _.extend(serverOpts, {
                seed: seed
              })

              const built = await buildServer(serverOpts)

              this.rpc = built.rpc
              this.server = built.server
            }
            break
          case 'client':
            {
              const built = await buildClient(_.pick(
                this.conf,
                ['idFile']
              ))

              this.rpc = built.rpc
            }
            break
          default:
            throw new Error('ERR_MODE_UNDEFINED')
        }
      }
    ], cb)
  }

  _stop (cb) {
    async.series([
      next => { super._stop(next) },
      async () => {
        switch (this.mode) {
          case 'server':
            await this.server.end()
            break
        }

        await this.rpc.destroy()
      }
    ], cb)
  }
}

module.exports = RpcFacility
