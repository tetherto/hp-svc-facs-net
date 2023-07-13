'use strict'

const async = require('async')
const _ = require('lodash')
const RPC = require('@hyperswarm/rpc')
const Base = require('bfx-facs-base')
const libKeys = require('@hyper-cmd/lib-keys')
const { promisify } = require('util')

const buildServer = async (conf) => {
  const rpc = new RPC(conf)

  const server = rpc.createServer({
    firewall: (remotePublicKey, remoteHandshakePayload) => {
      if (conf.allow && !libKeys.checkAllowList(conf.allow, remotePublicKey)) {
        return true
      }

      return false
    }
  })

  await server.listen()

  return { rpc, server }
}

const buildClient = async (conf) => {
  const rpc = new RPC()

  const client = rpc.connect(conf.peer)

  return { client, rpc }
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
              const built = await buildServer(_.pick(
                this.conf,
                ['seed', 'allowed']
              ))

              this.rpc = built.rpc
              this.server = built.server
            }
            break
          case 'client':
            {
              const built = await buildClient(_.pick(
                this.conf,
                ['peer']
              ))

              this.rpc = built.rpc
              this.client = built.client
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
          case 'client':
            await this.client.end()
            break
        }

        await this.rpc.destroy()
      }
    ], cb)
  }
}

module.exports = RpcFacility
