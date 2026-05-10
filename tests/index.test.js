'use strict'

const StoreFacility = require('@tetherto/hp-svc-facs-store')
const crypto = require('crypto')
const fs = require('fs')
const path = require('path')
const sinon = require('sinon')
const test = require('brittle')
const { EventEmitter } = require('events')

const NetFacility = require('../index')

test('NetFacility', async (t) => {
  t.timeout(300000)

  const facCaller = new class FacCaller extends EventEmitter {
    constructor () {
      super()
      this.ctx = { root: __dirname }
      this.calls = {}
    }

    _track (name) {
      this.calls[name] = (this.calls[name] || 0) + 1
      return this.calls[name]
    }

    resetCalls () {
      for (const key of Object.keys(this.calls)) {
        this.calls[key] = 0
      }
    }

    async ping (req) {
      this._track('ping')
      return req.value
    }

    async fail () {
      this._track('fail')
      throw new Error('boom')
    }

    async clientClosed () {
      this._track('clientClosed')
      throw new Error('RPC client closed')
    }

    async clientClosedOnce (req) {
      const n = this._track('clientClosedOnce')
      if (n === 1) throw new Error('RPC client closed')
      return req.value
    }

    async nonMatching () {
      this._track('nonMatching')
      throw new Error('some other error')
    }
  }()
  const facCtx = { env: 'test' }
  const storeDir = path.join(__dirname, 'store')
  if (fs.existsSync(storeDir)) {
    fs.rmSync(storeDir, { recursive: true })
  }

  const store = new StoreFacility(facCaller, { ns: 's0', label: 's0', storeDir, root: facCaller.ctx.root }, facCtx)
  const net = new NetFacility(facCaller, { ns: 'r0', label: 'r0', fac_store: store, root: facCaller.ctx.root }, facCtx)

  t.teardown(async () => {
    await Promise.all([
      new Promise((resolve) => store.stop(resolve)),
      new Promise((resolve) => net.stop(resolve))
    ])
    fs.rmSync(storeDir, { recursive: true })
  })

  await new Promise((resolve, reject) => store.start((err) => err ? reject(err) : resolve()))
  await new Promise((resolve, reject) => net.start((err) => err ? reject(err) : resolve()))

  await net.startRpcServer()
  const rpcKey = net.rpcServer.publicKey

  // Keep retry tests fast by default; the dedicated delay test overrides this.
  net.opts.autoRetryDelay = 0

  for (const method of ['ping', 'fail', 'clientClosed', 'clientClosedOnce', 'nonMatching']) {
    net.rpcServer.respond(method, (req) => net.handleReply(method, req))
  }

  await t.test('jRequest', async (t) => {
    await t.test('should return response upon request', async (t) => {
      const res = await net.jRequest(rpcKey, 'ping', { value: 3 })
      t.is(res, 3)
    })

    await t.test('should throw ERR_FACS_NET_RPC_NOTFOUND when rpc is not initialized', async (t) => {
      const savedRpc = net.rpc
      net.rpc = null
      t.teardown(() => { net.rpc = savedRpc })

      await t.exception(
        () => net.jRequest(rpcKey, 'ping', { value: 1 }),
        /ERR_FACS_NET_RPC_NOTFOUND/
      )
    })

    await t.test('should propagate remote handler errors as HRPC_ERR', async (t) => {
      await t.exception(
        () => net.jRequest(rpcKey, 'fail', {}),
        /HRPC_ERR.*boom/
      )
    })

    await t.test('should default opts.timeout to fac.opts.timeout', async (t) => {
      const spy = sinon.spy(net.rpc, 'request')
      t.teardown(() => spy.restore())

      await net.jRequest(rpcKey, 'ping', { value: 4 })

      t.is(spy.callCount, 1)
      t.is(spy.firstCall.args[3].timeout, net.opts.timeout)
    })

    await t.test('should honour user-supplied opts.timeout', async (t) => {
      const spy = sinon.spy(net.rpc, 'request')
      t.teardown(() => spy.restore())

      await net.jRequest(rpcKey, 'ping', { value: 5 }, { timeout: 12345 })

      t.is(spy.firstCall.args[3].timeout, 12345)
    })

    await t.test('autoRetry=0 (default): should not retry on RPC client closed', async (t) => {
      t.teardown(() => facCaller.resetCalls())

      await t.exception(
        () => net.jRequest(rpcKey, 'clientClosed', {}),
        /RPC client closed/
      )
      t.is(facCaller.calls.clientClosed, 1)
    })

    await t.test('autoRetry=1: should retry once on RPC client closed and succeed', async (t) => {
      t.teardown(() => facCaller.resetCalls())

      const res = await net.jRequest(rpcKey, 'clientClosedOnce', { value: 7 }, {}, 1)

      t.is(res, 7)
      t.is(facCaller.calls.clientClosedOnce, 2)
    })

    await t.test('autoRetry=1: should not retry on non-matching errors', async (t) => {
      t.teardown(() => facCaller.resetCalls())

      await t.exception(
        () => net.jRequest(rpcKey, 'nonMatching', {}, {}, 1),
        /some other error/
      )
      t.is(facCaller.calls.nonMatching, 1)
    })

    await t.test('autoRetry=N: should give up after N retries if RPC client closed persists', async (t) => {
      t.teardown(() => facCaller.resetCalls())

      await t.exception(
        () => net.jRequest(rpcKey, 'clientClosed', {}, {}, 3),
        /RPC client closed/
      )
      t.is(facCaller.calls.clientClosed, 4)
    })

    await t.test('should sleep fac.opts.autoRetryDelay ms between retries', async (t) => {
      const savedDelay = net.opts.autoRetryDelay
      net.opts.autoRetryDelay = 100
      t.teardown(() => {
        net.opts.autoRetryDelay = savedDelay
        facCaller.resetCalls()
      })

      const started = Date.now()
      await t.exception(
        () => net.jRequest(rpcKey, 'clientClosed', {}, {}, 3),
        /RPC client closed/
      )
      const elapsed = Date.now() - started

      t.is(facCaller.calls.clientClosed, 4)
      // 3 retries × 100ms sleep each, minus a small fudge for timer jitter.
      t.ok(elapsed >= 3 * 100 - 20, `elapsed ${elapsed}ms should be >= ~300ms`)
    })

    await t.test('should honour per-call opts.autoRetryDelay overriding facility default', async (t) => {
      t.teardown(() => facCaller.resetCalls())

      const started = Date.now()
      await t.exception(
        () => net.jRequest(rpcKey, 'clientClosed', {}, { autoRetryDelay: 100 }, 2),
        /RPC client closed/
      )
      const elapsed = Date.now() - started

      t.is(facCaller.calls.clientClosed, 3)
      t.ok(elapsed >= 2 * 100 - 20, `elapsed ${elapsed}ms should be >= ~200ms`)
    })
  })

  await t.test('jTopicRequest', async (t) => {
    net.startLookup()
    const topic = 'jTopicRequest-test-' + crypto.randomBytes(16).toString('hex')
    await net.lookup.announce(topic)

    t.teardown(async () => {
      await net.lookup.unnannounce(topic)
    })

    await t.test('should return response upon request', async (t) => {
      const res = await net.jTopicRequest(topic, 'ping', { value: 10 })
      t.is(res, 10)
    })

    await t.test('should throw ERR_FACS_NET_LOOKUP_NOTFOUND when lookup is not initialized', async (t) => {
      const saved = net.lookup
      net.lookup = null
      t.teardown(() => { net.lookup = saved })

      await t.exception(
        () => net.jTopicRequest(topic, 'ping', { value: 1 }),
        /ERR_FACS_NET_LOOKUP_NOTFOUND/
      )
    })

    await t.test('should throw ERR_TOPIC_LOOKUP_EMPTY when no peers announce topic', async (t) => {
      const unannouncedTopic = 'jTopicRequest-unannounced-' + crypto.randomBytes(16).toString('hex')

      await t.exception(
        () => net.jTopicRequest(unannouncedTopic, 'ping', {}),
        /ERR_TOPIC_LOOKUP_EMPTY/
      )
    })

    await t.test('should propagate remote handler errors as HRPC_ERR', async (t) => {
      await t.exception(
        () => net.jTopicRequest(topic, 'fail', {}),
        /HRPC_ERR.*boom/
      )
    })

    await t.test('autoRetry=0 (default): should not retry on RPC client closed', async (t) => {
      t.teardown(() => facCaller.resetCalls())

      await t.exception(
        () => net.jTopicRequest(topic, 'clientClosed', {}),
        /RPC client closed/
      )
      t.is(facCaller.calls.clientClosed, 1)
    })

    await t.test('autoRetry=1: should retry once on RPC client closed and succeed', async (t) => {
      t.teardown(() => facCaller.resetCalls())

      const res = await net.jTopicRequest(topic, 'clientClosedOnce', { value: 11 }, {}, true, 1)

      t.is(res, 11)
      t.is(facCaller.calls.clientClosedOnce, 2)
    })

    await t.test('autoRetry=1: should not retry on non-matching errors', async (t) => {
      t.teardown(() => facCaller.resetCalls())

      await t.exception(
        () => net.jTopicRequest(topic, 'nonMatching', {}, {}, true, 1),
        /some other error/
      )
      t.is(facCaller.calls.nonMatching, 1)
    })

    await t.test('autoRetry=N: should give up after N retries if RPC client closed persists', async (t) => {
      t.teardown(() => facCaller.resetCalls())

      await t.exception(
        () => net.jTopicRequest(topic, 'clientClosed', {}, {}, true, 3),
        /RPC client closed/
      )
      t.is(facCaller.calls.clientClosed, 4)
    })

    await t.test('should invalidate lookup cache on retry', async (t) => {
      t.teardown(() => facCaller.resetCalls())
      const spy = sinon.spy(net, 'lookupTopicKey')
      t.teardown(() => spy.restore())

      await t.exception(
        () => net.jTopicRequest(topic, 'clientClosed', {}, {}, true, 2),
        /RPC client closed/
      )

      t.is(spy.callCount, 3)
      t.is(spy.firstCall.args[1], true)
      t.is(spy.secondCall.args[1], false)
      t.is(spy.thirdCall.args[1], false)
    })
  })
})
