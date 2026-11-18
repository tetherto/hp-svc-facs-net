'use strict'

const RPC = require('@hyperswarm/rpc')
const StoreFacility = require('@tetherto/hp-svc-facs-store')
const crypto = require('crypto')
const fs = require('fs')
const DHT = require('hyperdht')
const createTestnet = require('hyperdht/testnet')
const path = require('path')
const sinon = require('sinon')
const test = require('brittle')
const { EventEmitter } = require('events')

const NetFacility = require('../index')

const facCtx = { env: 'test' }

const newCaller = () => new class FacCaller extends EventEmitter {
  constructor () {
    super()
    this.ctx = { root: __dirname }
  }
}()

const startTestnetNet = async (t) => {
  const network = await createTestnet(3)
  const net = new NetFacility(newCaller(), { ns: 'r0', label: 'r0', root: __dirname }, facCtx)
  net.dht = network.createNode()
  await net.startRpc(DHT.keyPair())
  t.teardown(async () => {
    await net.rpc.destroy()
    await network.destroy()
  })
  return { net, network }
}

test('buildFirewall', async (t) => {
  const net = new NetFacility(newCaller(), { ns: 'r0', label: 'r0', root: __dirname }, facCtx)

  const keyA = crypto.randomBytes(32)
  const keyB = crypto.randomBytes(32)

  await t.test('should allow any peer when allowed list is null', async (t) => {
    const fw = net.buildFirewall(null)
    t.is(await fw(keyA), false)
    t.is(await fw(keyB), false)
  })

  await t.test('should allow listed peers and reject others', async (t) => {
    const fw = net.buildFirewall([keyA])
    t.is(await fw(keyA), false)
    t.is(await fw(keyB), true)
  })

  await t.test('should coerce hex string keys in allowed list', async (t) => {
    const fw = net.buildFirewall([keyA.toString('hex')])
    t.is(await fw(keyA), false)
    t.is(await fw(keyB), true)
  })

  await t.test('should reject unlisted peers claiming local addresses in handshake payload', async (t) => {
    const fw = net.buildFirewall([keyA])
    const spoofedPayload = {
      addresses4: [{ host: '127.0.0.1' }, { host: '192.168.1.1' }, { host: '10.0.0.1' }]
    }
    t.is(await fw(keyB, spoofedPayload), true)
  })

  await t.test('should hold allowed peers until the caller startup finishes', async (t) => {
    let markStarted
    const caller = newCaller()
    caller._pStartupFinished = new Promise((resolve) => { markStarted = resolve })
    const fw = new NetFacility(caller, { ns: 'r0', label: 'r0', root: __dirname }, facCtx).buildFirewall([keyA])

    t.is(await fw(keyB), true)
    let settled = false
    const allowed = fw(keyA).finally(() => { settled = true })
    await new Promise((resolve) => setImmediate(resolve))
    t.is(settled, false)
    markStarted()
    t.is(await allowed, false)
  })
})

test('startRpcServer with legacy allowLocal conf', async (t) => {
  t.timeout(300000)

  const facCaller = newCaller()
  const storeDir = path.join(__dirname, 'store-firewall')
  if (fs.existsSync(storeDir)) {
    fs.rmSync(storeDir, { recursive: true })
  }

  const store = new StoreFacility(facCaller, { ns: 's0', label: 's0', storeDir, root: __dirname }, facCtx)
  const net = new NetFacility(facCaller, { ns: 'r0', label: 'r0', fac_store: store, root: __dirname }, facCtx)

  t.teardown(async () => {
    await Promise.all([
      new Promise((resolve) => store.stop(resolve)),
      new Promise((resolve) => net.stop(resolve))
    ])
    fs.rmSync(storeDir, { recursive: true })
  })

  await new Promise((resolve, reject) => store.start((err) => err ? reject(err) : resolve()))
  await new Promise((resolve, reject) => net.start((err) => err ? reject(err) : resolve()))

  net.conf.allowLocal = true
  const warnSpy = sinon.spy(console, 'warn')
  t.teardown(() => warnSpy.restore())

  await net.startRpcServer()

  t.ok(net.rpcServer, 'rpc server started')
  t.ok(
    warnSpy.getCalls().some(c => String(c.args[0]).includes('allowLocal')),
    'deprecation warning logged'
  )
})

test('startRpcServer holds incoming connections until the caller startup finishes', async (t) => {
  let markStarted
  let onWaiting
  const started = new Promise((resolve) => { markStarted = resolve })
  const waiting = new Promise((resolve) => { onWaiting = resolve })
  const { net, network } = await startTestnetNet(t)
  Object.defineProperty(net.caller, '_pStartupFinished', {
    get () {
      onWaiting()
      return started
    }
  })
  const client = new RPC({ dht: network.createNode() })
  t.teardown(() => client.destroy())

  const capability = Buffer.from('rpc-ready-test')
  await net.startRpcServer(null, { capability })

  const res = client.request(net.rpcServer.publicKey, 'ping', Buffer.from('pong'), { capability, timeout: 3000 })
  await waiting
  net.rpcServer.respond('ping', (data) => data)
  markStarted()

  t.is((await res).toString(), 'pong')
})
