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

const startTestnetNet = async (t, opts) => {
  const network = await createTestnet(3)
  const net = new NetFacility(newCaller(), { ns: 'r0', label: 'r0', root: __dirname, ...opts }, facCtx)
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
    t.is(fw(keyA), false)
    t.is(fw(keyB), false)
  })

  await t.test('should allow listed peers and reject others', async (t) => {
    const fw = net.buildFirewall([keyA])
    t.is(fw(keyA), false)
    t.is(fw(keyB), true)
  })

  await t.test('should coerce hex string keys in allowed list', async (t) => {
    const fw = net.buildFirewall([keyA.toString('hex')])
    t.is(fw(keyA), false)
    t.is(fw(keyB), true)
  })

  await t.test('should reject unlisted peers claiming local addresses in handshake payload', async (t) => {
    const fw = net.buildFirewall([keyA])
    const spoofedPayload = {
      addresses4: [{ host: '127.0.0.1' }, { host: '192.168.1.1' }, { host: '10.0.0.1' }]
    }
    t.is(fw(keyB, spoofedPayload), true)
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

test('startRpcServer holds incoming connections until rpcServerReady resolves', async (t) => {
  let markReady
  let onWaiting
  const ready = new Promise((resolve) => { markReady = resolve })
  const waiting = new Promise((resolve) => { onWaiting = resolve })
  const { net, network } = await startTestnetNet(t, {
    rpcServerReady: () => {
      onWaiting()
      return ready
    }
  })
  const client = new RPC({ dht: network.createNode() })
  t.teardown(() => client.destroy())

  const capability = Buffer.from('rpc-ready-test')
  await net.startRpcServer(null, { capability })

  const res = client.request(net.rpcServer.publicKey, 'ping', Buffer.from('pong'), { capability, timeout: 3000 })
  await waiting
  net.rpcServer.respond('ping', (data) => data)
  markReady()

  t.is((await res).toString(), 'pong')
})

test('startRpcServer keeps the allowlist when rpcServerReady is set', async (t) => {
  let markReady
  const ready = new Promise((resolve) => { markReady = resolve })
  const { net } = await startTestnetNet(t, { rpcServerReady: () => ready })
  const member = crypto.randomBytes(32)
  const outsider = crypto.randomBytes(32)
  net.conf.allow = [member.toString('hex')]
  const createServer = sinon.spy(net.rpc, 'createServer')

  await net.startRpcServer()
  const { firewall } = createServer.firstCall.args[0]

  t.is(await firewall(outsider), true)
  let settled = false
  const memberRejected = firewall(member).finally(() => { settled = true })
  await new Promise((resolve) => setImmediate(resolve))
  t.is(settled, false)
  markReady()
  t.is(await memberRejected, false)
})
