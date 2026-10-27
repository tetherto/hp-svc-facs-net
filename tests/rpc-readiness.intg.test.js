'use strict'

const test = require('brittle')
const DHT = require('hyperdht')
const createTestnet = require('hyperdht/testnet')
const RPC = require('@hyperswarm/rpc')
const NetFacility = require('../index')

async function fixture (t, opts = {}, serverOpts = {}) {
  const network = await createTestnet(3)
  const net = new NetFacility({ ctx: { root: __dirname } }, { ns: 'r0', ...opts }, { env: 'test' })
  net.dht = network.createNode()
  const client = new RPC({ dht: network.createNode() })
  t.teardown(async () => {
    await client.destroy()
    if (net.rpc) await net.rpc.destroy()
    await network.destroy()
  })
  await net.startRpcServer(DHT.keyPair(Buffer.alloc(32, 9)), serverOpts)
  return { net, client, key: net.rpcServer.publicKey }
}

test('RPC remains immediately available when no readiness hook is supplied', { timeout: 15000 }, async t => {
  const { net, client, key } = await fixture(t)
  net.rpcServer.respond('ping', data => data)
  const result = await client.request(key, 'ping', Buffer.from('ready'), { timeout: 3000 })
  t.is(result.toString(), 'ready')
})

test('real incoming RPC waits for readiness and preserves server options', { timeout: 15000 }, async t => {
  let release
  let observed
  let settled = false
  let firewallChecks = 0
  const startup = new Promise(resolve => { release = resolve })
  const entered = new Promise(resolve => { observed = resolve })
  const capability = Buffer.from('readiness-test')
  const { net, client, key } = await fixture(t, {
    rpcServerReady: () => { observed(); return startup }
  }, {
    capability,
    firewall: () => { firewallChecks++; return false }
  })
  t.teardown(() => release(false))
  const pending = client.request(key, 'productMethod', Buffer.from('{}'), { capability, timeout: 3000 })
  const result = pending.then(value => ({ value }), error => ({ error })).finally(() => { settled = true })
  await entered
  t.is(settled, false)
  t.ok(firewallChecks > 0)
  net.rpcServer.respond('productMethod', () => Buffer.from('ready'))
  release(true)
  const response = await result
  t.absent(response.error)
  t.is(response.value?.toString(), 'ready')
})

test('readiness false prevents dispatch to registered handlers', { timeout: 15000 }, async t => {
  const { net, client, key } = await fixture(t, { rpcServerReady: () => false })
  let dispatched = false
  net.rpcServer.respond('ping', () => { dispatched = true; return Buffer.from('unexpected') })
  await t.exception(client.request(key, 'ping', Buffer.from('{}'), { timeout: 1000 }))
  t.is(dispatched, false)
})
