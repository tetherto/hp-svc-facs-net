'use strict'

const test = require('brittle')
const NetFacility = require('../index')

function facility (opts = {}) {
  return new NetFacility({ ctx: { root: __dirname } }, { ns: 'r0', ...opts }, { env: 'test' })
}

test('without a readiness hook the original firewall is unchanged', t => {
  const net = facility()
  const firewall = () => false
  t.is(net._withRpcReadiness(firewall), firewall)
  t.is(net._withRpcReadiness(null), null)
  t.is(net._withRpcReadiness(undefined), undefined)
})

test('readiness waits after the peer firewall allows the connection', async t => {
  let release
  let settled = false
  const startup = new Promise(resolve => { release = resolve })
  const net = facility({ rpcServerReady: () => startup })
  const peer = Buffer.alloc(32)
  const payload = { addresses4: [] }
  const firewall = net._withRpcReadiness((...args) => {
    t.alike(args, [peer, payload])
    return false
  })
  const result = firewall(peer, payload).finally(() => { settled = true })
  await new Promise(resolve => setImmediate(resolve))
  t.is(settled, false)
  release(true)
  t.is(await result, false)
})

test('a firewall rejection does not invoke readiness', async t => {
  let calls = 0
  const net = facility({ rpcServerReady: () => { calls++; return true } })
  t.is(await net._withRpcReadiness(async () => true)(), true)
  t.is(calls, 0)
})

test('readiness must explicitly return true and is checked for each connection', async t => {
  let ready = true
  const net = facility({ rpcServerReady: () => ready })
  const firewall = net._withRpcReadiness(null)
  t.is(await firewall(), false)
  for (ready of [false, undefined, null, 1, 'true']) t.is(await firewall(), true)
})

test('readiness errors propagate to the rejecting transport firewall', async t => {
  const error = new Error('ERR_STARTUP_FAILED')
  const net = facility({ rpcServerReady: async () => { throw error } })
  await t.exception(net._withRpcReadiness(() => false)(), /ERR_STARTUP_FAILED/)
})

test('invalid readiness hooks are rejected at construction', async t => {
  for (const rpcServerReady of [null, true, 'ready']) {
    await t.exception.all(() => facility({ rpcServerReady }), /ERR_FACS_NET_RPC_READY_INVALID/)
  }
})
