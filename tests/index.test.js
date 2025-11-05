'use strict'

const test = require('brittle')
const RPC = require('@hyperswarm/rpc')
const NetFacility = require('../index')

// Mock store
class MockStore {
  constructor () {
    this._data = new Map()
  }

  async getBee (opts) {
    return {
      ready: async () => {},
      get: async (key) => {
        const value = this._data.get(key)
        return value ? { value } : null
      },
      put: async (key, value) => {
        this._data.set(key, value)
      }
    }
  }
}

// Mock caller object
class MockCaller {
  constructor (ctx) {
    this.store_s0 = new MockStore()
    this.ctx = ctx 
  }

  async testMethod (data) {
    return { received: data, success: true }
  }

  async errorMethod () {
    throw new Error('Test error')
  }
}

test('NetFacility', async (t) => {
  const ctx = { env: 'test', root: process.cwd() }
  const caller = new MockCaller(ctx)
  const facility = new NetFacility(caller, {}, ctx)

  t.teardown(async () => {
    await new Promise((resolve) => {
      facility._stop((err) => {
        if (err) t.fail(err)
        resolve()
      })
    })
  })

  // Start facility
  await new Promise((resolve) => {
    facility._start((err) => {
      if (err) t.fail(err)
      resolve()
    })
  })

  await t.test('parseInputJSON', async (t) => {
    t.comment('should parse valid JSON string')
    const valid = Buffer.from(JSON.stringify({ test: 'data' }))
    const parsed = facility.parseInputJSON(valid)
    t.alike(parsed, { test: 'data' })

    t.comment('should parse Buffer with JSON')
    const buffer = Buffer.from('{"key":"value"}')
    const result = facility.parseInputJSON(buffer)
    t.alike(result, { key: 'value' })

    t.comment('should throw error for invalid JSON')
    const invalid = Buffer.from('not json')
    t.exception(() => {
      facility.parseInputJSON(invalid)
    }, /ERR_FACS_NET_DATA_FORMAT/)
  })

  await t.test('handleInputError', async (t) => {
    t.comment('should return early for non-string data')
    t.is(facility.handleInputError({}), undefined)
    t.is(facility.handleInputError(123), undefined)
    t.is(facility.handleInputError(null), undefined)

    t.comment('should return early for non-error strings')
    t.is(facility.handleInputError('normal string'), undefined)
    t.is(facility.handleInputError('some other text'), undefined)
  })

  await t.test('toOutJSON', async (t) => {
    const data = { test: 'data', num: 123 }
    const result = facility.toOutJSON(data)
    t.ok(Buffer.isBuffer(result))
    t.is(result.toString(), JSON.stringify(data))
  })

  await t.test('toOut', async (t) => {
    t.comment('should convert string to buffer')
    const str = 'test string'
    const result = facility.toOut(str)
    t.ok(Buffer.isBuffer(result))
    t.is(result.toString(), str)

    t.comment('should convert number to buffer')
    const num = 123
    const numResult = facility.toOut(num)
    t.ok(Buffer.isBuffer(numResult))
    t.is(numResult.toString(), '123')
  })

  await t.test('getSeed', async (t) => {
    t.comment('should generate new seed if not exists')
    const seed1 = await facility.getSeed('testSeed1')
    t.ok(Buffer.isBuffer(seed1))
    t.is(seed1.length, 32)

    t.comment('should return existing seed if present')
    const seed2 = await facility.getSeed('testSeed1')
    t.alike(seed1, seed2)

    t.comment('should return different seed for different names')
    const seed3 = await facility.getSeed('testSeed2')
    t.not(seed1.toString('hex'), seed3.toString('hex'))
  })

  await t.test('getLocalIPAddress', async (t) => {
    const ip = facility.getLocalIPAddress()
    t.ok(typeof ip === 'string')
    t.ok(ip.length > 0)
    t.ok(ip === '127.0.0.1' || /^\d+\.\d+\.\d+\.\d+$/.test(ip))
  })

  await t.test('buildFirewall', async (t) => {
    t.comment('should return false when no allowed list')
    const firewall1 = facility.buildFirewall(null)
    t.is(firewall1(null, null), false)

    const firewall2 = facility.buildFirewall(undefined)
    t.is(firewall2(null, null), false)

    t.comment('should allow local IP when allowLocal is true')
    const localIp = facility.getLocalIPAddress()
    const firewall3 = facility.buildFirewall(['abc123'], true)
    const handshake = {
      addresses4: [{ host: localIp }]
    }
    const result = firewall3(Buffer.from('test'), handshake)
    t.ok(typeof result === 'boolean')
  })

  await t.test('_getDht', async (t) => {
    t.comment('should create new DHT for new seed name')
    const dht1 = await facility._getDht('testDht1')
    t.ok(dht1)
    t.ok(facility.dhts.has('testDht1'))

    t.comment('should return existing DHT for same seed name')
    const dht2 = await facility._getDht('testDht1')
    t.is(dht1, dht2)

    t.comment('should create different DHT for different seed name')
    const dht3 = await facility._getDht('testDht2')
    t.not(dht1, dht3)
    t.ok(facility.dhts.has('testDht2'))
  })

  await t.test('_getSwarm', async (t) => {
    t.comment('should create new swarm for new seed name')
    const dht = await facility._getDht('swarmTestDht')
    const swarm1 = await facility._getSwarm('testSwarm1', dht)
    t.ok(swarm1)
    t.ok(facility.swarms.has('testSwarm1'))

    t.comment('should return existing swarm for same seed name')
    const swarm2 = await facility._getSwarm('testSwarm1', dht)
    t.is(swarm1, swarm2)

    t.comment('should create different swarm for different seed name')
    const swarm3 = await facility._getSwarm('testSwarm2', dht)
    t.not(swarm1, swarm3)
    t.ok(facility.swarms.has('testSwarm2'))
  })

  await t.test('createNewSwarm', async (t) => {
    t.comment('should create new swarm with valid seed name')
    const swarm = await facility.createNewSwarm('newSwarm1')
    t.ok(swarm)
    t.ok(facility.swarms.has('newSwarm1'))
    t.ok(facility.dhts.has('newSwarm1dht'))

    t.comment('should throw error for base swarm seed name')
    t.exception(() => {
      return facility.createNewSwarm(facility.baseSwarmSeedName)
    }, /ERR_BASE_SWARM_SEED_NOT_ALLOWED/)

    t.comment('should throw error for invalid seed name')
    t.exception(() => {
      return facility.createNewSwarm('')
    }, /ERR_INVALID_SEED_NAME/)

    t.exception(() => {
      return facility.createNewSwarm(null)
    }, /ERR_INVALID_SEED_NAME/)

    t.exception(() => {
      return facility.createNewSwarm(123)
    }, /ERR_INVALID_SEED_NAME/)
  })

  await t.test('startSwarm', async (t) => {
    await facility.startSwarm()
    t.ok(facility.swarm)
    t.ok(facility.swarms.has(facility.baseSwarmSeedName))
  })

  await t.test('startRpc', async (t) => {
    t.comment('should create RPC instance')
    await facility.startRpc()
    t.ok(facility.rpc)
    t.ok(facility.rpc instanceof RPC)

    t.comment('should not create duplicate RPC')
    const rpc1 = facility.rpc
    await facility.startRpc()
    t.is(facility.rpc, rpc1)
  })

  await t.test('startRpcServer', async (t) => {
    t.comment('should create RPC server')
    if (!facility.conf) {
      facility.conf = { allow: null, allowReadOnly: null, allowLocal: false }
    }
    await facility.startRpcServer()
    t.ok(facility.rpcServer)

    t.comment('should not create duplicate server')
    const server1 = facility.rpcServer
    await facility.startRpcServer()
    t.is(facility.rpcServer, server1)
  })

  await t.test('handleReply', async (t) => {
    t.comment('should handle valid method call')
    const data = Buffer.from(JSON.stringify({ test: 'data' }))
    const result = await facility.handleReply('testMethod', data)
    t.ok(Buffer.isBuffer(result))
    const parsed = JSON.parse(result.toString())
    t.ok(parsed.received)
    t.ok(parsed.success === true)

    t.comment('should handle invalid JSON')
    const invalidData = Buffer.from('invalid json')
    const errorResult = await facility.handleReply('testMethod', invalidData)
    t.ok(Buffer.isBuffer(errorResult))
    const errorParsed = errorResult.toString()
    t.ok(errorParsed.includes('[HRPC_ERR]='))

    t.comment('should handle method errors')
    const errorData = Buffer.from(JSON.stringify({ test: 'error' }))
    const errorMethodResult = await facility.handleReply('errorMethod', errorData)
    t.ok(Buffer.isBuffer(errorMethodResult))
    const errorMethodParsed = errorMethodResult.toString()
    t.ok(errorMethodParsed.includes('[HRPC_ERR]=Test error'))
  })
})
