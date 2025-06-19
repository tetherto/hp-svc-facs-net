'use strict'

const crypto = require('crypto')
const HyperDHT = require('hyperdht')
const test = require('brittle')
const sinon = require('sinon')
const { setTimeout: sleep } = require('timers/promises')

const HyperDHTLookup = require('../lib/hyperdht.lookup')

test('HyperDHTLookup', async (t) => {
  t.timeout(300000)

  const dht = new HyperDHT()
  const dhtKeyPair = dht.defaultKeyPair
  const dhtPublicKey = dht.defaultKeyPair.publicKey.toString('hex')
  const otherKeyPair = HyperDHT.keyPair(crypto.randomBytes(32))
  const otherPublicKey = otherKeyPair.publicKey.toString('hex')

  const lookup = new HyperDHTLookup({
    dht, keyPair: dhtKeyPair
  })
  lookup.start()
  const lookupSec = new HyperDHTLookup({
    dht, keyPair: dhtKeyPair, crypto: { algo: 'hmac-sha384', key: 'my-secret' }
  })
  lookupSec.start()

  const topic = 'my-topic-' + crypto.randomBytes(64).toString('hex')

  t.teardown(async () => {
    await Promise.all([
      lookup.stop(),
      lookupSec.stop()
    ])
    await dht.destroy()
  })

  await t.test('lookup', async (t) => {
    t.teardown(async () => {
      await lookup.unnannounce(topic)
    })

    t.comment('should return empty when topic is missing')
    let res = await lookup.lookup(topic)
    t.is(res.length, 0)

    t.comment('should return cached content when present')
    await lookup.announce(topic)
    res = await lookup.lookup(topic)
    t.is(res.length, 0)

    t.comment('should return uncached content when flag is false')
    res = await lookup.lookup(topic, false)
    t.is(res.length, 1)
    t.is(res[0], dhtPublicKey)
  })

  await t.test('announce', async (t) => {
    t.teardown(async () => {
      await Promise.all([
        lookup.unnannounce(topic),
        lookup.unnannounce(topic, otherKeyPair)
      ])
    })

    t.comment('should announce self keypair by default')
    let res = await lookup.lookup(topic, false)
    t.is(res.length, 0)
    await lookup.announce(topic)

    res = await lookup.lookup(topic, false)
    t.is(res.length, 1)
    t.is(res[0], dhtPublicKey)

    t.comment('should announce keypair when present')
    await lookup.announce(topic, otherKeyPair)

    res = await lookup.lookup(topic, false)
    t.is(res.length, 2)
    t.ok(res.some(k => k === dhtPublicKey))
    t.ok(res.some(k => k === otherPublicKey))
  })

  await t.test('unannounce', async (t) => {
    await lookup.announce(topic)
    await lookup.announce(topic, otherKeyPair)

    t.comment('should unannounce self keypair by default')
    let res = await lookup.lookup(topic, false)
    t.is(res.length, 2)
    await lookup.unnannounce(topic)
    res = await lookup.lookup(topic, false)
    t.is(res.length, 1)
    t.is(res[0], otherPublicKey)

    t.comment('should unannounce keypair when present')
    await lookup.unnannounce(topic, otherKeyPair)
    res = await lookup.lookup(topic, false)
    t.is(res.length, 0)
  })

  await t.test('crypto encoded topic', async (t) => {
    t.teardown(async () => {
      await Promise.all([
        lookup.unnannounce(topic, otherKeyPair),
        lookupSec.unnannounce(topic)
      ])
    })

    t.comment('should fail on constructor if crypto algo is not supported')
    t.exception(
      () => { return new HyperDHTLookup({ dht, keyPair: dhtKeyPair, crypto: { algo: 'md5' } }) },
      /ERR_CRYPTO_ALGO_NOT_SUPPORTED/
    )

    t.comment('should announce obfuscated topic')
    await lookup.announce(topic, otherKeyPair)
    await lookupSec.announce(topic)
    const lookupRes = await lookup.lookup(topic, false)
    t.is(lookupRes.length, 1)
    t.is(lookupRes[0], otherPublicKey)
    const lookupSecRes = await lookupSec.lookup(topic, false)
    t.is(lookupSecRes.length, 1)
    t.is(lookupSecRes[0], dhtPublicKey)
  })

  await t.test('interval tests', async (t) => {
    t.timeout(120000)

    const lookupItv = new HyperDHTLookup({
      dht, keyPair: dhtKeyPair, announceTTL: 2000
    })

    const spy = sinon.spy(lookupItv, 'announce')
    t.teardown(async () => {
      await lookupItv.stop()
      spy.restore()
    })

    t.comment('should announce services from map on interval')
    lookupItv.start()
    await lookupItv.announceInterval(topic, otherKeyPair)
    t.ok(spy.callCount >= 1 && spy.callCount <= 2)
    t.alike(spy.firstCall.args, [topic, otherKeyPair])
    await sleep(2200)
    t.ok(spy.callCount >= 2 && spy.callCount <= 3)
    t.alike(spy.lastCall.args, [topic, otherKeyPair])
    await lookupItv.unnannounceInterval(topic, otherKeyPair)
    t.ok(spy.callCount <= 3)
    await lookupItv.stop()

    spy.resetHistory()

    t.comment('should fall back to original when key pair is not present')
    lookupItv.start()
    await lookupItv.announceInterval(topic)
    t.ok(spy.callCount >= 1 && spy.callCount <= 2)
    t.alike(spy.firstCall.args, [topic, dhtKeyPair])
    await sleep(2200)
    t.ok(spy.callCount >= 2 && spy.callCount <= 3)
    t.alike(spy.lastCall.args, [topic, dhtKeyPair])
    await lookupItv.unnannounceInterval(topic)
    await sleep(2200)
    t.ok(spy.callCount <= 3)
    await lookupItv.stop()

    spy.resetHistory()

    t.comment('should support multiple key pairs for same topic')
    lookupItv.start()
    await lookupItv.announceInterval(topic)
    await lookupItv.announceInterval(topic, otherKeyPair)
    t.ok(spy.callCount >= 2 && spy.callCount <= 4)
    await sleep(2200)
    t.ok(spy.callCount >= 4 && spy.callCount <= 6)
    t.ok(spy.getCalls().every(c => c.args[0] === topic))
    t.ok(spy.getCalls().some(c => c.args[1].publicKey.toString('hex') === dhtPublicKey))
    t.ok(spy.getCalls().some(c => c.args[1].publicKey.toString('hex') === otherPublicKey))
    await lookupItv.stop()
  })
})
