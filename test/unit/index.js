'use strict'

var assert = require('assert')
var crypto = require('crypto')
var ed = require('ed25519-supercop')
var keys = require('../../lib')
var nock = require('nock')
var random = require('seed-random')('marmot')

const mockExec = (portMap) =>
  (command) =>
    Promise.resolve(command === 'docker-machine ip $(docker-machine active)'
      ? '192.168.99.100'
      : portMap)

describe('eris inspection', function () {
  it('gets the port mappings for a chain', function () {
    const exec = mockExec(`33121`)

    return keys.serviceUrl('chain', 'blockchain', 1337, {exec}).then((url) => {
      assert.deepEqual(url, {
        protocol: 'http:',
        hostname: '192.168.99.100',
        port: 33121
      })
    })
  })

  it('gets the port mapping for Eris Keys', function () {
    const exec = mockExec('33128')

    return keys.serviceUrl('services', 'keys', 4767, {exec}).then((url) => {
      assert.deepEqual(url, {
        protocol: 'http:',
        hostname: '192.168.99.100',
        port: 33128
      })
    })
  })

  it('gets the port mapping for Eris Keys with localhost', function () {
    const exec = (command) =>
        command === 'docker-machine ip $(docker-machine active)'
          ? Promise.reject()
          : Promise.resolve(33128)

    return keys.serviceUrl('services', 'keys', 4767, {exec}).then((url) => {
      assert.deepEqual(url, {
        protocol: 'http:',
        hostname: 'localhost',
        port: 33128
      })
    })
  })
})

// Generate a random 32 byte seed deterministically.
function randomSeed () {
  var seed

  for (seed = []; seed.length < 32;) {
    seed.push(Math.floor(random() * 256))
  }

  return Buffer(seed)
}

function addressFromKey (publicKey) {
  var hash

  hash = crypto.createHash('RIPEMD160')
  hash.update(publicKey)
  return hash.digest('hex')
}

describe('a client for eris-keys', function () {
  var server, keyPair, address, identifier

  before(function () {
    keyPair = ed.createKeyPair(randomSeed())
    address = addressFromKey(keyPair.publicKey)
    identifier = {address: address}
    server = keys.open('http://localhost:4767/')
  })

  beforeEach(function () {
    nock.cleanAll()

    nock('http://localhost:4767')
      .post('/gen')
      .reply(200, {Response: address})
      .post('/pub', {addr: address})
      .reply(200, {Response: keyPair.publicKey.toString('hex')})
      .post('/pub', {name: 'marmot'})
      .reply(200, {Response: keyPair.publicKey.toString('hex')})
      .post('/pub', {name: 'badger'})
      .reply(200, {
        Error: 'open ~/.eris/keys/names/badger: no such file or directory'
      })
      .post('/sign')
      .reply(200, function (uri, request) {
        var message

        message = Buffer(request.msg, 'hex')

        return {Response: ed.sign(message, keyPair.publicKey,
          keyPair.secretKey).toString('hex')}
      })
      .post('/verify')
      .reply(200, function (uri, request) {
        var message, signature, publicKey

        message = Buffer(request.msg, 'hex')
        signature = Buffer(request.sig, 'hex')
        publicKey = Buffer(request.pub, 'hex')

        return {Response: ed.verify(signature, message, publicKey)
            ? 'true'
          : 'false'}
      })
  })

  it('generates a new key pair', function () {
    return server.generateKeyPair().then(function (generatedIdentifier) {
      assert.deepEqual(generatedIdentifier, identifier)
    })
  })

  it('returns the public key for an address', function () {
    return server.publicKeyFor(identifier).then(function (key) {
      assert.equal(key, keyPair.publicKey.toString('hex'))
    })
  })

  it('returns the public key for a named address', function () {
    return server.publicKeyFor({name: 'marmot'}).then(function (key) {
      assert.equal(key, keyPair.publicKey.toString('hex'))
    })
  })

  it('reports a missing key error', function () {
    return server.publicKeyFor({name: 'badger'})
      .then(function () {
        assert(false)
      })
      .catch(function () {
        assert(true)
      })
  })

  it('signs a message', function (done) {
    server.sign('a message', identifier).then(function (signature) {
      server.verifySignature('a message', signature, keyPair.publicKey)
        .then(function (valid) {
          assert(valid)
          done()
        })
    })
  })

  it('signs a message with a named key', function (done) {
    server.sign('a message', {name: 'marmot'}).then(function (signature) {
      server.verifySignature('a message', signature, keyPair.publicKey)
        .then(function (valid) {
          assert(valid)
          done()
        })
    })
  })
})
