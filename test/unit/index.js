'use strict'

var rewire = require('rewire')
var assert = require('assert')
var crypto = require('crypto')
var ed = require('ed25519-supercop')
var keys = rewire('../../lib')
var nock = require('nock')
var Promise = require('bluebird')
var random = require('seed-random')('marmot')

function mockExec (portMap) {
  return function (command, options) {
    return Promise.resolve(command === 'docker-machine ip'
      ? '192.168.99.100'
      : portMap)
  }
}

describe('eris inspection', function () {
  it('gets the port mappings for a chain', function () {
    keys.__set__('childProcess', {execAsync: mockExec(`map[1337/tcp:[{0.0.0.0 33121}] 46656/tcp:[{0.0.0.0 33120}] 46657/tcp:[{0.0.0.0 33119}]]\n`)})

    return keys.serviceUrl('chain', 'blockchain', 1337).then(function (url) {
      assert.deepEqual(url, {
        protocol: 'http:',
        hostname: '192.168.99.100',
        port: 33121
      })
    })
  })

  it('gets the port mapping for Eris Keys', function () {
    keys.__set__('childProcess', {
      execAsync: mockExec('map[4767/tcp:[{0.0.0.0 33128}]]\n')
    })

    return keys.serviceUrl('services', 'keys', 4767).then(function (map) {
      assert.deepEqual(map, {
        protocol: 'http:',
        hostname: '192.168.99.100',
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

  before(function (done) {
    keyPair = ed.createKeyPair(randomSeed())
    address = addressFromKey(keyPair.publicKey)
    identifier = {address: address}

    keys.open('http://localhost:4767/').then(function (opened) {
      server = opened
      done()
    })
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

  after(function () {
    server.close()
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
