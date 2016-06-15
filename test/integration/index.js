'use strict'

var assert = require('assert')
var keys = require('../../lib')
var Promise = require('bluebird')

describe('a client for eris-keys', function () {
  it('generates a key, signs a message, and verifies the signature',
    function (done) {
      this.timeout(10 * 1000)

      // Open a connection to the server.
      keys.serviceUrl('services', 'keys', 4767).then(function (url) {
        console.log('URL', url)
        keys.open(url).then(function (server) {
          // Generate a new key pair.
          server.generateKeyPair().then(function (keyPair) {
            var message

            message = 'a message in a bottle'

            Promise.all([
              // Get the public key of the key pair.
              server.publicKeyFor(keyPair),

              // Sign the message.
              server.sign(message, keyPair)
            ]).spread(function (publicKey, signature) {
              server.verifySignature(message, signature, publicKey)
                .then(function (valid) {
                  assert(valid)
                  server.close()
                  done()
                })
            })
          })
        })
      })
    })
})
