'use strict'

const assert = require('assert')
const keys = require('../../lib')

describe('a client for monax-keys', function () {
  it('generates a key, signs a message, and verifies the signature',
    function () {
      this.timeout(10 * 1000)

      // Open a connection to the server.
      return keys.serviceUrl('services', 'keys', 4767).then((url) => {
        const server = keys.connect(url)

        // Generate a new key pair.
        return server.generateKeyPair().then((keyPairId) => {
          const message = 'a message in a bottle'

          return Promise.all([
            // Get the public key of the key pair.
            server.publicKeyFor(keyPairId),

            // Sign the message.
            server.sign(message, keyPairId)
          ]).then(([publicKey, signature]) =>
            server.verifySignature(message, signature, publicKey)
              .then((valid) => {
                assert(valid)
              })
          )
        })
      })
    })
})
