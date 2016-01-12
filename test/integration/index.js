'use strict';

require('longjohn');

var
  assert = require('assert'),
  keys = require('../../lib'),
  Promise = require('bluebird');

describe("a client for eris-keys", function () {
  it("generates a key, signs a message, and verifies the signature",
    function (done) {
      // Open a connection to the server.
      keys.open().then(function (server) {
        // Generate a new key pair.
        server.generateKeyPair().then(function (keyPair) {
          var
            message;

          message = "a message in a bottle";

          Promise.all([
            // Get the public key of the key pair.
            server.publicKeyFor(keyPair),

            // Sign the message.
            server.sign(message, keyPair)
          ]).spread(function (publicKey, signature) {
            server.verifySignature(message, signature, publicKey)
              .then(function (valid) {
                assert(valid);
                server.close();
                done();
              });
          });
        });
      });
    });
});
