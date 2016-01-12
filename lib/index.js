/**
 * @typedef {Object} Identifier - an object identifying a key pair by either an
     address or a name

 * @property {string} address - the address of a key pair
 * @property {string} name - the name of a key pair
 */

/**
 * @module eris-keys
 */

'use strict';

var
  Promise = require('bluebird'),
  request = require('request-promise'),
  _ = require('lodash');

/**
 * Open the connection to the key server.
 * @param {string} [hostname = keys]
 * @param {number} [port = 4767]
 * @returns {Promise.<Object>} connection
 */
exports.open = function (hostname, port) {
  function serverRequest(pathname, body) {
    return request.post({
      uri: {
        protocol: 'http:',
        hostname: hostname,
        port: 4767,
        pathname: '/' + pathname
      },
      body: body || {},
      json: true
    }).then(function (body) {
      if (body.Error)
        throw body.Error;
      else
        return body.Response;
    });
  }

  hostname = hostname || 'keys';
  port = port || 4767;

  // Return a promise in case we switch to WebSocket someday.
  return Promise.resolve({
    /**
     * Close the connection to the key server.
     */
    close: function () {
      // This is here in case we switch to a stateful protocol in the future
      // like WebSocket.
    },

    /**
     * Generate a new key.
     * @param {Object} [options]
     * @param {string} [options.auth]
     * @param {string} [options.type=ed25519,ripemd160] - the type of key
         to generate

     * @param {string} [options.name] - a name for the new key
     * @returns {Promise.<Identifier>} key pair identifier
     */
    generateKeyPair: function (options) {
      return serverRequest('gen', options).then(function (address) {
        return {address: address};
      });
    },

    /**
     * Retrieve the public key associated with the specified address or name.
     * @param {Identifier} keyPair - key pair identifier
     * @returns {Promise.<string>}
     */
    publicKeyFor: function (keyPair) {
      return serverRequest('pub', _.mapKeys(keyPair, function (value, key) {
        return key === 'address' ? 'addr' : key;
      }));
    },

    /**
     * Sign a message with a key pair.
     * @param {(Buffer|string)} message
     * @param {Identifier} keyPair - key pair identifier
     * @returns {Promise.<Buffer>} signature
     */
    sign: function (message, keyPair) {
      var
        query;

      query = _.mapKeys(keyPair, function (value, key) {
        return key === 'address' ? 'addr' : key;
      });

      query.msg = Buffer(message).toString('hex');

      return serverRequest('sign', query).then(function (signature) {
        return Buffer(signature, 'hex');
      });
    },

    /**
     * Verify the signature of a message.
     * @param {(Buffer|string)} message
     * @param {Buffer} signature
     * @param {string} publicKey
     * @returns {Promise.<boolean>}
     */
    verifySignature: function (message, signature, publicKey) {
      return serverRequest('verify', {
        msg: Buffer(message).toString('hex'),
        sig: Buffer(signature).toString('hex'),
        pub: publicKey
      }).then(function (response) {
        return response === 'true';
      });
    }
  });
};
