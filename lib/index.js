/**
 * @typedef {Object} Identifier - an object identifying a key pair by either an
     address or a name

 * @property {string} address - the address of a key pair
 * @property {string} name - the name of a key pair
 */

/**
 * @module eris-keys
 */

'use strict'

const childProcess = require('mz/child_process')
const R = require('ramda')
var request = require('request-promise')
var url = require('url')
var _ = require('lodash')

const exec = R.composeP(R.trim, R.head, childProcess.exec)

const dockerMachineIp = (exec) =>
  exec('docker-machine ip $(docker-machine active)').catch(() => 'localhost')

// Return the URL for an Eris service on a running container.
exports.serviceUrl = (type, name, port, options = {exec}) =>
  Promise.all([
    dockerMachineIp(options.exec),

    options.exec(`
      id=$(eris ${type} inspect ${name} Id)
      docker inspect --format='{{(index (index .NetworkSettings.Ports "${port}\
/tcp") 0).HostPort}}' $id
    `)
  ]).then(([hostname, port]) => ({
    protocol: 'http:',
    hostname,
    port
  })
)

/**
 * Connect to the key server.
 * @param {string} url
 * @returns {Promise.<Object>} connection
 */
exports.connect = function (serverUrl) {
  function serverRequest (pathname, body) {
    return request.post({
      url: url.resolve(url.format(serverUrl), pathname),
      body: body || {},
      json: true
    }).then(function (body) {
      if (body.Error) {
        throw body.Error
      } else {
        return body.Response
      }
    })
  }

  return {
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
        return {address: address}
      })
    },

    /**
     * Retrieve the public key associated with the specified address or name.
     * @param {Identifier} keyPair - key pair identifier
     * @returns {Promise.<string>}
     */
    publicKeyFor: function (keyPair) {
      return serverRequest('pub', _.mapKeys(keyPair, function (value, key) {
        return key === 'address' ? 'addr' : key
      }))
    },

    /**
     * Sign a message with a key pair.
     * @param {(Buffer|string)} message
     * @param {Identifier} keyPair - key pair identifier
     * @returns {Promise.<Buffer>} signature
     */
    sign: function (message, keyPair) {
      var query

      query = _.mapKeys(keyPair, function (value, key) {
        return key === 'address' ? 'addr' : key
      })

      query.msg = Buffer(message).toString('hex')

      return serverRequest('sign', query).then(function (signature) {
        return Buffer(signature, 'hex')
      })
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
        return response === 'true'
      })
    }
  }
}
