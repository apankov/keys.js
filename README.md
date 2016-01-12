This is a JavaScript client library to facilitate interaction with an [Eris Keys](https://github.com/eris-ltd/eris-keys) server.

# Installation

`$ npm install eris-keys`

# Usage

First start a key server:

`$ eris services start keys --publish`

You need to know the IP address and port number of the key server.  If you're using [Docker Machine](https://docs.docker.com/machine/) you can find out the IP address with the command `docker-machine ip default`.  Discover the port mapping with the command `eris services inspect keys NetworkSettings.Ports`.

In the example below, the IP address is `192.168.99.100` and the port number is `32769`:

```shell
$ docker-machine ip default
192.168.99.100
$ eris services inspect keys NetworkSettings.Ports
map[4767/tcp:[{0.0.0.0 32769}]]
```

Once you have those numbers, pass them as arguments to the `keys.open` function, replacing `IPADDRESS` and `PORT` below.

```JavaScript
'use strict';

var
  assert = require('assert'),
  keys = require('eris-keys'),
  Promise = require('bluebird');

describe("a client for eris-keys", function () {
  it("generates a key, signs a message, and verifies the signature",
    function (done) {
      // Open a connection to the server.
      keys.open(IPADDRESS, PORT).then(function (server) {
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
                
                // Close the connection to the server.
                server.close();
                done();
              });
          });
        });
      });
  });
});
```

# Documentation

You can generate documentation in the `doc` subdirectory with the command `npm run doc`.

# Copyright

Copyright 2016 Eris Industries

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.