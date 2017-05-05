#!/bin/sh
set -o errexit
set -o xtrace

# Install Docker Machine because CircleCI's Docker support is hobbled.
curl -L https://github.com/docker/machine/releases/download/\
$DOCKER_MACHINE_VERSION/docker-machine-`uname -s`-`uname -m` > \
$HOME/bin/docker-machine && chmod +x $HOME/bin/docker-machine

docker-machine create --driver digitalocean default
eval $(docker-machine env default)

# Install Monax CLI.
sudo add-apt-repository https://pkgs.monax.io/apt
curl -L https://pkgs.monax.io/apt/APT-GPG-KEY | sudo apt-key add -
sudo apt-get --quiet update
sudo apt-get install --assume-yes --quiet monax
monax init --yes

npm test
