#!/bin/sh
set -o errexit
set -o xtrace

# Install the Eris CLI.

if [ $CIRCLE_BRANCH = 'master' ]; then
  sudo add-apt-repository https://apt.monax.io
  curl -L https://apt.monax.io/APT-GPG-KEY | sudo apt-key add -
  sudo apt-get --quiet update
  sudo apt-get install --assume-yes --quiet eris
else
  go get github.com/eris-ltd/eris-cli/cmd/eris
  cd $HOME/.go_workspace/src/github.com/eris-ltd/eris-cli/cmd/eris
  git checkout develop
  go install
fi

eris version
