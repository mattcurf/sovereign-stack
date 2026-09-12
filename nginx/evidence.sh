#!/bin/sh
set -eu
mkdir -p /evidence/npm /evidence/build-os/var/lib/dpkg
cp package*.json /evidence/
node --version > /evidence/node-version.txt
npm --version > /evidence/npm-version.txt
cp /usr/local/LICENSE /evidence/NODE-LICENSE
cp /var/lib/dpkg/status /evidence/build-os/var/lib/dpkg/status
cp -a /usr/share/doc /evidence/build-os/doc
# Retain package identities and attribution, not an unused copy of the npm CLI.
cd /usr/local/lib/node_modules/npm
find . -type f \( -name 'package.json' -o -iname '*license*' -o -iname '*notice*' -o -iname '*copying*' \) \
    -exec cp --parents {} /evidence/npm/ \;
