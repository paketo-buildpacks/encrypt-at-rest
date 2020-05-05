#!/usr/bin/env bash

set -euo pipefail

if [[ -d ../go-cache ]]; then
  GOPATH=$(realpath ../go-cache)
  export GOPATH
fi

GOOS="linux" go build -ldflags='-s -w' -o bin/decrypt-application github.com/paketo-buildpacks/encrypt-at-rest/cmd/decrypt-application
GOOS="linux" go build -ldflags='-s -w' -o bin/main github.com/paketo-buildpacks/encrypt-at-rest/cmd/main
ln -fs main bin/build
ln -fs main bin/detect
