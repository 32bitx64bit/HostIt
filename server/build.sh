#!/usr/bin/env sh
set -eu

# Builds the server binary into ./bin/
# Optional: GOOS=linux GOARCH=amd64 ./build.sh

mkdir -p bin

go build -trimpath -ldflags "-s -w" -o bin/tunnel-server ./cmd/server

echo "Built: bin/tunnel-server"