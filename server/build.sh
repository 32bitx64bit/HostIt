#!/usr/bin/env sh
set -eu

# Builds the server binary into ./bin/
# Optional: GOOS=linux GOARCH=amd64 ./build.sh

log() {
	# POSIX-safe timestamped log
	printf '%s %s\n' "$(date '+%H:%M:%S')" "$*"
}

die() {
	log "ERROR: $*"
	exit 1
}

command -v go >/dev/null 2>&1 || die "go not found in PATH"

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" 2>/dev/null && pwd) || die "failed to resolve script directory"

( 
	cd "$SCRIPT_DIR" || exit 1
	OUT_DIR="bin"
	OUT_BIN="$OUT_DIR/tunnel-server"
	PKG="./cmd/server"

	log "HostIt server build starting"
	log "Dir: $SCRIPT_DIR"
	log "Go: $(go version 2>/dev/null || echo unknown)"
	log "Env: GOOS=${GOOS-} GOARCH=${GOARCH-} CGO_ENABLED=${CGO_ENABLED-}"
	log "Output: $OUT_BIN"
	log "Package: $PKG"

	mkdir -p "$OUT_DIR"

	log "Building…"
	go build -v -trimpath -ldflags "-s -w" -o "$OUT_BIN" "$PKG"

	log "Built: $OUT_BIN"
	if command -v file >/dev/null 2>&1; then
		file "$OUT_BIN" || true
	fi
	if command -v ls >/dev/null 2>&1; then
		ls -lh "$OUT_BIN" || true
	fi

	log "✅ Build finished"
)