#!/usr/bin/env bash
# Cross-compile the relay and package it into a distroless image.
#
# Builds the Go binary natively on the host with GOARCH set to the target, then
# copies the static binary into a runtime-only image. This avoids running the Go
# compiler under QEMU emulation, which crashes on go1.26/go1.27 + qemu-user-static
# 10.0.x ("sweep increased allocation count" / SIGSEGV in the GC).
#
# Usage:
#   ./build.sh                  # build for linux/amd64 (default deploy target)
#   ./build.sh arm64            # build for linux/arm64
#   ./build.sh amd64 --no-image # compile only, skip the container image
set -euo pipefail

cd "$(dirname "$0")"

GOARCH_TARGET="${1:-amd64}"
SKIP_IMAGE=0
[[ "${2:-}" == "--no-image" ]] && SKIP_IMAGE=1

case "$GOARCH_TARGET" in
  amd64 | arm64) ;;
  *)
    echo "unsupported GOARCH: $GOARCH_TARGET (want amd64 or arm64)" >&2
    exit 1
    ;;
esac

command -v go >/dev/null 2>&1 || {
  echo "go not found on PATH; install with: brew install go" >&2
  exit 1
}

VERSION="$(git describe --tags --always 2>/dev/null || echo dev)"
GIT_COMMIT_SHA="$(git rev-parse HEAD 2>/dev/null || echo unknown)"
GIT_REPOSITORY_URL="$(git remote get-url origin 2>/dev/null || echo unknown)"
# Include the arch in the tag so building both architectures does not silently
# overwrite the earlier one under an identical tag.
IMAGE_TAG="webpush-apn-relay:${VERSION}-linux-${GOARCH_TARGET}"

echo "==> building linux/${GOARCH_TARGET} (version ${VERSION})"
# CGO_ENABLED=0 is required: it yields a fully static binary that runs on
# distroless, which has no glibc.
CGO_ENABLED=0 GOOS=linux GOARCH="$GOARCH_TARGET" \
  go build -ldflags "-s -w" -o "webpush-apn-relay" .

# Fail fast if the wrong arch slipped through (e.g. a stale binary).
file "webpush-apn-relay" | grep -qE "$(
  [[ $GOARCH_TARGET == amd64 ]] && echo 'x86-64' || echo 'aarch64'
)" || {
  echo "built binary is not linux/${GOARCH_TARGET}" >&2
  file "webpush-apn-relay" >&2
  exit 1
}
file "webpush-apn-relay" | grep -q 'statically linked' || {
  echo "binary is not statically linked; CGO_ENABLED=0 did not take effect" >&2
  exit 1
}

if [[ $SKIP_IMAGE -eq 1 ]]; then
  echo "==> skipping image (--no-image)"
  exit 0
fi

command -v podman >/dev/null 2>&1 || {
  echo "podman not found on PATH" >&2
  exit 1
}

echo "==> building image ${IMAGE_TAG} (linux/${GOARCH_TARGET})"
podman build \
  --platform "linux/${GOARCH_TARGET}" \
  -f Dockerfile.cross \
  --build-arg TARGETPLATFORM="linux/${GOARCH_TARGET}" \
  --build-arg GIT_REPOSITORY_URL="$GIT_REPOSITORY_URL" \
  --build-arg GIT_COMMIT_SHA="$GIT_COMMIT_SHA" \
  --build-arg VERSION="$VERSION" \
  -t "$IMAGE_TAG" \
  .

echo "==> done: ${IMAGE_TAG}"
