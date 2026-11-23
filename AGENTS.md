# AGENTS.md

Notes for automated agents working in this repository. Read this before changing
build tooling or making assumptions about the runtime.

**Do not add a `Co-Authored-By:` trailer to commits in this repository** — nor
`Assisted-By:`, `Generated-With:`, or any other trailer attributing the work to a
model or tool. Commit messages describe the change, not the software that typed
it. If a commit already has one, remove the line rather than amending around it.

## What this is

`webpush-apn-relay` (historically "toot-relay") is a single Go service that
accepts RFC 8030 web push POSTs and forwards the encrypted payloads to iOS via
APNs. Origin: Mastodon's relay for the Toot! client. Module path is
`github.com/mastodon/webpush-apn-relay`.

~800 lines across three files, plus `main_test.go`. No database, no frontend, no
code generation, no linter config.

## Layout

| Path | Notes |
|---|---|
| `main.go` | Entry point, config, HTTP routes, z85 encoder, header parsing |
| `process_apn_notification.go` | Worker pool, APNs push, 410 unsubscribe handling |
| `metrics.go` | Prometheus registry, metric definitions, `/metrics` helper wiring |
| `observability/` | Prometheus + Grafana stack, generated dashboard, alert rules. Not part of the Go build. |
| `Dockerfile` | Multi-stage in-container build. **Used by CI.** |
| `Dockerfile.cross` | Runtime-only image; binary is built on the host |
| `build.sh` | Cross-compiles then invokes `Dockerfile.cross`. **Local images only** — see "Releasing" |
| `cas.crt` | Pinned root CA for APNs TLS (USERTrust RSA); baked into the image as `CA_FILENAME`. See Runtime gotchas |
| `iOS/*.swift` | Vendored Toot! client — the reference for the wire format. **Not compiled by anything here.** |
| `now.json` | Legacy Zeit Now config. Ignore unless asked about it. |
| `.github/workflows/` | `go.yml` (build+test), `release.yml` (publish to ghcr.io) |

`iOS/` is excluded from language stats via `.gitattributes` and is not part of
any build. Do not try to compile it as part of `go build`. It is the vendored
Toot! client, kept as the reference for the wire format the relay must match, and
it is type-checkable with the `swiftc` on a macOS host — see "Local environment
facts".

## Commands

Go is installed via Homebrew and may not be on a non-interactive `PATH`:

```sh
export PATH="/home/linuxbrew/.linuxbrew/bin:$PATH"
```

```sh
go build -v ./...            # build
go vet ./...                 # vet (clean at time of writing)
go test ./...                # main_test.go: aes128gcm header shape checks
```

Commit with a plain message: subject line, blank line, body. No
`Co-Authored-By:` (see the note at the top).

Images are built with **podman**, not docker. On Debian use `/usr/bin/podman`
(5.4.2); do not install podman from Homebrew, its build has no Linux `uidmap`
dependency and rootless mode fails with
`exec: "newuidmap": executable file not found in $PATH`.

```sh
./build.sh                   # linux/amd64 image (default)
./build.sh arm64             # linux/arm64 image
./build.sh amd64 --no-image  # compile only
```

## Build guidance

There are two image paths, and the choice matters:

- **`Dockerfile`** compiles inside `golang:1.27-trixie`. Correct on native
  architecture and what `release.yml` runs. CI is unaffected by the emulation
  issue below because GitHub runners are native x86_64.
- **`build.sh` + `Dockerfile.cross`** compiles on the host with `GOOS`/`GOARCH`
  and copies the static binary into distroless. Use this when the build host and
  deploy target differ. Roughly 1s versus several minutes.

**Do not "fix" the emulation crash by adding `ENV GOGC=off` to `Dockerfile`.**
Cross-building amd64 on arm64 with `Dockerfile` fails in `RUN go mod download`
with non-deterministic GC faults (`sweep increased allocation count`, or
`SIGSEGV` at a garbage address). Cause is qemu-user-static 10.0.x mis-emulating
Go's concurrent GC marking, not this repository: `go version` under the same
emulation succeeds, and `GOGC=off` makes it pass 3/3. That is a workaround for a
host defect and it degrades native CI builds for no benefit. Route around it via
`build.sh` instead.

Cross-compiling is safe here specifically because `CGO_ENABLED=0` produces a
fully static binary (`ldd` reports "not a dynamic executable"), which is what
lets it run on distroless — an image with no glibc. `build.sh` asserts both the
architecture and `statically linked` before committing an image; keep those
guards if you touch the script.

### Keep Go on the latest stable release

This project deliberately tracks the newest stable Go. Most minor releases
include security fixes to the standard library (`net/http`, `crypto/*`,
`net/http2`), and this service is an internet-facing HTTP server that terminates
TLS to APNs, so those fixes are the point — not the language features. Do not
leave the version pinned at an older release because it "works".

**Three places pin the version, and all three must move together.** Bumping only
`go.mod` is the usual mistake; it silently leaves release images on the old
compiler:

1. `go.mod` — the `go` directive. `go mod tidy` will *lower* it to the highest
   directive any dependency declares, so the floor is whatever the dependencies
   require (as of writing, `golang.org/x/net`, `x/crypto`, `x/sys`, `x/text` and
   `prometheus/common` all declare `go 1.26.0`). Setting it above that floor is
   allowed and is what we want; expect `tidy` to leave it alone.
2. `Dockerfile` — `FROM golang:<ver>-trixie`. This is the compiler that builds
   the published image, so it is the one that actually determines whether a
   release contains a given stdlib fix. `release.yml` runs this file.
3. `.github/workflows/go.yml` — `go-version-file: go.mod`, which follows item 1
   automatically. Nothing to edit, which is why it is easy to overlook that CI
   and `Dockerfile` can disagree.

`build.sh` compiles with the host toolchain, so the local build tracks whatever
Homebrew has at `/home/linuxbrew/.linuxbrew/bin/go`. With `GOTOOLCHAIN=auto`
(the default) the `go` command will also download a newer toolchain on demand if
a `go.mod` asks for one, so no host action is normally needed.

When bumping, verify the image tag exists before pushing, since `release.yml`
fails on a bad tag only at release time:

```sh
podman manifest inspect docker.io/library/golang:1.27-trixie >/dev/null && echo tag exists
```

Prefer a `-trixie` suffix over the bare major tag so the Debian base stays
aligned with `gcr.io/distroless/base-debian13` in the runtime stage.

## Runtime gotchas

The service **exits at startup without APNs credentials**. This is the single
most common cause of "the image builds but won't run" and is not a bug. Credent-
ials are read in this order, first defined wins:

1. `TOKEN_AUTH_KEY_FILENAME` (with `TOKEN_KEY_ID`, `TOKEN_TEAM_ID`)
2. `P12_BASE64`
3. `P12_FILENAME` (default `toot-relay.p12`)

`.p12` files are gitignored and absent from the repo, so a fresh checkout cannot
run without supplying one. Expected failure:

```
level=fatal msg="Error loading certificate file: open toot-relay.p12: no such file or directory"
```

Other things that look like failures but are not:

- **Metrics are off by default.** `/metrics` exists only when started with
  `-metrics-port` (or `METRICS_PORT`). It is a separate listener bound to
  `127.0.0.1` by default, so the public relay port returns 404 for it — that is
  intentional isolation, not a broken route. A metrics bind failure is logged,
  never fatal. See `observability/README.md`.
- **`DD_VERSION` is not dead despite the tracer being gone.** It feeds
  `userAgent()`, which is set on the unsubscribe `DELETE`. Renaming or removing
  it changes what the origin server sees. `DD_GIT_REPOSITORY_URL` and
  `DD_GIT_COMMIT_SHA`, still set by both Dockerfiles, *are* unread by any code.
- **Timestamps inside the container are UTC.** Distroless has no `tzdata`.
- **`CA_FILENAME` is unset locally but `/cas.crt` in the image.** Locally
  `os.ReadFile("")` errors and the error is correctly ignored, falling back to
  system roots. Not a bug.
- **`cas.crt` is pinned to exactly one root: USERTrust RSA Certification
  Authority**, added in `15cbd8f` (2021) when Apple's APNs chain terminated in
  AddTrust/USERTrust. It still works — Apple currently serves a two-cert chain
  (`api.push.apple.com` <- `Apple Public Server RSA CA 11 - G1` <- USERTrust RSA)
  — but it is *pinning*, not supplementing: `x509.NewCertPool()` starts empty and
  `AppendCertsFromPEM` adds only what is in the file, so the system store is not
  consulted. If Apple moves APNs to a root with no USERTrust cross-signature,
  every push fails with a certificate error and only a rebuild fixes it. The file
  is not a secret and is not a private CA; it is a snapshot of one public root.
  `1024670` (2026-11-20) is what made it take effect on the token-auth path —
  before that `CA_FILENAME` was silently ignored unless using a `.p12`.

## Conventions and shape of the code

- Routes use Go 1.22+ method-and-wildcard patterns and depend on
  `http.NewServeMux()` returning a `*ServeMux` that supports
  `PathValue("extra...")` catch-all segments:
  `POST /relay-to/{environment}/{token}/{extra...}`, `GET /relay-to/_health`.
- Requests are **not** sent to APNs inline. They are pushed onto the package-level
  `messageChan`, and `maxWorkers` goroutines drain it. `main.go` pre-allocates
  `maxQueueSize` slots, so raising `-max-queue-size` costs real RAM.
- The handler replies `201` **before** the push is attempted, so the response
  never reflects the APNs outcome. Don't "improve" this without checking RFC 8030
  async/receipt semantics; the README states receipts are deliberately unimplemented.
- `context.WithoutCancel` is used deliberately when queueing, so a client
  disconnect does not abort a push already accepted. Preserve this.
- A `410` from APNs triggers a `DELETE` against the `Unsubscribe-Url` header.
  That is intentional subscription hygiene per Apple's docs, not an error path
  to swallow.
- `topic` and the `Message` fields are package-level globals. New code touching
  them inherits the existing data race surface; `go test` has no coverage to
  catch regressions.
- `encode85` implements z85 **extended** to arbitrary lengths (see README). It is
  a wire format shared with the iOS client — changing it breaks decryption. The
  digit table is z85's own:
  `0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#`.
  It is *not* the table in RFC 8292's example or in libzmq, which orders digits
  and letters differently; `iOS/Decode85.swift` must stay byte-identical to this
  table or every decode is garbage that surfaces only as an AEAD tag failure.
- `aes128gcm` (RFC 8291, the encoding senders use today) is accepted and its
  86-octet content-coding header is shape-checked by `checkAes128gcmHeader`.
  Nothing is copied out of the request headers for it — the salt and server key
  are in the body, so `p` carries the body whole. The check catches truncation
  only: the relay holds no key and cannot validate the crypto.
- `iOS/Aes128Gcm.swift` is the client side of that encoding and is the one piece
  of `iOS/` that is *not* vendored Toot! code. It derives keys with CryptoKit
  rather than Security/CommonCrypto because RFC 8291 §3.4 interleaves two HKDFs
  — the Expand of the first feeds the Extract of the second — which neither
  `CryptoKit.hkdfDerivedSymmetricKey` nor the fused `deriveKey` helper used by
  the `aesgcm` path can express. Each step is a plain HMAC-SHA-256 instead.
- **Never answer `4xx` for a relay-side failure.** Mastodon's
  `Web::PushNotificationWorker` destroys the `Web::PushSubscription` on any
  response in `400..499` except `408` and `429`, so a `4xx` from this service is
  effectively an unsubscribe command and can mass-unsubscribe users. Relay-side
  problems are `5xx`; `429` is reserved for a full queue (see
  `queueMessage`), `501` for an unsupported `Content-Encoding`. The one `4xx`
  the relay does send on a success path is `410`, and that is only in the
  `Unsubscribe-Url` `DELETE`, never as the push response.

## Verifying changes

`go test ./...` covers the aes128gcm header shape checks in `main_test.go`; there
is no test for the HTTP handler or the APNs path, so verify those by running the
binary and checking it reaches the expected credential error (or starts cleanly
when credentials are supplied). To confirm a build targeted the right
architecture:

```sh
podman inspect <image> --format '{{.Architecture}} {{.Os}}'
file ./webpush-apn-relay
```

CI runs only `go build -v ./...` and `go test -v ./...`, so anything that fails
`go build` breaks the release pipeline. Note that `go.yml` triggers on `push:
branches: [master]` while the default branch is **main**, so it does not run on
ordinary pushes — the three release runs on record are all `release.yml`. The Go
code is therefore verified locally, not by CI, unless that trigger is fixed.

### Type-checking the vendored Swift

Nothing compiles `iOS/`, so a syntax error there is invisible to CI. On a macOS
host the whole directory type-checks in a few seconds:

```sh
swiftc -typecheck -sdk "$(xcrun --show-sdk-path --sdk macosx)" \
  -import-objc-header iOS/BridgingHeader.h iOS/*.swift
```

The `-import-objc-header` is required, not optional: `PushNotificationReceiver`
uses `CCHmac*`, and `import CommonCrypto` from Swift does not work on macOS —
the framework has no Swift-visible module map, so the app's bridging header is
the only way in. This checks that the code compiles; it does not run it. To
actually decrypt something, see the harness note below.

### Running the client decryption against a real message

`iOS/` has no test target, and the aes128gcm path cannot be verified by
inspection — every key-schedule and padding mistake presents as either an AEAD
tag failure or corrupt JSON, with nothing pointing at the cause. A scratch SwiftPM
package that mirrors `iOS/` plus a Go fixture generator is the fastest way to
get a real answer; it is scaffolding, kept out of the repo, and is not something
CI can run (CI is Linux, CryptoKit is Apple-only). It produces a GoToSocial-shaped
message, sends it through the relay's own `encode85`, and decrypts it client-side.

## Releasing: images are built by GitHub Actions, not on a workstation

**Published images come from `.github/workflows/release.yml`, which is triggered
by publishing a GitHub Release — not by a tag push and not by a local build.**
Nothing needs to be built by hand to ship, and a container engine is not
required on the machine you develop on. The steps are:

```sh
git tag v0.9.2 && git push origin v0.9.2
gh release create v0.9.2 --generate-notes   # or draft it in the web UI
gh run list --workflow=release.yml           # watch the build
gh release view v0.9.2                       # image is ghcr.io/<owner>/<repo>:v0.9.2
```

Details that matter when doing this:

- `release.yml` fires on `release: types: [published]`. **Pushing the tag alone
  builds nothing.** The workflow reads `${{ github.ref_name }}` into the image
  tag and `VERSION` build arg, so it runs against the release's tag, not your
  working copy.
- `go.yml` runs `go build` + `go test` on push and on PRs, so the release build
  is not the first thing to compile your change unless you push the tag without
  CI having gone green.
- `docker/metadata-action` also produces `:latest` and the bare semver tags, so
  a published release moves `ghcr.io/<owner>/<repo>:latest`. Releasing a
  half-finished change is not harmless.
- `build.sh` is for **local/development images only**. It derives its tag from
  `git describe --tags --always`, so an untagged tree produces
  `webpush-apn-relay:v0.9.1-3-gabcdef-linux-arm64`, and it never pushes. Use it
  when the build host and deploy target differ in architecture; use a GitHub
  Release to actually ship.
- `release.yml` fails late and unhelpfully on a bad base image tag, which is why
  the `podman manifest inspect` check under "Keep Go on the latest stable
  release" is worth running before publishing.

## Local environment facts

Two different hosts have been used for this repo, and they differ in ways that
matter for the above.

**Build/deploy host** — Debian 13 (trixie) on aarch64 (Raspberry Pi 5). Homebrew
at `/home/linuxbrew/.linuxbrew`. Installed: Go 1.27.4 via brew (matches the
`golang:1.27-trixie` build image, so local and CI compile with the same
version), podman 5.4.2 + `uidmap` + `qemu-user-static` via apt. Rootless podman
works. `sudo` requires a password, so apt installs must be run by the user.

**macOS workstation (Apple Silicon)** — Go 1.27 via Homebrew at `/opt/homebrew/bin`,
which is *not* on a non-interactive `PATH`; prefix commands with
`export PATH="/opt/homebrew/bin:$PATH"`. Xcode and `swiftc` are present, so the
`iOS/` sources can at least be type-checked here. There is **no podman, docker,
or colima**, and the Homebrew podman formula is a client-only bottle with no
Linux `uidmap` — container builds belong in Actions on this host, not locally.

