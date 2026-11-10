# AGENTS.md

Notes for automated agents working in this repository. Read this before changing
build tooling or making assumptions about the runtime.

## What this is

`webpush-apn-relay` (historically "toot-relay") is a single Go service that
accepts RFC 8030 web push POSTs and forwards the encrypted payloads to iOS via
APNs. Origin: Mastodon's relay for the Toot! client. Module path is
`github.com/mastodon/webpush-apn-relay`.

~450 lines across two files. No database, no frontend, no code generation, no
test files, no linter config.

## Layout

| Path | Notes |
|---|---|
| `main.go` | Entry point, config, HTTP routes, z85 encoder, header parsing |
| `process_apn_notification.go` | Worker pool, APNs push, 410 unsubscribe handling |
| `Dockerfile` | Multi-stage in-container build. **Used by CI.** |
| `Dockerfile.cross` | Runtime-only image; binary is built on the host |
| `build.sh` | Cross-compiles then invokes `Dockerfile.cross` |
| `cas.crt` | Bundled CA, baked into the image as `CA_FILENAME` |
| `iOS/*.swift` | Vendored client reference code. **Not compiled by anything here.** |
| `now.json` | Legacy Zeit Now config. Ignore unless asked about it. |
| `.github/workflows/` | `go.yml` (build+test), `release.yml` (publish to ghcr.io) |

`iOS/` is excluded from language stats via `.gitattributes` and is not part of
any build. Do not try to compile it.

## Commands

Go is installed via Homebrew and may not be on a non-interactive `PATH`:

```sh
export PATH="/home/linuxbrew/.linuxbrew/bin:$PATH"
```

```sh
go build -v ./...            # build
go vet ./...                 # vet (clean at time of writing)
go test ./...                # "no test files" is the expected result
```

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

- **`Dockerfile`** compiles inside `golang:1.26-trixie`. Correct on native
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

- **Datadog tracer warnings are benign.** `Unable to reach agent intake: ...
  localhost:8126 ... connection refused` is normal without a DogStatsD agent; the
  tracer continues. Note `tracer.Start()` failure *is* fatal, so do not conclude
  the tracer is optional.
- **Timestamps inside the container are UTC.** Distroless has no `tzdata`.
- **`CA_FILENAME` is unset locally but `/cas.crt` in the image.** Locally
  `os.ReadFile("")` errors and the error is correctly ignored, falling back to
  system roots. Not a bug.

## Conventions and shape of the code

- Routes use Go 1.22+ method-and-wildcard patterns and depend on
  `httptrace.NewServeMux()` returning a `*ServeMux` that supports
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
  a wire format shared with the iOS client — changing it breaks decryption.
- `aes128gcm` is accepted in the `Content-Encoding` switch but the README says
  the client cannot handle it. Confirm client support before relying on it.

## Verifying changes

There are no tests, so verify by running the binary or image and checking it
reaches the expected credential error (or starts cleanly when credentials are
supplied). To confirm a build targeted the right architecture:

```sh
podman inspect <image> --format '{{.Architecture}} {{.Os}}'
file ./webpush-apn-relay
```

CI runs only `go build -v ./...` and `go test -v ./...`, so anything that fails
`go build` breaks the release pipeline.

## Local environment facts

Debian 13 (trixie) on aarch64 (Raspberry Pi 5). Homebrew at
`/home/linuxbrew/.linuxbrew`. Installed: Go 1.27.3 via brew (`go.mod` declares
1.26; builds fine), podman 5.4.2 + `uidmap` + `qemu-user-static` via apt.
Rootless podman works. `sudo` requires a password, so apt installs must be run
by the user.
