# toot-relay

This is a small service, written in Go, that can be set as an endpoint for web
push notifications, and forwards the encrypted payloads it receives to an iOS
app through APNs. It is designed to forward notifications from Mastodon to
the iOS client Toot!, but may be of use in other cases too.

## Usage

Run `go build`, run `./toot-relay`. It will listen on port 42069. Subscribe to web
pushes using the endpoint
`http://<your-domain-name>:42069/relay-to/<environment>/<device-token>[/extra]`,
where `<environment>` is either `development` or `production`, `<device-token>`
is the hex encoded device token for the device to push to, and `extra` is any
extra information you want relayed back to your client.

You will need a push notification certificate, which should be put in the same
directory, named `toot-relay.p12`. With a production certificate, both pushing
to production and development environments works. With a development certificate,
only development will work.

## Docker

**Published images are built by GitHub Actions.** Publishing a GitHub Release
triggers `.github/workflows/release.yml`, which builds `Dockerfile` on a native
x86_64 runner and pushes `ghcr.io/<owner>/<repo>:<tag>` (and `:latest`). To ship
a version, tag it and publish a release — no local image build is involved, and
no container engine is needed on your machine:

```sh
git tag v0.9.2 && git push origin v0.9.2
gh release create v0.9.2 --generate-notes
```

The two paths below are for building images yourself, which you only need to do
to test a change before releasing it, or to run a fork that never gets a release.
Use the second one if you are building on a machine whose architecture differs
from your deploy target.

### In-container build (`Dockerfile`)

The default path, and what CI uses. Multi-stage: `golang:1.27-trixie` compiles
the service, and the result is copied into `gcr.io/distroless/base-debian13`.

The Go version tracks the latest stable release, because minor releases carry
security fixes to the standard library and this service is internet-facing and
terminates TLS to APNs. See the *Keep Go on the latest stable release* section of
[`AGENTS.md`](AGENTS.md) — the version is pinned in `go.mod` **and** in
`Dockerfile`, and both have to move together.

```sh
podman build -t webpush-apn-relay .
```

This builds for the architecture of the build host. Add `--platform linux/amd64`
to target a different architecture, but see the caveat below before doing so.

### Cross-compiled build (`Dockerfile.cross` + `build.sh`)

Cross-compiles with the host Go toolchain (`GOOS`/`GOARCH`), then copies the
static binary into a distroless image. There is no build stage, so no compiler
runs under emulation.

```sh
./build.sh              # linux/amd64
./build.sh arm64        # linux/arm64
./build.sh amd64 --no-image   # compile only
```

Images are tagged `webpush-apn-relay:<version>-linux-<arch>` so that building
for several architectures does not overwrite earlier results. The script also
asserts that the compiled binary matches the requested architecture and is
statically linked, which catches a stale binary before it is baked into an image.

This is much faster than an emulated build, because the Go compiler runs natively.

`build.sh` never pushes anything, and its tag comes from `git describe`, so a
local image is development-only: it will not appear on ghcr.io and publishing a
release does not pick it up.

**Caveat when cross-building with `Dockerfile`:** running the amd64 Go compiler
under QEMU on an arm64 host is unreliable. `go mod download` fails
non-deterministically with GC faults (`sweep increased allocation count`, or a
`SIGSEGV` at a garbage address) using go1.26/go1.27 with qemu-user-static 10.0.x.
This is a defect in the emulation of the GC's concurrent marking, not in this
repository; `go version` succeeds and the same build passes on native amd64
hardware, which is why CI is unaffected. `build.sh` avoids the problem by not
emulating at all.

### Runtime requirement

Whichever image you build, the service exits immediately unless it can load
APNs credentials. It reads the first defined of `TOKEN_AUTH_KEY_FILENAME`,
`P12_BASE64`, then `P12_FILENAME` (defaulting to `toot-relay.p12`, which is not
committed). Without one, startup ends with:

```
level=fatal msg="Error loading certificate file: open toot-relay.p12: no such file or directory"
```

### Metrics

The service exports [Prometheus](https://prometheus.io/) metrics, but only if
you ask for them — the listener is off by default:

```
./webpush-apn-relay -metrics-port 19100
```

`METRICS_PORT=19100` is equivalent; the flag wins if both are set. Metrics are
served from a separate listener on `127.0.0.1` (override with
`-metrics-bind-address`) so the public port never exposes them. A metrics
listener that cannot bind is logged and does not stop the relay.

See [`observability/`](observability/) for metric definitions, a Prometheus +
Grafana stack, a dashboard, and suggested alert rules.

`DD_VERSION` is unrelated to metrics and is still read: it becomes the
`User-Agent` sent on unsubscribe `DELETE` requests. The `DD_GIT_*` variables the
Dockerfiles set are leftovers from the previous Datadog tracer and are no longer
read by anything.

A simple Dockerfile is included for running the service containerised. It has been
tested with the following hosting solutions:

- [Zeit Now](https://zeit.co/now) - There is also a configuration file (`now.json`)
  for using this service to host it. It requites adding the p12 file as a base 64
  encoded secret: `now secrets add p12-base64 "$(cat toot-relay.p12 | base64)`
- [Heroku](https://heroku.com/) - Add a configuration var named `P12_BASE64`
  containing the base 64 encoded p12 file.

## Status

This is a fairly minimal implementation of only the parts of RFC 8030 that are
required to relay push notifications from Mastodon. It only supports the simple
POST requests, and not async requests with receipts.

It does support the various headers, such as `TTL:`, `Urgency:`, and `Topic:`,
which are converted into expiration time, priority (`very-low` and `low` are 5,
`high` and `very-high` are 10), and collapse ID.

The relay replies `201 Created` as soon as a notification is queued, before
Apple has been contacted. That is RFC 8030's synchronous mode: `201` means
*accepted for delivery*, not *delivered*, and the APNs outcome is never
reported back to the sender. Genuine delivery confirmation would require the
asynchronous mode with `Receipt:` headers, which is not implemented here and
which Mastodon does not request.

Because Mastodon treats most `4xx` responses as a permanent failure and deletes
the user's Web Push subscription outright (every `4xx` except `408` and `429`),
this service answers `5xx` for anything that is its own problem, and reserves
`429` for the queue being full. A `4xx` from a relay is effectively an
unsubscribe command.

`Content-Encoding: aes128gcm` is the encoding web push senders use today (RFC 8291,
which restricts RFC 8188). Unlike the older `aesgcm`, it needs no headers relayed to
the client: the cryptographic salt and the server's public key travel in an 86-octet
header at the front of the body, which is why `p` carries the body whole. The relay
checks that header's shape - length, key length, uncompressed point marker, and a
record large enough to hold a tag - and answers `500` for a body that cannot be
parsed at all. That check catches truncation; it cannot validate crypto the relay
holds no key for. Any other encoding is answered with `501 Not Implemented` rather
than `415` - see the note above on why relays avoid `4xx`.

## Configuration

### Runtime Flags

- `-max-queue-size`: sets the size of the channel that buffers incoming notifications. Raising this value will consume more RAM (Go will pre-allocate the entire buffer to hold `N * size of message`). Defaults to `4096`.
- `-max-workers`: sets the number of parallel goroutines that will send notifications to Apple. Raising it will drain the queue more quickly at a small cost to increased resource usage. Each goroutine uses gets approx. 2kb of memory. This can safely scale into the thousands, if needed. See [this post](https://tpaschalis.github.io/goroutines-size/) for scaling considerations. Defaults to `8`.
- `-queue-drop-timeout`: how long an incoming notification waits for room in the queue before the relay answers `429 Too Many Requests`. A short wait absorbs ordinary bursts; `0` rejects immediately whenever the queue is full. Once the wait expires the notification is dropped rather than queued, and the `429` tells the sender to back off instead of leaving it to time out and retry. Defaults to `2s`.
- `-max-body-size`: reject request bodies larger than this many octets. APNs allows 4 KiB for an alert, so the default of `4096` refuses payloads Apple could never have accepted instead of answering `201` and letting a worker discover it later. `0` accepts any size and leaves APNs to answer `413`. An oversized body is answered `500`, not `413` - see the note on `4xx` above.

### Environment Variables

The service will read a few environment variables that let you make some adjustments.

For authentication to Apple, the relay will use the first defined variable from this list, in order:

- `TOKEN_AUTH_KEY_FILENAME`: For JWT token auth (using a non-expiring auth key to generate ephemerary JWT tokens)
- `P12_BASE64`
- `P12_FILENAME`

* `TOKEN_AUTH_KEY_FILENAME`: The name of the p8 file to use for JWT token auth.
  Needs to be requested from [developer.apple.com](https://developer.apple.com/account/resources/keys/list) (See [Apple's docs](https://developer.apple.com/documentation/usernotifications/establishing-a-token-based-connection-to-apns#Obtain-an-encryption-key-and-key-ID-from-Apple) for more details).
* `TOKEN_KEY_ID`: When using JWT token auth, Key ID from developer account (Certificates, Identifiers & Profiles -> Keys)
* `TOKEN_TEAM_ID`: When using JWT token auth, Team ID from developer account (View Account -> Membership)
* `P12_FILENAME`: The name of the p12 file to use for the push notification certificate.
  Defaults to `toot-relay.p12`.
* `P12_BASE64`: Alternative, you can include the base64-encoded data for the entire p12
  file in this variable. This is useful for hosting services that let you set
  environment variables for secret values.
* `P12_PASSWORD`: The password for the p12 file or base64 encoded data. Defaults to no
  password.
* `PORT`: The port to listen on. Defaults to `42069`.
* `CRT_FILENAME`: The crt file to use for TLS connections. Defaults to `toot-relay.crt`.
* `KEY_FILENAME`: The key file to use for TLS connections. Defaults to `toot-relay.key`.
* `CA_FILENAME`: A file containing PEM encoded certificates that will override the system
  root CAs when connecting to the Apple Notification Service API if set. Default: unset.
  "Override" is literal: the listed certificates become the *only* trust anchors,
  so an incomplete file breaks every APNs connection rather than falling back.
  The published images set this to `/cas.crt`, a copy of the single USERTrust RSA
  root that Apple's chain currently chains to — see the Dockerfiles.

## Receiving

The client needs to implement a user notification service extension that can
decrypt the payloads once they arrive. The original payload is transmitted in the
`p` property of the notification. The server's public key is transmitted in `k`,
the cryptographic salt in `s`, and any extra value supplied in the push endpoint
URL (the `extra` part as shown in the Usage section above) is passed in `x`.

Which of `k` and `s` appear depends on the content encoding the application
server chose, and the relay does not change it. With `aesgcm` both are present
and `p` holds the ciphertext alone. With `aes128gcm` — RFC 8291, what Mastodon
and GoToSocial send today — neither is present, because RFC 8188 puts the salt
and the server key in a 86-octet header at the front of the body, so `p` carries
them. A client that wants to work with both decides which path to take by
whether `s` and `k` are there, and `iOS/DecryptNotification.swift` does exactly
that.

### Example

An [excerpt of the Toot! code base](iOS/) for receiving and decrypting messages
is available. You can use this as a basis for your own implementation, or
read on for more technical details of how to do it yourself.

### Encoding

The fields `p`, `s` and `k` are transmitted using an extended variant of z85
encoding. This encoding is the same as [ZeroMQ's z85 encoding][z85], but extended
to support messages of any length, not just multiples of four bytes. It follows the
spec suggested in [this message][z85ext], storing the last 1-3 bytes as 2-4 characters,
representing an 8, 16 or 24-bit integer similarly to how normal z85 encoding represents
32-bit integers.

[z85]: https://rfc.zeromq.org/spec:32/Z85/
[z85ext]: http://grokbase.com/t/zeromq/zeromq-dev/144nd380c4/rfc-32-z85-requiring-frames-to-be-multiples-of-4-or-5-bytes

## Regarding HTTPS

Mastodon, and possibly others, force SSL when connecting to the push endpoint.
The service does have rudimentary support; put files named `toot-relay.crt` and
`toot-relay.key` in the same directory, and those will be loaded and used to
serve HTTPS instead of HTTP. (Also see the "Configuration" section.)

In practice, it may be easier to use ngnix or another service to handle HTTPS
traffic for you, and forward it to the service as plain HTTP.

## License

This code is released into the public domain with no warranties. If that is not
suitable, it is also available under the
[CC0 license](http://creativecommons.org/publicdomain/zero/1.0/).
