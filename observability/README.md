# Observability stack

Prometheus + Grafana for `webpush-apn-relay`. The relay itself exposes a
Prometheus endpoint; this directory contains everything else.

## Enabling the metrics endpoint

Metrics are **off by default**. Start the relay with:

```sh
./webpush-apn-relay -metrics-port 19100
```

or `METRICS_PORT=19100` in the environment (the flag wins if both are set).

The listener is separate from the public relay port and serves only `/metrics`.
It binds to `127.0.0.1` by default so the public port never exposes internal
telemetry. Override the address with `-metrics-bind-address` or
`METRICS_BIND_ADDRESS` (again, the flag wins). A failure to bind is logged and
does **not** take the relay down.

To scrape from a container, see [Topology](#topology) — loopback will not work.

## Metrics

All names are prefixed `relay_`. Counters are pre-initialised to `0` for every
label combination the relay can produce, so a panel reads zero rather than "no
data" on a healthy idle service. The one exception is
`relay_apns_response_status_total`, whose `status` label comes from Apple and
cannot be enumerated in advance — use `... or vector(0)` when you need a zero.

| Metric | Type | Labels | Meaning |
|---|---|---|---|
| `relay_relay_requests_total` | counter | `outcome` | Inbound requests by validation result: `accepted`, `error_body`, `error_crypto_key`, `error_salt`, `error_encoding`, `error_push_header`, `error_payload_too_large`, `error_queue_full`, `error_client_gone`. |
| `relay_pushes_total` | counter | `environment`, `result` | Pushes handed to APNs. `result` is `sent` (2xx), `rejected` (non-2xx), `error` (no HTTP response at all). |
| `relay_push_duration_seconds` | histogram | `environment` | Worker pickup to APNs response. **Excludes queue wait.** |
| `relay_apns_response_status_total` | counter | `environment`, `status` | Every HTTP status Apple returned, including 200. |
| `relay_unsubscribes_total` | counter | `result` | `DELETE` calls to `Unsubscribe-Url`, fired on APNs 410. `ok`, `error`, `build_request_error`. |
| `relay_registrations_total` | counter | `outcome` | `POST /register` and `POST /unregister` by result: `register_ok`, `register_bad_request`, `register_body_too_large`, `unregister_ok`. |
| `relay_status_requests_total` | counter | `outcome` | `GET /status` served. `ok`. A rising line means someone is reading the relay's configuration from outside, which is intended but worth noticing. |
| `relay_queue_depth` | gauge | — | Messages waiting for a worker. |
| `relay_queue_capacity` | gauge | — | `-max-queue-size`. |
| `relay_workers_active` | gauge | — | Workers currently blocked on an APNs round-trip. |

Plus the standard `go_*` and `process_*` collectors.

### Reading the two most important ones

**`result="error"` vs `result="rejected"` is the distinction that matters.**
`rejected` means Apple answered with a status code, and the common cause (410
Unregistered) is normal churn from users deleting their subscriptions. `error`
means no response arrived — DNS, TLS, timeout — and points at the relay or the
network. Alert on `error`; chart `rejected`.

**Queue saturation, not queue depth.** Alert on
`relay_queue_depth / relay_queue_capacity`. If you raise `-max-queue-size`, an
alert on raw depth silently changes meaning. Note that when the queue is full
the handler **blocks**; requests are not dropped, so a full queue shows up as
rising client latency before it shows up as an error.

## Topology

`prometheus.yml` in this directory is a complete config; `docker-compose.yml`
mounts it at `/etc/prometheus/prometheus.yml`. Its target is
`127.0.0.1:19100`, which is only correct if Prometheus can reach the host's
loopback.

On **rootless podman** (the setup this repo is developed on) a container gets
its own network namespace, so `127.0.0.1` inside Prometheus is Prometheus itself.
Pick one:

1. **Bind the relay publicly and scrape over the network.** Start the relay with
   `-metrics-bind-address 0.0.0.0` (or `METRICS_BIND_ADDRESS=0.0.0.0`) and set
   the target to the host's LAN address.
   Simplest, but `/metrics` is then reachable from the network — put it behind a
   firewall or a reverse proxy with auth if that is not acceptable.
2. **Scrape the host from the container.** Keep the relay on loopback and use
   `host.containers.internal:19100` (podman) or `host.docker.internal:19100`
   (docker). This still will not reach a plain loopback bind from a bridge
   network; it works with `--network=host`, or with `pasta`/`slirp4netns`
   setups that route the special hostname to the host loopback. Test with
   `podman run --rm docker.io/curlimages/curl host.containers.internal:19100/metrics`
   before assuming it works.
3. **Run Prometheus on the host**, not in a container. Then `127.0.0.1:19100` is
   correct as written and nothing needs changing.

Option 3 is the least surprising on a single Raspberry Pi.

## Running the stack

```sh
podman-compose -f observability/docker-compose.yml up -d
```

Grafana on <http://localhost:3000> (`admin`/`admin`, forced change on first
login; override with `GRAFANA_USER` / `GRAFANA_PASSWORD` in an `.env` file).
Prometheus on <http://localhost:9090>.

The datasource and dashboard are provisioned from files, so they appear on first
start without touching the UI. Dashboard changes made in the UI are not written
back to the file and will be overwritten on the next provision interval — edit
`gen_dashboard.py` instead.

## Dashboard

`grafana/dashboards/webpush-apn-relay.json` is **generated**:

```sh
python3 observability/gen_dashboard.py
```

Edit the generator, not the JSON. It keeps PromQL consistent across panels and
lays out the grid automatically (rows advance the y cursor, so adding a panel
does not require hand-moving everything below it).

The generator emits a validation-friendly structure; to check that every metric
the dashboard references is actually exported, scrape a running relay and diff
the names:

```sh
curl -s 127.0.0.1:19100/metrics | grep -oE '^relay_[a-z_]+' | sort -u
```

## Suggested alerts

These are the four worth paging on; the rest of the dashboard is for context.

```yaml
groups:
  - name: webpush-apn-relay
    rules:
      - alert: RelayQueueSaturating
        expr: relay_queue_depth / clamp_min(relay_queue_capacity, 1) > 0.8
        for: 5m
        labels: { severity: warning }
        annotations:
          summary: "Relay queue above 80% for 5m"
          description: >-
            Workers are not keeping up. The handler blocks when the queue is
            full, so origin servers are seeing latency, not errors. Raise
            -max-workers first; -max-queue-size only buys time and costs RAM.

      - alert: RelayTransportErrors
        # No HTTP response from Apple at all: DNS, TLS, or timeout.
        expr: sum(rate(relay_pushes_total{result="error"}[5m])) > 0
        for: 5m
        labels: { severity: critical }
        annotations:
          summary: "APNs transport failures"
          description: >-
            Pushes are failing without any response from APNs. Check DNS,
            egress, and the certificate expiry. Distinct from `rejected`,
            which is mostly expected 410 churn.

      - alert: RelayPushSuccessLow
        expr: |
          sum(rate(relay_pushes_total{result="sent"}[10m]))
          /
          clamp_min(
            sum(rate(relay_pushes_total{result="sent"}[10m]))
            + sum(rate(relay_pushes_total{result="rejected"}[10m])), 1) < 0.9
        for: 15m
        labels: { severity: warning }
        annotations:
          summary: "Push success rate below 90%"
          description: >-
            Check relay_apns_response_status_total for the dominant code.
            A burst of 403 usually means a certificate or provider-token
            problem, not bad device tokens.

      - alert: RelayUnsubscribesFailing
        # 410s are happening but the DELETE is not succeeding, so the origin
        # keeps pushing to dead tokens forever.
        expr: |
          sum(rate(relay_unsubscribes_total{result="ok"}[30m])) == 0
          and sum(rate(relay_apns_response_status_total{status="410"}[30m])) > 0
        for: 30m
        labels: { severity: warning }
        annotations:
          summary: "410s seen but no successful unsubscribes"
          description: >-
            Dead subscriptions are not being cleaned up. Check the
            Unsubscribe-Url is reachable from the relay.
```

`RelayPushSuccessLow` uses `clamp_min` so a quiet relay with zero traffic does
not divide by zero and fire spuriously. `RelayUnsubscribesFailing` reads the
410 counter directly rather than inferring it from `rejected`, because
`rejected` also covers 400 and 403.

## Certificate expiry

Not exposed as a metric — the relay does not read its own expiry into a gauge.
Check out of band:

```sh
openssl pkcs12 -in toot-relay.p12 -nokeys -clcerts -passin pass: \
  | openssl x509 -noout -enddate
```

Apple push certificates expire, and the failure mode is a wall of 403s, which
`RelayPushSuccessLow` will catch a few minutes after it starts hurting users.
