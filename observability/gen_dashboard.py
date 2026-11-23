#!/usr/bin/env python3
"""Generate observability/grafana/dashboards/webpush-apn-relay.json.

Regenerate after changing metric names:
    python3 observability/gen_dashboard.py
Kept as a generator rather than checked-in-by-hand JSON so the PromQL stays
consistent across panels and the gridPos math is not done by eye.
"""
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "grafana", "dashboards", "webpush-apn-relay.json")

# --- PromQL -----------------------------------------------------------------
# All rates over $__rate_interval so panels behave at every zoom level.
Q_ACCEPTED = 'sum(rate(relay_relay_requests_total{outcome="accepted"}[$__rate_interval]))'
Q_REJECTED = "sum(rate(relay_pushes_total{result=\"rejected\"}[$__rate_interval]))"
Q_ERRORS = 'sum(rate(relay_pushes_total{result="error"}[$__rate_interval]))'
Q_SENT = 'sum(rate(relay_pushes_total{result="sent"}[$__rate_interval]))'

# 410 Unregistered churn. `or vector(0)` keeps the stat at zero instead of
# "no data" when the label has never been seen (status is not pre-seeded).
Q_410 = 'sum(rate(relay_apns_response_status_total{status="410"}[$__rate_interval])) or vector(0)'

# Success ratio of pushes that actually reached APNs and got a verdict.
# Excludes result="error" (transport failure, no HTTP status) because those
# have no status code to divide by; they are charted separately.
Q_SUCCESS_RATIO = (
    'sum(rate(relay_pushes_total{result="sent"}[$__rate_interval])) / '
    '(sum(rate(relay_pushes_total{result="sent"}[$__rate_interval])) or vector(0)) + '
    '(sum(rate(relay_pushes_total{result="rejected"}[$__rate_interval])) or vector(0))'
)

P95 = "histogram_quantile(0.95, sum by (le, environment) (rate(relay_push_duration_seconds_bucket[$__rate_interval])))"
P50 = "histogram_quantile(0.50, sum by (le, environment) (rate(relay_push_duration_seconds_bucket[$__rate_interval])))"
P99 = "histogram_quantile(0.99, sum by (le, environment) (rate(relay_push_duration_seconds_bucket[$__rate_interval])))"
HEATMAP = "sum by (le) (rate(relay_push_duration_seconds_bucket[$__rate_interval]))"

STATUS = "sum by (status) (rate(relay_apns_response_status_total[$__rate_interval]))"
UNSUB = "sum by (result) (rate(relay_unsubscribes_total[$__rate_interval]))"

# Saturation: depth as a fraction of capacity. Alerts on this, not raw depth,
# so raising -max-queue-size does not silently change what "full" means.
SATURATION = "relay_queue_depth / clamp_min(relay_queue_capacity, 1)"


def stat(pid, title, x, y, w, h, expr, unit, thresholds, desc, reduce="lastNotNull"):
    return {
        "id": pid, "type": "stat", "title": title,
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "datasource": {"type": "prometheus", "uid": "${DS_PROMETHEUS}"},
        "description": desc,
        "fieldConfig": {"defaults": {
            "unit": unit, "color": {"mode": "thresholds"},
            "thresholds": {"mode": "absolute",
                           "steps": [{"color": "green", "value": None}] + thresholds},
            "decimals": 1 if unit == "percentunit" else 0,
        }, "overrides": []},
        "options": {"colorMode": "background", "graphMode": "area",
                    "reduceOptions": {"calcs": [reduce], "fields": "", "values": False},
                    "textMode": "auto"},
        "targets": [{"expr": expr, "refId": "A", "instant": True}],
    }


def ts(pid, title, x, y, w, h, targets, unit, desc, legend="{{label}}", stack=False, fill=1):
    return {
        "id": pid, "type": "timeseries", "title": title,
        "gridPos": {"h": h, "w": w, "x": x, "y": y},
        "datasource": {"type": "prometheus", "uid": "${DS_PROMETHEUS}"},
        "description": desc,
        "fieldConfig": {"defaults": {
            "unit": unit, "color": {"mode": "palette-classic"},
            "custom": {"drawStyle": "line", "lineWidth": 1, "fillOpacity": fill,
                       "showPoints": "never", "spanNulls": True,
                       "stacking": {"group": "A", "mode": "none"},
                       "gradientMode": "opacity"},
        }, "overrides": []},
        "options": {"legend": {"displayMode": "table", "placement": "bottom",
                               "showLegend": True, "calcs": ["lastNotNull", "max"]},
                    "tooltip": {"mode": "multi", "sort": "desc"}},
        "targets": [{"expr": e, "refId": chr(65 + i), "legendFormat": lf}
                    for i, (e, lf) in enumerate(targets)],
    }


panels = [
    # --- Row: traffic -------------------------------------------------------
    {"id": 100, "type": "row", "title": "Traffic", "collapsed": False,
     "gridPos": {"h": 1, "w": 24, "x": 0, "y": 0}, "panels": []},

    stat(1, "Accepted /sec", 0, 1, 4, 5, Q_ACCEPTED, "reqps", [],
         "Requests that passed validation and were queued. The relay replies 201 "
         "before the push is attempted, so this measures acceptance, not delivery."),
    stat(2, "Delivered /sec", 4, 1, 4, 5, Q_SENT, "reqps", [],
         "Pushes APNs accepted (2xx)."),
    stat(3, "Rejected /sec", 8, 1, 4, 5, Q_REJECTED, "reqps",
         [{"color": "yellow", "value": 0.01}, {"color": "red", "value": 0.1}],
         "APNs returned a non-2xx status. Includes 410 Unregistered, which is "
         "expected churn when devices unsubscribe."),
    stat(4, "Transport errors /sec", 12, 1, 4, 5, Q_ERRORS, "reqps",
         [{"color": "yellow", "value": 0.01}, {"color": "red", "value": 0.1}],
         "No HTTP response at all: DNS, TLS, or timeout. This is the one that means "
         "the relay itself is broken rather than a subscription being stale."),
    stat(5, "Push success rate", 16, 1, 4, 5, Q_SUCCESS_RATIO, "percentunit",
         [{"color": "red", "value": None}, {"color": "yellow", "value": 0.95},
          {"color": "green", "value": 0.99}],
         "sent / (sent + rejected). Excludes transport errors, which have no status."),
    stat(6, "Queue saturation", 20, 1, 4, 5, SATURATION, "percentunit",
         [{"color": "green", "value": None}, {"color": "yellow", "value": 0.5},
          {"color": "red", "value": 0.9}],
         "relay_queue_depth / relay_queue_capacity. Sustained growth means workers "
         "cannot keep up; at 100% new requests block the handler, they are not dropped."),

    stat(17, "410 Unregistered /sec", 0, 6, 4, 4, Q_410, "reqps",
         [{"color": "green", "value": None}, {"color": "yellow", "value": 0.05}],
         "APNs says the device token is gone. Normal churn, but it is what drives "
         "the unsubscribe path below - if this is high and unsubscribes ok is low, "
         "dead subscriptions are not being cleaned up."),

    stat(18, "Transport errors (total)", 4, 6, 4, 4,
         'sum(increase(relay_pushes_total{result="error"}[24h]))', "short",
         [{"color": "green", "value": None}, {"color": "yellow", "value": 1},
          {"color": "red", "value": 100}],
         "Count of pushes with no HTTP response at all in the last 24h. Kept as a "
         "24h total because transport errors are rare and a per-second rate makes a "
         "real outage look invisible."),

    # --- Row: latency -------------------------------------------------------
    {"id": 101, "type": "row", "title": "APNs latency", "collapsed": False,
     "gridPos": {"h": 1, "w": 24, "x": 0, "y": 6}, "panels": []},

    ts(7, "Push duration percentiles", 0, 7, 12, 8,
       [(P50, "p50 {{environment}}"), (P95, "p95 {{environment}}"),
        (P99, "p99 {{environment}}")], "s",
       "Worker pickup to APNs response. Excludes queue wait by design - watch "
       "queue saturation for that. A spike here with flat saturation means Apple "
       "is slow, not the relay."),
    ts(8, "Duration distribution", 12, 7, 12, 8,
       [(HEATMAP, "{{le}}")], "s",
       "Histogram buckets as a heatmap. Reveals bimodality that percentiles hide, "
       "e.g. a fast path plus a TLS-renegotiation path.", stack=False),

    # --- Row: outcomes ------------------------------------------------------
    {"id": 102, "type": "row", "title": "Outcomes", "collapsed": False,
     "gridPos": {"h": 1, "w": 24, "x": 0, "y": 15}, "panels": []},

    ts(9, "APNs response status rate", 0, 16, 12, 8,
       [(STATUS, "{{status}}")], "reqps",
       "Every HTTP status APNs returned. 200 = delivered. 400 BadDeviceToken, "
       "403 = certificate problem, 410 Unregistered = dead token, 429 = throttled, "
       "503 = Apple is down.", stack=True, fill=30),
    ts(10, "Inbound request outcomes", 12, 16, 12, 8,
       [("sum by (outcome) (rate(relay_relay_requests_total[$__rate_interval]))",
         "{{outcome}}")], "reqps",
       "accepted vs the validation failures: error_body, error_crypto_key, "
       "error_salt, error_encoding, error_push_header, error_payload_too_large. "
       "A rising error_encoding means a client started sending an unsupported "
       "Content-Encoding; error_payload_too_large means the origin server is "
       "sending bodies APNs cannot carry.", stack=True, fill=30),
    ts(11, "Unsubscribe DELETEs", 0, 24, 12, 8,
       [(UNSUB, "{{result}}")], "reqps",
       "Fired on APNs 410. If ok stays at 0 while rejected rate is high, the relay "
       "is not cleaning up dead subscriptions and the origin server will keep "
       "pushing to dead tokens forever.", stack=True, fill=30),
    ts(12, "Push rate by environment", 12, 24, 12, 8,
       [('sum by (environment, result) (rate(relay_pushes_total[$__rate_interval]))',
         "{{environment}} / {{result}}")], "reqps",
       "Split of development (sandbox) vs production APNs traffic.",
       stack=True, fill=30),

    # --- Row: saturation ----------------------------------------------------
    {"id": 103, "type": "row", "title": "Saturation", "collapsed": False,
     "gridPos": {"h": 1, "w": 24, "x": 0, "y": 32}, "panels": []},

    ts(13, "Queue depth vs capacity", 0, 33, 12, 8,
       [("relay_queue_depth", "depth"), ("relay_queue_capacity", "capacity")], "short",
       "Messages waiting for a worker. Capacity is -max-queue-size; note that each "
       "slot holds a pointer to a payload, so raising it costs real RAM.",
       legend="", stack=False),
    ts(14, "Workers active", 12, 33, 12, 8,
       [("relay_workers_active", "active")], "short",
       "Workers blocked on an APNs round-trip. Pinned at -max-workers for long "
       "stretches means the pool is the bottleneck: raise -max-workers. There is "
       "no metric for the configured maximum; compare against the flag value.",
       legend="", stack=False),
    ts(15, "Process memory / goroutines", 0, 41, 12, 8,
       [("process_resident_memory_bytes", "RSS"),
        ("go_goroutines", "goroutines")], "bytes",
       "Provided by the Go and process collectors. Goroutine count climbing without "
       "bound suggests handlers parked on a full channel.", legend="", stack=False),
    ts(16, "Request handling rate (all outcomes)", 12, 41, 12, 8,
       [("sum(rate(relay_relay_requests_total[$__rate_interval]))", "all")], "reqps",
       "Total inbound rate including rejects; compare against accepted to see "
       "the rejection fraction over time.", legend="", stack=False),
]

# --- auto-layout -----------------------------------------------------------
# Rows flow top to bottom; panels inside a row fill a 24-column grid in the
# order they are declared. Adding a panel therefore never requires hand-fixing
# the y coordinates of everything below it.
def auto_layout(panels):
    y = 0
    col = 0
    row_height = 0
    for p in panels:
        if p["type"] == "row":
            # A row header always begins a fresh band: advance past whatever the
            # previous band used, otherwise it lands on top of those panels.
            if row_height:
                y += row_height
            col = 0
            row_height = 0
            p["gridPos"] = {"h": 1, "w": 24, "x": 0, "y": y}
            y += 1
            continue
        w = p["gridPos"]["w"]
        h = p["gridPos"]["h"]
        if col + w > 24:
            col = 0
            y += row_height
            row_height = 0
        p["gridPos"] = {"h": h, "w": w, "x": col, "y": y}
        col += w
        row_height = max(row_height, h)
    return panels


panels = auto_layout(panels)

dashboard = {
    "uid": "webpush-apn-relay",
    "title": "Web Push APNs Relay",
    "tags": ["webpush-apn-relay", "generated"],
    "timezone": "browser",
    "schemaVersion": 39,
    "version": 1,
    "editable": True,
    "refresh": "30s",
    "time": {"from": "now-6h", "to": "now"},
    "fiscalYearStartMonth": 0,
    "liveNow": False,
    "style": "dark",
    "annotations": {"list": [{
        "builtIn": 1, "datasource": {"type": "grafana", "uid": "-- Grafana --"},
        "enable": True, "hide": True, "iconColor": "rgba(0, 211, 255, 1)",
        "name": "Annotations & Alerts", "type": "dashboard",
    }]},
    "templating": {"list": [{
        "name": "DS_PROMETHEUS", "label": "Datasource", "type": "datasource",
        "query": "prometheus", "current": {}, "hide": 0,
    }]},
    "panels": panels,
    "links": [],
}

# Alert rules are expressed in the dashboard only as a comment-free companion
# file; Grafana OSS provisioning of alerting requires a separate YAML, which
# observability/README.md documents.
os.makedirs(os.path.dirname(OUT), exist_ok=True)
with open(OUT, "w") as fh:
    json.dump(dashboard, fh, indent=2)
    fh.write("\n")
print(f"wrote {OUT} ({len(panels)} top-level panels)")
