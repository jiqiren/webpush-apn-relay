package main

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

// metricsRegistry is a dedicated registry rather than the prometheus default
// one, so the exported set is exactly what is declared here plus the Go and
// process collectors. It also keeps registration safe if a second registry is
// ever needed for tests.
var metricsRegistry = prometheus.NewRegistry()

var (
	relayRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "relay_relay_requests_total",
			Help: "Web push requests received by the relay, by outcome.",
		},
		[]string{"outcome"},
	)

	pushesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "relay_pushes_total",
			Help: "APNs push attempts by environment and result.",
		},
		[]string{"environment", "result"},
	)

	pushDurationSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name: "relay_push_duration_seconds",
			Help: "Time from worker pickup to APNs response, in seconds.",
			// prometheus.DefBuckets tops out at 10s; APNs hiccups and
			// TLS renegotiation land above that, so extend the tail.
			Buckets: append(append([]float64{}, prometheus.DefBuckets...), 15, 30, 60),
		},
		[]string{"environment"},
	)

	apnsResponseStatusTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "relay_apns_response_status_total",
			Help: "HTTP status codes returned by APNs, including 200 successes.",
		},
		[]string{"environment", "status"},
	)

	unsubscribesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "relay_unsubscribes_total",
			Help: "Unsubscribe DELETEs issued against Unsubscribe-Url, by result.",
		},
		[]string{"result"},
	)

	// registrationsTotal counts /register and /unregister separately from
	// relay_relay_requests_total, because their outcomes are not comparable: a
	// "bad request" on the registration path is a client bug that costs a user
	// their notifications, while on the push path it is a payload problem. Merging
	// them would make either one unreadable.
	registrationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "relay_registrations_total",
			Help: "Registration requests received, by outcome.",
		},
		[]string{"outcome"},
	)

	// statusRequestsTotal counts GET /status. It is a counter rather than a gauge
	// because the value it protects against is surprise traffic to an endpoint that
	// discloses configuration: a rising line is the signal, and a gauge would only
	// show the last scrape.
	statusRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "relay_status_requests_total",
			Help: "GET /status requests served, by outcome.",
		},
		[]string{"outcome"},
	)

	// queueDepth samples the shared message channel. Defined here but
	// registered by main once messageChan exists, since the closure reads it.
	queueDepth = prometheus.NewGaugeFunc(
		prometheus.GaugeOpts{
			Name: "relay_queue_depth",
			Help: "Messages waiting in the queue. Sustained growth means workers cannot keep up.",
		},
		func() float64 {
			if messageChan == nil {
				return 0
			}
			return float64(len(messageChan))
		},
	)

	queueCapacity = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "relay_queue_capacity",
			Help: "Configured capacity of the message queue (-max-queue-size).",
		},
	)

	workersActive = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "relay_workers_active",
			Help: "Workers currently blocked on an APNs round-trip.",
		},
	)
)

func init() {
	metricsRegistry.MustRegister(prometheus.NewGoCollector())
	metricsRegistry.MustRegister(prometheus.NewProcessCollector(prometheus.ProcessCollectorOpts{}))

	metricsRegistry.MustRegister(relayRequestsTotal)
	metricsRegistry.MustRegister(pushesTotal)
	metricsRegistry.MustRegister(pushDurationSeconds)
	metricsRegistry.MustRegister(apnsResponseStatusTotal)
	metricsRegistry.MustRegister(unsubscribesTotal)
	metricsRegistry.MustRegister(registrationsTotal)
	metricsRegistry.MustRegister(statusRequestsTotal)
	metricsRegistry.MustRegister(queueDepth)
	metricsRegistry.MustRegister(queueCapacity)
	metricsRegistry.MustRegister(workersActive)

	initializeLabelSeries()
}

// initializeLabelSeries creates every label combination that is not derived
// from an unbounded input, at value 0.
//
// Without this, a CounterVec emits nothing until a label value is first used,
// so a Grafana panel cannot distinguish "zero events" from "no such series" -
// and a healthy relay would show empty panels for exactly the things an
// operator most wants to confirm are zero (transport errors, unsubscribes).
//
// relay_apns_response_status_total is deliberately excluded: its "status"
// label comes from APNs, and pre-seeding it would require inventing status
// codes. Queries that need a zero for it should use `... or vector(0)`.
func initializeLabelSeries() {
	for _, outcome := range []string{
		"accepted", "error_body", "error_crypto_key", "error_salt", "error_encoding",
		"error_push_header", "error_queue_full", "error_client_gone",
		"error_payload_too_large",
	} {
		relayRequestsTotal.WithLabelValues(outcome).Add(0)
	}

	for _, environment := range []string{"production", "development"} {
		for _, result := range []string{"sent", "error", "rejected"} {
			pushesTotal.WithLabelValues(environment, result).Add(0)
		}
		// Guarantees each environment has a histogram series before the first
		// push, so histogram_quantile() returns 0 rather than empty.
		pushDurationSeconds.WithLabelValues(environment)
	}

	for _, result := range []string{"ok", "error", "build_request_error"} {
		unsubscribesTotal.WithLabelValues(result).Add(0)
	}

	for _, outcome := range []string{
		"register_ok", "register_bad_request", "register_body_too_large", "unregister_ok",
	} {
		registrationsTotal.WithLabelValues(outcome).Add(0)
	}

	for _, outcome := range []string{"ok"} {
		statusRequestsTotal.WithLabelValues(outcome).Add(0)
	}
}

// recordRelayRequest counts an inbound request by outcome. Kept as a function
// so every exit point in the handler is a single, greppable call.
func recordRelayRequest(outcome string) {
	relayRequestsTotal.WithLabelValues(outcome).Inc()
}

func environmentName(isProduction bool) string {
	if isProduction {
		return "production"
	}
	return "development"
}

func recordPush(isProduction bool, result string) {
	pushesTotal.WithLabelValues(environmentName(isProduction), result).Inc()
}

func recordApnsStatus(isProduction bool, statusCode int) {
	apnsResponseStatusTotal.WithLabelValues(environmentName(isProduction), strconv.Itoa(statusCode)).Inc()
}

func recordUnsubscribe(result string) {
	unsubscribesTotal.WithLabelValues(result).Inc()
}

func recordRegistration(outcome string) {
	registrationsTotal.WithLabelValues(outcome).Inc()
}

func recordStatusRequest(outcome string) {
	statusRequestsTotal.WithLabelValues(outcome).Inc()
}
