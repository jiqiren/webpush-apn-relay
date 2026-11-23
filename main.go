package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
	"uuid"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/payload"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/http2"
)

var (
	developmentClient *apns2.Client
	productionClient  *apns2.Client
	topic             string
	messageChan       chan *Message
	maxQueueSize      int
	maxWorkers        int
	queueDropTimeout  time.Duration
	maxBodySize       int64
	metricsPort       int
	metricsBind       string

	// apnsAuthMode records which branch of the credential chain actually built the
	// clients. It has exactly two values, "token" and "p12": every other path in
	// loadAPNsCredentials is fatal, so a process that is running always has one.
	// The zero value is "" on purpose - see loadAPNsCredentials.
	apnsAuthMode string

	// apnsKeyFingerprint is a short hash of the public half of whichever credential
	// loaded, for "is this the key I think it is?". See apnsCredentials.
	apnsKeyFingerprint string

	// caFilenameResolved is the CA_FILENAME value in effect, for /status. It is
	// the evaluated string, not whether it loaded: an unset CA_FILENAME yields ""
	// locally and "/cas.crt" in the image, and the difference is worth seeing.
	caFilenameResolved string

	startedAt = time.Now()
)

// maxBodySize bounds the request body this relay will accept, set by
// -max-body-size.
//
// APNs allows 4 KiB for an alert, and RFC 8030 section 7.2 requires a push
// service to accept at least 4096 octets - the same figure. Without a cap, an
// oversized payload is accepted with 201, queued, and only then rejected by
// Apple with 413 PayloadTooLarge, after a worker has paid for a round trip to
// discover what was knowable on arrival. The sender has already been told the
// notification was accepted, so there is no way to report that back.
//
// The default is generous rather than tight. GoToSocial - the sender Seloi
// receives from - sets recordSize to 2048 in internal/webpush/sender.go with
// APNs' 4 kB limit explicitly in mind, so 4096 leaves real traffic untouched
// and only rejects payloads Apple could never have taken.
//
// 4096 is a minimum in RFC 8030, not a maximum, so this is a limit of ours and
// not a protocol rule: set -max-body-size to 0 to accept any size and let APNs
// answer 413 as before.
const defaultMaxBodySize = 4096

var envVersion = os.Getenv("DD_VERSION")

func userAgent() string {
	var version = envVersion

	if version == "" {
		version = "dev"
	}

	return "mastodon-webpush-apn-relay/" + version + " (https://github.com/mastodon/webpush-apn-relay)"
}

func main() {
	httpClient := http.DefaultClient

	mux := http.NewServeMux()

	flag.IntVar(&maxQueueSize, "max-queue-size", 4096, "Maximum number of messages to queue")
	flag.IntVar(&maxWorkers, "max-workers", 8, "Maximum number of workers")
	flag.DurationVar(&queueDropTimeout, "queue-drop-timeout", 2*time.Second, "How long to wait for queue space before answering 429 (0 rejects immediately when full)")
	flag.Int64Var(&maxBodySize, "max-body-size", defaultMaxBodySize, "Reject bodies larger than this many octets (0 accepts any size and lets APNs answer 413)")
	flag.IntVar(&metricsPort, "metrics-port", 0, "Port to serve Prometheus /metrics on (0 disables)")
	flag.StringVar(&metricsBind, "metrics-bind-address", "127.0.0.1", "Address to bind the metrics listener to (use 0.0.0.0 to allow remote scrapes)")
	flag.Parse()

	// METRICS_PORT is honoured only when the flag was left at its default, so
	// an explicit command-line flag always wins over the container environment.
	if metricsPort == 0 {
		if raw := env("METRICS_PORT", ""); raw != "" {
			if parsed, err := strconv.Atoi(raw); err == nil {
				metricsPort = parsed
			} else {
				log.Warn(fmt.Sprintf("Ignoring invalid METRICS_PORT %q: %s", raw, err))
			}
		}
	}

	topic = env("TOPIC", "cx.c3.toot")
	p12file := env("P12_FILENAME", "toot-relay.p12")
	p12base64 := env("P12_BASE64", "")
	p12password := env("P12_PASSWORD", "")

	tokenSignKeyFile := env("TOKEN_AUTH_KEY_FILENAME", "")
	tokenKeyId := env("TOKEN_KEY_ID", "")
	tokenTeamId := env("TOKEN_TEAM_ID", "")

	port := env("PORT", "42069")
	tlsCrtFile := env("CRT_FILENAME", "toot-relay.crt")
	tlsKeyFile := env("KEY_FILENAME", "toot-relay.key")
	// CA_FILENAME can be set to a file that contains PEM encoded certificates that will be
	// used as the sole root CAs when connecting to the Apple Notification Service API.
	// If unset, the system-wide certificate store will be used.
	caFile := env("CA_FILENAME", "")
	caFilenameResolved = caFile
	var rootCAs *x509.CertPool

	if caPEM, err := os.ReadFile(caFile); err == nil {
		rootCAs = x509.NewCertPool()
		if ok := rootCAs.AppendCertsFromPEM(caPEM); !ok {
			log.Fatal(fmt.Sprintf("CA file %s specified but no CA certificates could be loaded\n", caFile))
		}
	}

	// The credential chain always ends in a load attempt: p12file has a default, so
	// there is no configuration in which the relay starts without trying one.
	credentials, err := loadAPNsCredentials(apnsCredentialConfig{
		tokenKeyFile: tokenSignKeyFile,
		tokenKeyID:   tokenKeyId,
		tokenTeamID:  tokenTeamId,
		p12File:      p12file,
		p12Base64:    p12base64,
		p12Password:  p12password,
	})
	if err != nil {
		// Fatal, and it always was: there is no running process that failed to load a
		// credential, so the log line is the diagnostic for that case, not /status.
		log.Fatal(err)
	}

	developmentClient = credentials.development
	productionClient = credentials.production
	apnsAuthMode = credentials.mode
	apnsKeyFingerprint = credentials.keyFingerprint

	// We only want to add root CAs when we are using a client CA.
	// apns2 builds the token-auth transport without a TLSClientConfig (only the
	// certificate-auth path sets one), so it has to be created before RootCAs
	// can be assigned. Otherwise CA_FILENAME is silently ignored when
	// TOKEN_AUTH_KEY_FILENAME is in use.
	if rootCAs != nil {
		for _, c := range []*apns2.Client{developmentClient, productionClient} {
			http2Transport, ok := c.HTTPClient.Transport.(*http2.Transport)
			if !ok {
				log.Fatalf("unexpected APNs transport type %T; cannot apply CA_FILENAME", c.HTTPClient.Transport)
			}
			if http2Transport.TLSClientConfig == nil {
				http2Transport.TLSClientConfig = &tls.Config{}
			}
			http2Transport.TLSClientConfig.RootCAs = rootCAs
		}
	}

	mux.HandleFunc("POST /relay-to/{environment}/{token}/{extra...}", handleApnNotification)
	mux.HandleFunc("GET /relay-to/_health", handleHealthCheck)

	// Registration endpoints for clients that cannot compose a relay URL. They sit
	// on the public port because the phone talks to it directly; the push route
	// above is a catch-all so these must be registered as their own patterns, and
	// Go's mux prefers a literal segment over a wildcard anyway.
	mux.HandleFunc("POST /register", handleRegister)
	mux.HandleFunc("POST /unregister", handleUnregister)

	// Operational introspection, on the public port so it is reachable through the
	// reverse proxy without an SSH session. /status is a literal segment and the
	// push route lives entirely under /relay-to/, so the two trees cannot collide.
	mux.HandleFunc("GET /status", handleStatus)

	messageChan = make(chan *Message, maxQueueSize)
	queueCapacity.Set(float64(maxQueueSize))
	for i := 1; i <= maxWorkers; i++ {
		go apnNotificationsWorker(i, httpClient)
	}

	// Metrics are served on a separate listener so the public relay port does
	// not expose internal telemetry by default. Loopback binding by default
	// means a sidecar or host process scrapes it without opening the network.
	if metricsPort != 0 {
		go serveMetrics(metricsBind, metricsPort)
	}

	if _, err := os.Stat(tlsCrtFile); !os.IsNotExist(err) {
		log.Fatal(http.ListenAndServeTLS(":"+port, tlsCrtFile, tlsKeyFile, mux))
	} else {
		log.Fatal(http.ListenAndServe(":"+port, mux))
	}
}

// serveMetrics exposes the Prometheus registry. A failure here is logged but
// never fatal: telemetry must not be able to take the relay down.
func serveMetrics(bind string, port int) {
	metricsMux := http.NewServeMux()
	metricsMux.Handle("GET /metrics", promhttp.HandlerFor(metricsRegistry, promhttp.HandlerOpts{}))

	addr := bind + ":" + strconv.Itoa(port)
	log.Info(fmt.Sprintf("serving Prometheus metrics on http://%s/metrics", addr))
	if err := http.ListenAndServe(addr, metricsMux); err != nil {
		log.Error(fmt.Sprintf("metrics server stopped: %s", err))
	}
}

func handleHealthCheck(writer http.ResponseWriter, request *http.Request) {
	requestLog := log.WithContext(request.Context())

	writer.WriteHeader(200)
	fmt.Fprint(writer, "OK")
	requestLog.Info("Health check OK")
}

// handleStatus reports the configuration that cannot be inferred from outside and
// whose failure is otherwise invisible.
//
// The reason it exists: a wrong TOPIC makes Apple reject every push with BadTopic
// while the relay still answers 201 to the sender, because the response is written
// before the push is attempted. Nothing about the running configuration - topic,
// which credential mode won, which build this is - was observable without
// inspecting the container.
//
// What it does NOT do is diagnose a credential that failed to load. Every failure in
// loadAPNsCredentials is fatal, so such a process never serves this endpoint: it
// exits, and under a restart policy it crash-loops with no health check to query.
// The log line is the diagnostic for that case. /status can only report that a live
// process came up with working credentials and say which mode it is using.
//
// Nothing here is secret. The response carries no Key ID and no Team ID: this
// endpoint sits on the same public listener as the relay, so everything in it must
// be assumed to be in a public paste, and a Key ID names the exact key to attack
// without helping anyone debug. keyFingerprint is a short hash of the public half of
// the loaded credential, which is reproducible by whoever holds the key and useless
// to anyone who does not. The private material - p8 contents, p12 bytes, password -
// is unreachable from this handler: it is local to loadAPNsCredentials and main().
func handleStatus(writer http.ResponseWriter, request *http.Request) {
	status := struct {
		Topic          string `json:"topic"`
		AuthMode       string `json:"authMode"`
		KeyFingerprint string `json:"keyFingerprint"`
		CAFilename     string `json:"caFilename"`
		Version        string `json:"version"`
		UptimeSeconds  int64  `json:"uptimeSeconds"`
	}{
		Topic:          topic,
		AuthMode:       apnsAuthMode,
		KeyFingerprint: apnsKeyFingerprint,
		CAFilename:     caFilenameResolved,
		Version:        envVersion,
		UptimeSeconds:  int64(time.Since(startedAt).Seconds()),
	}

	// no-store because this is a live view of a running process, and a proxy cache
	// holding a stale authMode is exactly the confusion this endpoint exists to end.
	writer.Header().Set("Content-Type", "application/json")
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusOK)

	if err := json.NewEncoder(writer).Encode(status); err != nil {
		log.WithError(err).Error("failed to write status response")
	}

	recordStatusRequest("ok")
}

func handleApnNotification(writer http.ResponseWriter, request *http.Request) {
	ctx := request.Context()
	requestID := request.Header.Get("X-Request-ID")

	if requestID == "" {
		requestID = uuid.New().String()
	}

	requestLog := log.WithFields(log.Fields{"request-id": requestID}).WithContext(ctx)

	isProduction := request.PathValue("environment") == "production"

	notification := &apns2.Notification{}
	notification.DeviceToken = request.PathValue("token")

	// Cap the body before reading it. MaxBytesReader leaves the excess unread
	// rather than truncating, so the read below fails instead of quietly
	// forwarding half a payload whose AEAD tag could never verify - a truncated
	// record is undecryptable, and the client would have no way to say so.
	//
	// Passing writer is what makes the limit stick: it marks the connection
	// non-reusable so net/http stops reading, which keeps a sender that ignores
	// the limit from streaming unbounded bytes at us. The trade is that the
	// connection is then closed rather than kept alive, so an oversized body
	// costs the sender a reconnect - which is the correct cost to impose.
	if maxBodySize > 0 {
		request.Body = http.MaxBytesReader(writer, request.Body, maxBodySize)
	}

	buffer := new(bytes.Buffer)
	_, err := buffer.ReadFrom(request.Body)
	if err != nil {
		// A body over the cap is the common case here, and it is worth its own
		// outcome: an operator watching error_body climb needs to know whether
		// the relay is broken or whether the origin server started sending
		// payloads APNs cannot carry.
		if maxBytes, oversized := asTooLarge(err); oversized {
			recordRelayRequest("error_payload_too_large")
			requestLog.Error(fmt.Sprintf("Request body exceeds the %d octet limit (-max-body-size)", maxBytes))
			// 500, not 413. Mastodon destroys the subscription on any 4xx outside
			// {408, 429}, so this is expensive to get wrong, and the limit is
			// genuinely ours: RFC 8030 section 7.2 only requires a push service to
			// accept 4096 octets, so a sender going larger violates nothing we can
			// hold it to. Answering 413 would blame the sender for our APNs
			// constraint and could mass-unsubscribe.
			//
			// 429 is the other code Mastodon tolerates, and is arguable - but it
			// invites retries of a payload that is permanently too large. 500 is
			// left deliberately: it describes a relay that cannot carry this
			// without implying the sender should try again.
			http.Error(writer, "Request body too large", http.StatusInternalServerError)
			return
		}

		recordRelayRequest("error_body")
		// The message never quotes the body, which is encrypted; MaxBytesReader's
		// error text carries only a byte count.
		http.Error(writer, "Error reading request body", http.StatusInternalServerError)
		requestLog.Error(fmt.Sprintf("Error reading request body: %s", err))
		return
	}

	encodedString := encode85(buffer.Bytes())
	payload := payload.NewPayload().Alert("🎺").MutableContent().ContentAvailable().Custom("p", encodedString)

	extra := request.PathValue("extra")
	if extra != "" {
		payload.Custom("x", extra)
	}

	notification.Payload = payload
	notification.Topic = topic

	switch request.Header.Get("Content-Encoding") {
	case "aesgcm":
		if publicKey, err := encodedValue(request.Header, "Crypto-Key", "dh"); err == nil {
			payload.Custom("k", publicKey)
		} else {
			recordRelayRequest("error_crypto_key")
			requestLog.Error(fmt.Sprintf("Error retrieving public key: %s", err))
			// 500, not 4xx: Mastodon destroys the subscription on any 4xx other
			// than 408 and 429, and a parse failure here is a relay-side problem,
			// not proof the endpoint is dead. The body deliberately omits the
			// error text, which may quote header values.
			http.Error(writer, "Error parsing Crypto-Key header", http.StatusInternalServerError)
			return
		}

		if salt, err := encodedValue(request.Header, "Encryption", "salt"); err == nil {
			payload.Custom("s", salt)
		} else {
			recordRelayRequest("error_salt")
			requestLog.Error(fmt.Sprintf("Error retrieving salt: %s", err))
			// See the Crypto-Key branch above for why this is 5xx.
			http.Error(writer, "Error parsing Encryption header", http.StatusInternalServerError)
			return
		}
	case "aes128gcm": // RFC8030+RFC8291+RFC8292 support. No further headers needed.
		//
		// Nothing is copied out of the request headers, because RFC 8291 moved
		// the salt and the server public key into the body itself: they are the
		// first 82 octets of the content-coding header, followed by the keyid
		// length. That is why `p` stays the whole body, header included, and why
		// the client reads them from there rather than from `s` and `k`.
		//
		// The body is not opaque to us even so. That header is the only place
		// those two values travel, so if it will not parse, no client can derive
		// a key either, and the notification cannot reach the user. Catching it
		// here costs a few length checks and turns a silent failure on the device
		// into an error the sender can see and a counter an operator can chart.
		if err := checkAes128gcmHeader(buffer.Bytes()); err != nil {
			recordRelayRequest("error_push_header")
			requestLog.Error(fmt.Sprintf("Invalid aes128gcm payload: %s", err))
			// 500 for the reason given in the aesgcm branches below.
			http.Error(writer, "Error parsing aes128gcm payload", http.StatusInternalServerError)
			return
		}
	default:
		recordRelayRequest("error_encoding")
		requestLog.Error(fmt.Sprintf("Unsupported Content-Encoding: %s", request.Header.Get("Content-Encoding")))
		// 501 Not Implemented, deliberately not 415 Unsupported Media Type.
		// 415 blames the request, but the limitation is ours, and Mastodon
		// destroys the Web Push subscription on any 4xx outside {408, 429} -
		// a capability gap on this side must not unsubscribe the user.
		writer.Header().Set("Accept-Encoding", "aesgcm, aes128gcm")
		http.Error(writer, "Unsupported Content-Encoding", http.StatusNotImplemented)
		return
	}

	if seconds := request.Header.Get("TTL"); seconds != "" {
		if ttl, err := strconv.Atoi(seconds); err == nil {
			notification.Expiration = time.Now().Add(time.Duration(ttl) * time.Second)
		}
	}

	if topic := request.Header.Get("Topic"); topic != "" {
		notification.CollapseID = topic
	}

	switch request.Header.Get("Urgency") {
	case "very-low", "low":
		notification.Priority = apns2.PriorityLow
	default:
		notification.Priority = apns2.PriorityHigh
	}

	unsubscribeUrl := request.Header.Get("Unsubscribe-Url")

	// A bare channel send blocks indefinitely once the queue fills, and the
	// sender sees only a read timeout - which it answers by retrying, turning
	// overload into a retry storm. Reject instead, after a short wait that lets
	// ordinary bursts wait their turn.
	if !queueMessage(writer, isProduction, notification, unsubscribeUrl, requestLog, ctx) {
		return
	}

	recordRelayRequest("accepted")

	// always reply w/ success, since we don't know how apple responded
	writer.WriteHeader(201)
}

// queueMessage hands a notification to the worker pool, waiting up to
// queueDropTimeout for room. It returns false when the message was not queued,
// having already written the response.
func queueMessage(writer http.ResponseWriter, isProduction bool, notification *apns2.Notification, unsubscribeUrl string, requestLog *log.Entry, ctx context.Context) bool {
	msg := &Message{isProduction, notification, unsubscribeUrl, requestLog, context.WithoutCancel(ctx)}

	select {
	case messageChan <- msg:
		return true
	default:
	}

	timer := time.NewTimer(queueDropTimeout)
	defer timer.Stop()

	select {
	case messageChan <- msg:
		return true
	case <-timer.C:
		recordRelayRequest("error_queue_full")
		requestLog.Error("Message queue full; rejecting notification")
		// 429 is one of the two 4xx codes Mastodon will not treat as permanent,
		// and it is the accurate description: the subscription is fine, this
		// relay is simply at capacity.
		http.Error(writer, "Relay queue full", http.StatusTooManyRequests)
		return false
	case <-ctx.Done():
		// The sender gave up. Nothing was queued and nothing was pushed.
		recordRelayRequest("error_client_gone")
		return false
	}
}

// aes128gcmHeaderLength is the size of the RFC 8188 content-coding header:
//
//	salt (16) || rs (4) || idlen (1) || keyid (idlen)
//
// RFC 8291 section 4 fixes idlen at 65 for web push - the application server's
// ECDH public key in the uncompressed point form of [X9.62] - so every push
// body opens with exactly 86 octets of header. Push messages carry a single
// record, so there is never a second header or a record boundary to track.
const aes128gcmHeaderLength = 86

// checkAes128gcmHeader reports whether a body could be an aes128gcm payload at
// all, by checking the shape of the content-coding header and the minimum size
// of the record behind it.
//
// Be clear about what this does not do. It cannot tell good crypto from bad:
// the relay holds no key, the client holds the private half of the ECDH pair,
// and RFC 8291 section 3.4 needs that private key to derive anything, so a
// payload with a well-formed header and wrong keys passes here and fails on the
// device exactly as it always did. What it does catch is truncation and
// non-aes128gcm bodies wearing the wrong Content-Encoding, both of which are
// certain failures rather than probable ones - which is the only kind worth
// rejecting on a path where a wrong answer costs users their subscription.
//
// rs is not examined. RFC 8291 section 4 requires exactly one record per push
// message and lets a receiver ignore the record size, so validating it would
// reject senders over a padding choice nobody acts on.
func checkAes128gcmHeader(body []byte) error {
	if len(body) < aes128gcmHeaderLength {
		return fmt.Errorf("body is %d octets, shorter than the %d-octet aes128gcm header", len(body), aes128gcmHeaderLength)
	}

	if idLength := body[20]; idLength != 65 {
		return fmt.Errorf("keyid is %d octets, expected 65 (an uncompressed P-256 point)", idLength)
	}

	if key := body[21]; key != 0x04 {
		return fmt.Errorf("server public key starts with 0x%02x, expected 0x04 (uncompressed point form)", key)
	}

	// RFC 8188 section 2: a record is plaintext plus a padding delimiter plus a
	// 16-octet tag, so 17 is the smallest a complete one can be. Anything
	// shorter is a body that stopped arriving.
	if record := len(body) - aes128gcmHeaderLength; record < 17 {
		return fmt.Errorf("record is %d octets, shorter than the 17-octet minimum of one padding delimiter plus a tag", record)
	}

	return nil
}

// asTooLarge reports whether a body read failed because it exceeded the
// -max-body-size cap, returning that cap. errors.As is used rather than a type
// assertion because io.Reader.ReadFrom wraps what the underlying reader returns.
func asTooLarge(err error) (int64, bool) {
	var maxBytes *http.MaxBytesError
	if errors.As(err, &maxBytes) {
		return maxBytes.Limit, true
	}
	return 0, false
}

func env(name, defaultValue string) string {
	if value, isPresent := os.LookupEnv(name); isPresent {
		return value
	} else {
		return defaultValue
	}
}

func encodedValue(header http.Header, name, key string) (string, error) {
	keyValues := parseKeyValues(header.Get(name))
	value, exists := keyValues[key]
	if !exists {
		return "", fmt.Errorf("value %s not found in header %s", key, name)
	}

	bytes, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}

	return encode85(bytes), nil
}

func parseKeyValues(values string) map[string]string {
	f := func(c rune) bool {
		return c == ';'
	}

	entries := strings.FieldsFunc(values, f)

	m := make(map[string]string)
	for _, entry := range entries {
		parts := strings.Split(entry, "=")
		m[parts[0]] = parts[1]
	}

	return m
}

var z85digits = []byte("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.-:+=^!/*?&<>()[]{}@%$#")

func encode85(bytes []byte) string {
	numBlocks := len(bytes) / 4
	suffixLength := len(bytes) % 4

	encodedLength := numBlocks * 5
	if suffixLength != 0 {
		encodedLength += suffixLength + 1
	}

	encodedBytes := make([]byte, encodedLength)

	src := bytes
	dest := encodedBytes
	for block := 0; block < numBlocks; block++ {
		value := binary.BigEndian.Uint32(src)

		for i := 0; i < 5; i++ {
			dest[4-i] = z85digits[value%85]
			value /= 85
		}

		src = src[4:]
		dest = dest[5:]
	}

	if suffixLength != 0 {
		value := 0

		for i := 0; i < suffixLength; i++ {
			value *= 256
			value |= int(src[i])
		}

		for i := 0; i < suffixLength+1; i++ {
			dest[suffixLength-i] = z85digits[value%85]
			value /= 85
		}
	}

	return string(encodedBytes)
}
