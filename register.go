package main

// Registration endpoints for clients that cannot compose a relay URL themselves.
//
// The relay has always been stateless: the device token rides in the URL path,
// so a push needs nothing but the URL it was POSTed to. That property is what
// makes this service one restartable static binary, and these endpoints preserve
// it. /register is a pure function of its inputs that validates them and returns
// a URL; /unregister acknowledges and logs. Neither opens a database, because
// nothing about delivering a notification requires one.
//
// The client contract implemented here is pinned by Seloi's
// PushRelayClient.swift and its tests, and two details of it are load-bearing
// enough to belong where the code can see them:
//
//   - The response key `relayKey` is decoded by the client as a required String.
//     Omitting it, or sending null, makes JSONDecoder throw *after* a 200 - the
//     client reports failure while the relay logs success.
//   - The returned endpoint must carry a trailing slash. ServeMux's
//     `POST /relay-to/{environment}/{token}/{extra...}` pattern cannot match a
//     two-segment path, so a slash-less endpoint answers 307, and a POST redirect
//     risks losing Content-Encoding, Crypto-Key, Encryption and Unsubscribe-Url.
//
// Note on tests: this file is compiled into `package main`, whose TestMain
// requires APNs credentials that no test checkout has. The validation functions
// here are therefore covered by the black-box tests in register_check_test.go,
// which builds the same code as a binary and exercises it over HTTP.

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"

	log "github.com/sirupsen/logrus"
)

// maxRegistrationBodySize bounds the /register and /unregister request bodies.
// These are small fixed-shape JSON documents - a 64-hex-char token, a 65-byte
// base64url key and a server URL come to well under 512 octets - so the cap is an
// order of magnitude above any legitimate request. It is deliberately not
// -max-body-size: that limit reflects an APNs constraint on push payloads and has
// no bearing on these bodies.
const maxRegistrationBodySize = 4096

// apnsEnvironmentProduction is the default when the client says nothing. Getting
// this default wrong is asymmetric: APNs environment is fixed by the
// aps-environment entitlement baked into the installed build, and every TestFlight
// and App Store build is production. Defaulting to development would silently
// break every real user while working in the simulator; defaulting to production
// fails loudly in relay logs for the handful of Xcode-run debug builds.
const apnsEnvironmentProduction = "production"

// relayKeyValue is read once at startup. See relayKey() for what it is for.
var relayKeyValue = env("RELAY_KEY", "")

// registerRequest is the body of POST /register.
//
// The field names are camelCase because the client encodes a Swift struct with
// these property names and no key-conversion strategy, so they arrive literally.
// unregisterRequest below is snake_case for the same reason in reverse: that one
// is built from a dictionary literal. The inconsistency is the client's, and
// matching it is not negotiable on the server.
type registerRequest struct {
	DeviceToken    string `json:"deviceToken"`
	VapidPublicKey string `json:"vapidPublicKey"`
	ServerURL      string `json:"serverURL"`
	Environment    string `json:"environment"`
}

// unregisterRequest is the body of POST /unregister.
type unregisterRequest struct {
	DeviceToken string `json:"device_token"`
}

type registerResponse struct {
	Endpoint string `json:"endpoint"`
	RelayKey string `json:"relayKey"`
}

func handleRegister(writer http.ResponseWriter, request *http.Request) {
	requestLog := log.WithContext(request.Context())

	var body registerRequest
	if err := decodeRegistrationJSON(writer, request, &body); err != nil {
		return
	}

	token, err := validateDeviceToken(body.DeviceToken)
	if err != nil {
		rejectRegistration(writer, requestLog, "device_token", err)
		return
	}

	if _, err := validateVapidPublicKey(body.VapidPublicKey); err != nil {
		rejectRegistration(writer, requestLog, "vapid_public_key", err)
		return
	}

	serverURL, err := validateServerURL(body.ServerURL)
	if err != nil {
		rejectRegistration(writer, requestLog, "server_url", err)
		return
	}

	// Whitelisted rather than sanitised, because the value is interpolated into a
	// URL path segment. Anything unrecognised becomes the production default
	// rather than a rejection, for the reason given on apnsEnvironmentProduction.
	environment := apnsEnvironmentProduction
	if body.Environment == "development" {
		environment = "development"
	}

	// Built from validated components only, and through url.URL rather than
	// string concatenation so the host is escaped and a scheme cannot be smuggled
	// in via the path. The trailing slash is required: see the package comment.
	endpoint := &url.URL{
		Scheme: "https",
		Host:   request.Host,
		Path:   "/relay-to/" + environment + "/" + token + "/",
	}

	writeJSON(writer, http.StatusOK, registerResponse{
		Endpoint: endpoint.String(),
		RelayKey: relayKey(),
	})

	recordRegistration("register_ok")

	// serverURL is logged because it is the only signal of which instances are
	// using this relay. It is stored nowhere and dialed by nothing.
	requestLog.WithFields(log.Fields{
		"environment": environment,
		"server":      serverURL,
	}).Info("registered push endpoint")
}

// handleUnregister acknowledges a sign-out. It is a no-op by design, and an
// unknown token must still succeed: the client calls this on sign-out, and an
// error there surfaces to a user who has already left.
func handleUnregister(writer http.ResponseWriter, request *http.Request) {
	requestLog := log.WithContext(request.Context())

	var body unregisterRequest
	if err := decodeRegistrationJSON(writer, request, &body); err != nil {
		return
	}

	token, err := validateDeviceToken(body.DeviceToken)
	if err != nil {
		rejectRegistration(writer, requestLog, "device_token", err)
		return
	}

	recordRegistration("unregister_ok")
	requestLog.WithField("token_length", len(token)).Info("unregistered push endpoint")

	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	fmt.Fprint(writer, "{}")
}

// relayKey returns what is handed back as `relayKey`.
//
// It is not a credential today, and that is a decision rather than an omission:
// the client requires the field to be present, but nothing on the relay path
// verifies it and the client has no code that sends it. Returning RELAY_KEY when
// an operator sets it lets a value be minted now and enforced later without a
// client-visible format change.
//
// The unset value is the empty string, not a placeholder word. `authMode` on
// /status deliberately uses "" for the same reason: a sentinel like "none" is
// indistinguishable from a real value in a client log, so a half-wired deployment
// looks configured. Empty is visibly absent.
//
// Making it gate anything is a client-side change too - Seloi would have to send
// it on the push path - and is not done here.
func relayKey() string {
	return relayKeyValue
}

// decodeRegistrationJSON reads a size-bounded JSON body, answering and counting
// the failure itself so no caller can forget to.
//
// 400 is correct here and only here: a 4xx in front of Mastodon destroys a Web
// Push subscription, but /register is called by the iOS client, which has no
// subscription to lose. The relay path keeps its 5xx rule; see AGENTS.md.
func decodeRegistrationJSON(writer http.ResponseWriter, request *http.Request, target any) error {
	request.Body = http.MaxBytesReader(writer, request.Body, maxRegistrationBodySize)

	err := json.NewDecoder(request.Body).Decode(target)
	if err == nil {
		return nil
	}

	var maxBytes *http.MaxBytesError
	switch {
	case errors.As(err, &maxBytes):
		recordRegistration("register_body_too_large")
		http.Error(writer, "request body too large", http.StatusRequestEntityTooLarge)
	case errors.Is(err, io.EOF):
		recordRegistration("register_bad_request")
		http.Error(writer, "request body is required", http.StatusBadRequest)
	default:
		recordRegistration("register_bad_request")
		http.Error(writer, "request body must be JSON", http.StatusBadRequest)
	}

	return err
}

func rejectRegistration(writer http.ResponseWriter, requestLog *log.Entry, field string, err error) {
	recordRegistration("register_bad_request")
	// The reason goes to the log, not the response: echoing a rejected value back
	// to an unauthenticated caller is a cheap way to learn what passed.
	requestLog.WithError(err).WithField("field", field).Warn("rejected registration")
	http.Error(writer, "invalid "+strings.ReplaceAll(field, "_", "-"), http.StatusBadRequest)
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	// Set explicitly rather than relying on Go's sniffing: the client decodes with
	// JSONDecoder, and a text/plain response is a needless way to fail a
	// content-type check.
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)

	if err := json.NewEncoder(writer).Encode(value); err != nil {
		log.WithError(err).Error("failed to write registration response")
	}
}

// validateDeviceToken normalises an APNs device token and proves it is only a
// token.
//
// This string becomes a URL path segment, so this validation is the only thing
// between a client and route injection into this service's own routing table: a
// token of ".." or "production/AAA" would otherwise mint an endpoint that points
// somewhere else entirely. Case is normalised because APNs tokens are
// conventionally lowercase hex and a client uppercasing them is a plausible
// accident; the relay path lowercases nothing, so normalising here keeps every
// minted URL in one shape.
func validateDeviceToken(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("deviceToken is required")
	}

	// Checked before lowering: unicode folding can map non-ASCII lookalikes into
	// the hex range, and this loop keeps the accepted alphabet closed to ASCII.
	for _, c := range raw {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return "", errors.New("deviceToken contains a non-hex character")
		}
	}

	if len(raw)%2 != 0 {
		return "", fmt.Errorf("deviceToken has odd length %d", len(raw))
	}

	decoded, err := hex.DecodeString(raw)
	if err != nil {
		return "", err
	}

	// Length is a sanity bound, not a pin. APNs tokens have been 32 bytes for
	// years but Apple does not document the size as fixed, and newer ones are
	// longer - so anything at or above the historic size passes and only
	// implausible sizes are refused.
	if len(decoded) < 32 {
		return "", fmt.Errorf("deviceToken is %d octets, shorter than the 32 APNs has used", len(decoded))
	}
	if len(decoded) > 128 {
		return "", fmt.Errorf("deviceToken is %d octets, longer than any token this relay will serve", len(decoded))
	}

	return strings.ToLower(raw), nil
}

// validateVapidPublicKey checks that the client's key is a P-256 public key in the
// uncompressed form RFC 8291 requires, and returns the decoded bytes.
//
// The relay never encrypts with this, so the check is not needed to deliver a
// push. It exists because accepting a garbage key means the client subscribes
// successfully and then receives nothing it can ever decrypt - a failure with no
// symptom at registration time and no explanation later. A 400 here is the only
// moment the problem is visible.
func validateVapidPublicKey(raw string) ([]byte, error) {
	if raw == "" {
		return nil, errors.New("vapidPublicKey is required")
	}

	// RawURLEncoding (unpadded) is what Web Crypto and CryptoKit both emit.
	// Accepting padded input too costs nothing and avoids a confusing 400 for a
	// client that pads.
	key, err := base64.RawURLEncoding.DecodeString(raw)
	if err != nil {
		if key, err = base64.URLEncoding.DecodeString(raw); err != nil {
			return nil, fmt.Errorf("vapidPublicKey is not base64url: %w", err)
		}
	}

	if len(key) != 65 {
		return nil, fmt.Errorf("vapidPublicKey is %d octets, want 65 for an uncompressed P-256 point", len(key))
	}

	if key[0] != 0x04 {
		return nil, fmt.Errorf("vapidPublicKey starts with 0x%02x, want 0x04 (uncompressed point)", key[0])
	}

	// The shape checks pass for random 65-octet data 1/256 of the time. This is
	// what proves it is a curve point, and it is the same check the client
	// performs on the server's key.
	if _, err := ecdh.P256().NewPublicKey(key); err != nil {
		return nil, fmt.Errorf("vapidPublicKey is not a P-256 point: %w", err)
	}

	return key, nil
}

// validateServerURL checks the instance URL the client claims to belong to, and
// returns it normalised to scheme and host.
//
// IMPORTANT: nothing stores or fetches this value. It is logged and discarded, so
// it is not an SSRF surface as written. If a future change ever dials it - to
// resolve webPushPublicKey, or to confirm the instance exists - that change must
// also refuse private, loopback, link-local and metadata ranges, because an
// unauthenticated caller controls this string completely.
func validateServerURL(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("serverURL is required")
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return "", err
	}

	if parsed.Scheme != "https" {
		return "", fmt.Errorf("serverURL scheme is %q, want https", parsed.Scheme)
	}

	if parsed.Host == "" {
		return "", errors.New("serverURL has no host")
	}

	// A bare IP host is refused outright: no Mastodon-compatible instance
	// subscribes by address, so this is either a misconfiguration or probing. It
	// also rejects IPv6 literals and decimal-octet forms without having to
	// classify every reserved range by hand - and if this value is ever dialed,
	// refusing IPs removes the most direct route to 127.0.0.1 and 169.254.169.254.
	if ip := net.ParseIP(parsed.Hostname()); ip != nil {
		return "", fmt.Errorf("serverURL host %q is an IP address, not a server name", parsed.Hostname())
	}

	if parsed.User != nil {
		return "", errors.New("serverURL must not contain credentials")
	}

	return parsed.Scheme + "://" + parsed.Host, nil
}
