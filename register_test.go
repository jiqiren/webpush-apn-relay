package main

// Tests for the /register and /unregister endpoints, and for the shape of the
// relay path's responses.
//
// These live in `package main` and construct the mux by hand rather than calling
// main(), because main() loads APNs credentials and log.Fatal exits the process -
// so the handler wiring is asserted here by registering the same patterns and
// documenting that they must match main.go. If you add a route to main(), add it
// to newTestMux() too; the route-parity test below is what catches a drift
// between the two.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
)

// registerBody builds a /register request body, letting a single test override
// just the field it cares about.
func registerBody(t *testing.T, overrides map[string]string) []byte {
	t.Helper()

	body := map[string]string{
		"deviceToken":    validToken,
		"vapidPublicKey": validVAPID(t),
		"serverURL":      "https://mastodon.social",
	}

	for k, v := range overrides {
		if v == "" {
			delete(body, k)
		} else {
			body[k] = v
		}
	}

	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	return encoded
}

const validToken = "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"

// validVAPID returns a real P-256 key rather than 65 bytes of noise, so the
// happy path exercises the curve check instead of merely passing a length test.
func validVAPID(t *testing.T) string {
	t.Helper()

	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	return base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
}

// newRegisterMux mirrors the routing in main(). See the package comment.
func newRegisterMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /register", handleRegister)
	mux.HandleFunc("POST /unregister", handleUnregister)
	return mux
}

func post(t *testing.T, handler http.Handler, path string, body []byte) *httptest.ResponseRecorder {
	t.Helper()

	request := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body))
	request.Host = "push-seloi.dusty.ninja"
	request.Header.Set("Content-Type", "application/json")

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)

	return recorder
}

func TestRegisterHappyPath(t *testing.T) {
	recorder := post(t, newRegisterMux(), "/register", registerBody(t, nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s, want 200", recorder.Code, recorder.Body)
	}

	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}

	var response registerResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("response is not the shape the client decodes: %v (body %s)", err, recorder.Body)
	}

	// RELAY_KEY unset must still yield the field. Set explicitly rather than left to
	// the environment, so this test does not pass or fail depending on the host.
	t.Setenv("RELAY_KEY", "")
	relayKeyValue = ""
	t.Cleanup(func() { relayKeyValue = env("RELAY_KEY", "") })

	// The key must be *present* (a JSON string, even an empty one), not non-empty.
	// The client's decoder requires the field; it does not require content. Asserted
	// on the raw JSON because unmarshalling into a struct cannot tell "" from an
	// absent field, which is exactly the distinction that matters here.
	if !strings.Contains(recorder.Body.String(), `"relayKey":"`) {
		t.Error("response has no relayKey string: the client decodes it as required, so an absent field reads as a failure after a 200")
	}

	if !strings.HasSuffix(response.Endpoint, "/") {
		t.Errorf("endpoint %q has no trailing slash, which makes the relay answer 307", response.Endpoint)
	}

	if !strings.HasPrefix(response.Endpoint, "https://push-seloi.dusty.ninja/relay-to/production/"+validToken+"/") {
		t.Errorf("endpoint = %q, want the production path for the token", response.Endpoint)
	}

	// The path must be exactly the four segments we intend. A "//" or ".." here
	// means a client-supplied string reached the path unescaped.
	path := strings.TrimPrefix(response.Endpoint, "https://push-seloi.dusty.ninja")
	if strings.Contains(path, "..") {
		t.Errorf("endpoint path %q contains ..", path)
	}

	if strings.Count(path, "//") != 0 {
		t.Errorf("endpoint path %q contains an empty segment", path)
	}
}

func TestRegisterEnvironment(t *testing.T) {
	// An unrecognised value must fall back to production rather than being
	// interpolated into the URL, and must not be a 400 either: the client cannot
	// recover from a rejection it did not cause.
	for _, tc := range []struct{ sent, want string }{
		{"", "production"},
		{"development", "development"},
		{"production", "production"},
		{"Production", "production"},
		{"../../etc", "production"},
		{"production/AAA", "production"},
		{"https://evil.example", "production"},
	} {
		t.Run("sent="+tc.sent, func(t *testing.T) {
			recorder := post(t, newRegisterMux(), "/register", registerBody(t, map[string]string{"environment": tc.sent}))

			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
			}

			var response registerResponse
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}

			if want := "/relay-to/" + tc.want + "/"; !strings.Contains(response.Endpoint, want) {
				t.Errorf("endpoint = %q, want it to contain %q", response.Endpoint, want)
			}
		})
	}
}

func TestRegisterRejectsBadInput(t *testing.T) {
	noiseKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xaa}, 65))
	compressedKey := base64.RawURLEncoding.EncodeToString(append([]byte{0x02}, bytes.Repeat([]byte{0x01}, 64)...))
	shortKey := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0x04}, 64))

	for _, tc := range []struct {
		name      string
		overrides map[string]string
	}{
		{"missing deviceToken", map[string]string{"deviceToken": ""}},
		{"non-hex token", map[string]string{"deviceToken": "0000111122223333444455556666777788889999aaaabbbbccccddddzzzzffff"}},
		{"token with slash", map[string]string{"deviceToken": "aaaa/bbbb"}},
		{"token with dotdot", map[string]string{"deviceToken": ".."}},
		{"token with newline", map[string]string{"deviceToken": validToken + "\n"}},
		{"token with space", map[string]string{"deviceToken": validToken + " "}},
		{"odd-length token", map[string]string{"deviceToken": validToken[:63]}},
		{"short token", map[string]string{"deviceToken": "aabbccddeeff00112233445566778899"}},
		{"overlong token", map[string]string{"deviceToken": strings.Repeat("ab", 200)}},
		{"missing vapidPublicKey", map[string]string{"vapidPublicKey": ""}},
		{"vapid not base64", map[string]string{"vapidPublicKey": "not base64!!!"}},
		{"vapid wrong length", map[string]string{"vapidPublicKey": shortKey}},
		{"vapid compressed point", map[string]string{"vapidPublicKey": compressedKey}},
		{"vapid not a curve point", map[string]string{"vapidPublicKey": noiseKey}},
		{"missing serverURL", map[string]string{"serverURL": ""}},
		{"http serverURL", map[string]string{"serverURL": "http://mastodon.social"}},
		{"unparseable serverURL", map[string]string{"serverURL": "https://%zz"}},
		{"serverURL with no host", map[string]string{"serverURL": "https:///path"}},
		{"serverURL is an IP", map[string]string{"serverURL": "https://127.0.0.1"}},
		{"serverURL is an IPv6 literal", map[string]string{"serverURL": "https://[::1]"}},
		{"serverURL with credentials", map[string]string{"serverURL": "https://user:pw@mastodon.social"}},
		{"serverURL is a lookalike scheme", map[string]string{"serverURL": "https:/mastodon.social"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := post(t, newRegisterMux(), "/register", registerBody(t, tc.overrides))

			// 4xx is deliberate here and only here: the caller is the iOS client,
			// which has no Web Push subscription to lose. See AGENTS.md.
			if recorder.Code < 400 || recorder.Code > 499 {
				t.Fatalf("status = %d, want 4xx (body %s)", recorder.Code, recorder.Body)
			}

			if strings.Contains(recorder.Body.String(), "relayKey") {
				t.Error("a rejected registration still returned a relayKey")
			}
		})
	}
}

func TestRegisterRejectsOversizedBody(t *testing.T) {
	// Well past maxRegistrationBodySize, padded inside a field the parser accepts
	// so the rejection comes from the size limit and not from JSON validity.
	padded := validToken + strings.Repeat("ab", maxRegistrationBodySize)

	recorder := post(t, newRegisterMux(), "/register", registerBody(t, map[string]string{"deviceToken": padded}))

	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413 (body %s)", recorder.Code, recorder.Body)
	}
}

func TestRegisterRejectsNonJSON(t *testing.T) {
	for _, tc := range []struct{ name, body string }{
		{"empty", ""},
		{"plain text", "deviceToken=abcdef"},
		{"truncated object", `{"deviceToken": "`},
		{"array", `[1,2,3]`},
		{"null", `null`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := post(t, newRegisterMux(), "/register", []byte(tc.body))

			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s)", recorder.Code, recorder.Body)
			}
		})
	}
}

// TestRegisterUppercaseTokenIsNormalised pins that a client which uppercases its
// token still gets a working endpoint, and that the relay sees one URL shape.
func TestRegisterUppercaseTokenIsNormalised(t *testing.T) {
	recorder := post(t, newRegisterMux(), "/register", registerBody(t, map[string]string{"deviceToken": strings.ToUpper(validToken)}))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}

	var response registerResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(response.Endpoint, validToken) {
		t.Errorf("endpoint = %q, want the lowercased token", response.Endpoint)
	}
}

func TestUnregister(t *testing.T) {
	mux := newRegisterMux()

	// The client sends snake_case here and camelCase on /register; that asymmetry
	// is the client's and this asserts the server matches it.
	recorder := post(t, mux, "/unregister", []byte(`{"device_token":"`+validToken+`"}`))

	if recorder.Code/100 != 2 {
		t.Fatalf("status = %d, want 2xx (body %s)", recorder.Code, recorder.Body)
	}

	// Unknown tokens must also succeed: the client calls this on sign-out, and an
	// error would surface to a user who has already left.
	unknown := post(t, mux, "/unregister", []byte(`{"device_token":"ffffeeeedddccccccbbbbaaaa999988887777666655554444333322221111000"}`))

	if unknown.Code/100 != 2 {
		t.Errorf("unknown token: status = %d, want 2xx", unknown.Code)
	}

	// A malformed token is still rejected, so the endpoint is not a free-form
	// string sink.
	bad := post(t, mux, "/unregister", []byte(`{"device_token":"../../etc/passwd"}`))

	if bad.Code/100 != 4 {
		t.Errorf("malformed token: status = %d, want 4xx", bad.Code)
	}
}

// TestRelayPathStatusCodes pins the rule that a relay-side fault is never a 4xx:
// Mastodon destroys the Web Push subscription on any 4xx except 408 and 429, so a
// 4xx here is an unsubscribe command. These use a mux containing the real push
// pattern but no APNs client, so every failure is a handler-side one.
func TestRelayPathStatusCodes(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /relay-to/{environment}/{token}/{extra...}", handleApnNotification)

	for _, tc := range []struct {
		name     string
		encoding string
		want     int
	}{
		{"unsupported encoding is 501, not 400", "aes128ccm", http.StatusNotImplemented},
		{"aesgcm with no Crypto-Key is 500, not 400", "aesgcm", http.StatusInternalServerError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/relay-to/production/"+validToken+"/", strings.NewReader("payload"))
			request.Header.Set("Content-Encoding", tc.encoding)

			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, request)

			if recorder.Code != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", recorder.Code, tc.want, recorder.Body)
			}

			if recorder.Code >= 400 && recorder.Code < 500 && recorder.Code != http.StatusTooManyRequests {
				t.Errorf("status %d is a 4xx: this unsubscribes every user of a sender that follows Mastodon's behaviour", recorder.Code)
			}
		})
	}

	t.Run("unsupported encoding advertises what works", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "/relay-to/production/"+validToken+"/", strings.NewReader("payload"))
		request.Header.Set("Content-Encoding", "aes128ccm")

		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, request)

		if got := recorder.Header().Get("Accept-Encoding"); !strings.Contains(got, "aes128gcm") {
			t.Errorf("Accept-Encoding = %q, want it to list aes128gcm", got)
		}
	})

	t.Run("oversized body is 500, not 413", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "/relay-to/production/"+validToken+"/", strings.NewReader(strings.Repeat("a", int(maxBodySize)+1)))
		request.Header.Set("Content-Encoding", "aes128gcm")

		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, request)

		if recorder.Code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500: 413 would be read as an unsubscribe signal", recorder.Code)
		}
	})
}

// TestRelayAcceptsEndpointFromRegister is the end-to-end shape check for the
// trailing-slash requirement: the URL /register mints must be routable by the
// push handler with no redirect in between.
//
// This test previously passed a 7-octet body and asserted only that the status was
// not a redirect, so it could never have observed the 201 it exists to protect -
// checkAes128gcmHeader rejects that body with a 500 first. It now sends a real
// 86-octet content-coding header and asserts the 201 directly.
func TestRelayAcceptsEndpointFromRegister(t *testing.T) {
	restore := useTestQueue(t)
	defer restore()

	registered := post(t, newRegisterMux(), "/register", registerBody(t, map[string]string{"environment": "development"}))

	var response registerResponse
	if err := json.Unmarshal(registered.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodPost, response.Endpoint, bytes.NewReader(makeBody(t, 144)))
	request.Header.Set("Content-Encoding", "aes128gcm")

	recorder := httptest.NewRecorder()
	relayMux().ServeHTTP(recorder, request)

	// ServeMux answers 307 for a path it wants to canonicalise, which is
	// StatusTemporaryRedirect. StatusPermanentRedirect is 308 and this mux never
	// emits it; both are named because the point is "any redirect", and the reason
	// to also assert the 201 below rather than trusting this pair is that a guard
	// which names the wrong constant passes forever.
	if recorder.Code == http.StatusPermanentRedirect || recorder.Code == http.StatusTemporaryRedirect {
		t.Fatalf("the minted endpoint redirects (%d): Mastodon may drop Content-Encoding, Crypto-Key, Encryption and Unsubscribe-Url", recorder.Code)
	}

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201 for the minted endpoint %q (body %s)", recorder.Code, response.Endpoint, recorder.Body)
	}

	if !strings.HasSuffix(response.Endpoint, "/") {
		t.Errorf("endpoint %q lacks the trailing slash", response.Endpoint)
	}
}

// TestRegisterWithExtraMintsThreeSegmentEndpoint covers the account-hint field:
// a valid `extra` must become a third path segment, and must keep the trailing
// slash that the two-segment form needs for the same reason.
func TestRegisterWithExtraMintsThreeSegmentEndpoint(t *testing.T) {
	for _, extra := range []string{
		"acct1",
		"acct.1",
		"acct-1",
		"acct_1",
		"A",
		"aA0.-_",
		strings.Repeat("x", 64), // the upper bound is inclusive
	} {
		t.Run("extra="+extra, func(t *testing.T) {
			recorder := post(t, newRegisterMux(), "/register", registerBody(t, map[string]string{"extra": extra}))

			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s, want 200", recorder.Code, recorder.Body)
			}

			var response registerResponse
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatalf("response is not the shape the client decodes: %v (body %s)", err, recorder.Body)
			}

			want := "https://push-seloi.dusty.ninja/relay-to/production/" + validToken + "/" + extra + "/"

			if response.Endpoint != want {
				t.Errorf("endpoint = %q, want %q", response.Endpoint, want)
			}

			// Asserted separately from the equality above because it is a client
			// contract that outlives any particular routing quirk. Be precise about
			// what it buys on this path: the `{extra...}` catch-all matches a *missing*
			// segment, so a three-segment endpoint routes with or without the slash
			// (see TestRegisterExtraEndpointRoundTrips, which POSTs to the slashless
			// form to pin that). The slash is load-bearing for the two-segment form,
			// and is emitted in both so the client has one rule rather than two.
			if !strings.HasSuffix(response.Endpoint, "/") {
				t.Errorf("endpoint %q has no trailing slash", response.Endpoint)
			}

			// Exactly four segments: /relay-to, environment, token, extra. A fifth
			// would mean the value carried a separator, and an empty one would mean
			// the slash was doubled.
			path := strings.TrimPrefix(response.Endpoint, "https://push-seloi.dusty.ninja")

			if got := strings.Count(path, "/"); got != 5 {
				t.Errorf("path %q has %d slashes, want 5 (four segments plus the trailing slash)", path, got)
			}

			// The whitelist forbids both of these, so their presence would mean the
			// value reached the path unvalidated rather than through validateExtra.
			if strings.Contains(path, "..") {
				t.Errorf("path %q contains ..", path)
			}

			if strings.Contains(path, "%") {
				t.Errorf("path %q contains a percent sign, so the value was escaped on the way out and the device would receive something other than what was registered", path)
			}
		})
	}
}

// TestRegisterWithoutExtraIsUnchanged is the backward-compatibility guard. Every
// installed client holds a two-segment endpoint, and an "optional" field that
// changed the shape of the URL when absent would break them for no benefit.
func TestRegisterWithoutExtraIsUnchanged(t *testing.T) {
	// An absent field and an explicit empty string must land on the same branch:
	// encoding/json leaves Extra as "" either way, and "" means "no segment", not
	// "a zero-length segment". A trailing empty segment is a different path to
	// ServeMux, so this distinction is observable, not cosmetic.
	for _, tc := range []struct {
		name string
		body []byte
	}{
		// registerBody drops keys whose override value is "", so this is genuinely
		// a body with no `extra` key at all.
		{"absent", registerBody(t, nil)},
		{"empty string", registerBody(t, map[string]string{"extra": ""})},
		{"explicit JSON null", registerBodyWithNullExtra(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := post(t, newRegisterMux(), "/register", tc.body)

			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s, want 200", recorder.Code, recorder.Body)
			}

			var response registerResponse
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}

			want := "https://push-seloi.dusty.ninja/relay-to/production/" + validToken + "/"

			if response.Endpoint != want {
				t.Errorf("endpoint = %q, want the two-segment form %q", response.Endpoint, want)
			}

			// The regression this exists for, spelled out: a trailing empty segment
			// would render as .../token//.
			if strings.HasSuffix(response.Endpoint, "//") {
				t.Errorf("endpoint %q ends in an empty segment", response.Endpoint)
			}
		})
	}
}

// registerBodyWithNullExtra sends "extra": null, which encoding/json also
// decodes as "", so it must behave like an absent field rather than a rejection.
func registerBodyWithNullExtra(t *testing.T) []byte {
	t.Helper()

	body := `{"deviceToken":"` + validToken +
		`","vapidPublicKey":"` + validVAPID(t) +
		`","serverURL":"https://mastodon.social","extra":null}`

	return []byte(body)
}

// TestRegisterRejectsBadExtra pins the whitelist. Each case is a value that would
// either change the routing this service performs on the minted URL, or arrive at
// the device as something other than what the client registered.
func TestRegisterRejectsBadExtra(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra string
		why   string
	}{
		{"slash", "acct/1", "a slash adds a path segment, so the endpoint would route differently than registered"},
		{"leading slash", "/acct1", "a leading slash makes the extra an absolute-looking segment and inserts an empty one"},
		{"bare dotdot", "..", "the only reachable dot segment (the class excludes `/`, so it cannot appear inside a value): net/http normalises /token/../ to /relay-to/production/, which is not routable, so the sender gets 404 after /register said 200"},
		{"bare dot", ".", "collapses to nothing, so the endpoint would be a two-segment path wearing a three-segment registration"},
		{"interior dotdot", "a/../b", "refused for its slashes before any dot rule applies; listed because it is the value a sanitiser would rewrite rather than reject"},
		{"single dot", "a/./b", "collapses to `a/b`"},
		{"bare dotdot", "..", "the classic traversal: net/http normalises /token/../ to the environment segment, which is no longer a routable path"},
		{"dotdot tail", "a/..", "collapses to an empty extra, i.e. a two-segment endpoint wearing a three-segment registration"},
		{"percent", "acct%2F1", "url.URL renders a literal % as %25, so the device would receive acct%252F1"},
		{"percent-encoded slash", "a%2fb", "same double-escape, and it decodes to a slash for anything that unescapes"},
		{"length 65", strings.Repeat("x", 65), "over the bound"},
		{"unicode", "complété", "outside the accepted class; it would also percent-escape on the way out"},
		{"unicode emoji", "\U0001f514", "outside the accepted class"},
		{"space", "acct 1", "a space in a path segment is escaped or truncated depending on the sender"},
		{"tab", "acct\t1", "a control character in a URL path"},
		{"newline", "acct\n1", "request splitting surface in a path segment"},
		{"query", "acct?x=1", "a ? would terminate the path for anything that re-parses the endpoint"},
		{"hash", "acct#1", "a # would become a fragment and never reach the handler"},
		{"colon", "acct:1", "outside the accepted class"},
		{"at sign", "acct@1", "outside the accepted class"},
		{"plus", "acct+1", "outside the accepted class; some senders read + as a space"},
		{"equals", "acct=1", "outside the accepted class"},
		{"tilde", "acct~1", "outside the accepted class"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recorder := post(t, newRegisterMux(), "/register", registerBody(t, map[string]string{"extra": tc.extra}))

			// 4xx is deliberate here and only here. rejectRegistration carries the
			// comment; AGENTS.md carries the rule. The relay path would answer 5xx for
			// a problem of its own, because a 4xx there unsubscribes the user.
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want 400 (body %s) - %s", recorder.Code, recorder.Body, tc.why)
			}

			// http.Error writes "invalid " + field with underscores turned into
			// dashes, so the field name `extra` comes back verbatim. Asserted on the
			// body because a 400 that named the wrong field would send the client off
			// debugging the wrong key.
			if !strings.Contains(recorder.Body.String(), "invalid extra") {
				t.Errorf("body = %q, want it to name the rejected field", recorder.Body)
			}

			if strings.Contains(recorder.Body.String(), tc.extra) {
				t.Errorf("body %q echoes the rejected value back to an unauthenticated caller", recorder.Body)
			}

			if strings.Contains(recorder.Body.String(), "relayKey") {
				t.Error("a rejected registration still returned a relayKey")
			}
		})
	}
}

// TestRegisterExtraDoesNotOverrideEnvironment guards against the two optional
// fields being concatenated rather than independently validated: an extra that
// looks like an environment must not become one, and must not let a caller pick
// an environment it was not given.
func TestRegisterExtraDoesNotOverrideEnvironment(t *testing.T) {
	for _, extra := range []string{"development", "production"} {
		t.Run("extra="+extra, func(t *testing.T) {
			recorder := post(t, newRegisterMux(), "/register", registerBody(t, map[string]string{"extra": extra}))

			if recorder.Code != http.StatusOK {
				t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
			}

			var response registerResponse
			if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}

			// The word lands in the fourth segment, and the environment segment stays
			// at the default, since no `environment` was sent.
			want := "https://push-seloi.dusty.ninja/relay-to/production/" + validToken + "/" + extra + "/"

			if response.Endpoint != want {
				t.Errorf("endpoint = %q, want %q", response.Endpoint, want)
			}
		})
	}
}

// relayMux builds the push route as main.go registers it, so a test that POSTs to
// a minted endpoint asserts against the real routing table rather than a stub.
//
// The pattern is duplicated rather than shared because main() loads APNs
// credentials and log.Fatal exits the process, so no test can call it; TestRouteParity
// is what keeps this list honest. It is spelled in pieces because that parity test
// scrapes the literal `mux.HandleFunc("` out of main.go by substring, and its
// allowlist has no way to tell a registration from a comment about one.
func relayMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST "+pushRoutePattern, handleApnNotification)

	return mux
}

// TestRegisterExtraEndpointRoundTrips is the end-to-end half: the three-segment
// endpoint /register mints must actually be routable, must not redirect, and must
// be accepted. A whitelist that produced endpoints the mux could not serve would
// pass every validation test above and deliver nothing.
//
// This is also the only place the {extra...} segment is proven to arrive: the
// handler forwards it to APNs as the custom field `x`, which is the whole point of
// the field, and ServeMux handing back a 307 or a 404 here would mean the minted
// URL is dead on arrival.
//
// The bodies are built by makeBody so they carry a real 86-octet aes128gcm
// content-coding header. A short body is refused with 500 by checkAes128gcmHeader
// before the handler ever reaches its 201, which is why the pre-existing
// TestRelayAcceptsEndpointFromRegister only asserts "not a redirect" - it cannot
// get further with `strings.NewReader("payload")`.
func TestRegisterExtraEndpointRoundTrips(t *testing.T) {
	restore := useTestQueue(t)
	defer restore()

	for _, extra := range []string{"acct1", "acct.2-3", strings.Repeat("z", 64)} {
		t.Run("extra="+extra, func(t *testing.T) {
			registered := post(t, newRegisterMux(), "/register", registerBody(t, map[string]string{"extra": extra}))

			if registered.Code != http.StatusOK {
				t.Fatalf("register: status = %d, body = %s", registered.Code, registered.Body)
			}

			var response registerResponse
			if err := json.Unmarshal(registered.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}

			request := httptest.NewRequest(http.MethodPost, response.Endpoint, bytes.NewReader(makeBody(t, 144)))
			request.Header.Set("Content-Encoding", "aes128gcm")

			recorder := httptest.NewRecorder()
			relayMux().ServeHTTP(recorder, request)

			if recorder.Code == http.StatusTemporaryRedirect || recorder.Code == http.StatusPermanentRedirect {
				t.Fatalf("the minted endpoint redirects (%d): Mastodon may drop Content-Encoding, Crypto-Key, Encryption and Unsubscribe-Url", recorder.Code)
			}

			// 404 would mean the minted path is not in the routing table at all, which
			// is the failure mode the three-segment form actually risks.
			if recorder.Code == http.StatusNotFound {
				t.Fatalf("ServeMux does not match the minted path %q", response.Endpoint)
			}

			// 201 is what the handler answers once the message is queued, before any
			// APNs round-trip. Anything else means the request never got that far.
			if recorder.Code != http.StatusCreated {
				t.Fatalf("status = %d, want 201 (body %s)", recorder.Code, recorder.Body)
			}
		})
	}

	// The two-segment form must round-trip too, or the regression guard above is
	// protecting an endpoint that does not work either.
	t.Run("absent extra still round-trips", func(t *testing.T) {
		registered := post(t, newRegisterMux(), "/register", registerBody(t, nil))

		var response registerResponse
		if err := json.Unmarshal(registered.Body.Bytes(), &response); err != nil {
			t.Fatal(err)
		}

		request := httptest.NewRequest(http.MethodPost, response.Endpoint, bytes.NewReader(makeBody(t, 144)))
		request.Header.Set("Content-Encoding", "aes128gcm")

		recorder := httptest.NewRecorder()
		relayMux().ServeHTTP(recorder, request)

		if recorder.Code != http.StatusCreated {
			t.Fatalf("status = %d, want 201 for %q (body %s)", recorder.Code, response.Endpoint, recorder.Body)
		}
	})

	// What the trailing slash is actually for, pinned from both sides. ServeMux
	// cannot match a path that stops after the token, so the slashless two-segment
	// form redirects; the same catch-all that makes the three-segment form match with
	// OR without its slash is what makes the two-segment form need one. If this ever
	// stops returning 307 the slash is no longer load-bearing and the package comment
	// needs updating.
	//
	// Driven through a real client rather than httptest.NewRequest, because a
	// hand-built request carries no URL.Clean()ed path and the redirect is a
	// function of what the client actually puts on the wire. CheckRedirect keeps the
	// client from silently following the 307 and reporting the 201 it lands on.
	t.Run("two-segment endpoint without the slash redirects", func(t *testing.T) {
		server := httptest.NewServer(relayMux())
		defer server.Close()

		restore := useTestQueue(t)
		defer restore()

		endpoint := server.URL + "/relay-to/production/" + validToken
		noRedirect := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}

		request, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(makeBody(t, 144)))
		if err != nil {
			t.Fatal(err)
		}

		request.Header.Set("Content-Encoding", "aes128gcm")

		response, err := noRedirect.Do(request)
		if err != nil {
			t.Fatalf("do: %v", err)
		}

		defer response.Body.Close()

		// ServeMux answers 307, which is StatusTemporaryRedirect. StatusPermanentRedirect
		// is 308 - a different code, and the reason the pre-existing redirect guards in
		// this file never fire. See TestRelayAcceptsEndpointFromRegister.
		if response.StatusCode != http.StatusTemporaryRedirect {
			t.Errorf("slashless two-segment endpoint: status = %d, want 307 - the trailing slash is what prevents this", response.StatusCode)
		}

		if !strings.HasSuffix(response.Header.Get("Location"), "/") {
			t.Errorf("redirect Location = %q, want it to point at the slashless form's canonical target", response.Header.Get("Location"))
		}
	})

	// And the mirror of that, so the comment in register.go cannot drift into
	// claiming the slash is required in both forms: the three-segment endpoint
	// routes without it, because `{extra...}` matches a present segment either way.
	t.Run("three-segment endpoint routes without the slash too", func(t *testing.T) {
		endpoint := "https://push-seloi.dusty.ninja/relay-to/production/" + validToken + "/acct1"

		request := httptest.NewRequest(http.MethodPost, endpoint, bytes.NewReader(makeBody(t, 144)))
		request.Header.Set("Content-Encoding", "aes128gcm")

		recorder := httptest.NewRecorder()
		relayMux().ServeHTTP(recorder, request)

		if recorder.Code == http.StatusPermanentRedirect || recorder.Code == http.StatusTemporaryRedirect {
			t.Errorf("slashless three-segment endpoint redirected (%d): the catch-all should have matched it", recorder.Code)
		}

		if recorder.Code != http.StatusCreated {
			t.Errorf("slashless three-segment endpoint: status = %d, want 201", recorder.Code)
		}
	})
}

// pushRoutePattern is the relay route, spelled in pieces so this file stays free
// of the literal TestRouteParity scrapes out of main.go. See relayMux.
const pushRoutePattern = "/relay-to/{environment}/{token}/{extra...}"

// useTestQueue gives the push handler somewhere to put a message so it can reach
// its 201. messageChan is built by main(), which no test calls, so it is nil in
// tests and a send on a nil channel blocks forever. The channel is restored by the
// returned func; nothing here starts a worker, so nothing drains it, which is why
// the capacity is generous and every subtest runs with the queue empty.
func useTestQueue(t *testing.T) func() {
	t.Helper()

	previous := messageChan
	messageChan = make(chan *Message, 256)

	return func() { messageChan = previous }
}

// TestRegisterBadExtraHasOwnMetricOutcome checks the counter rather than the
// response, because the whole point of the series is that it is chartable: a
// client shipping hints outside the whitelist is invisible in the logs unless
// something increments.
//
// It asserts the specific series moved and that the generic one did not, which is
// the double-counting bug: the two counters must stay additive against the
// pre-existing relay_registrations_total series, not overlap.
func TestRegisterBadExtraHasOwnMetricOutcome(t *testing.T) {
	// The registry is package-level and other tests in this package have already
	// incremented these series, so every assertion is a delta against a baseline
	// read immediately before the request - never an absolute count. Asserting
	// absolutes here would couple this test to the order go test happens to run in.
	beforeBad := registrationCount(t, "register_bad_extra")
	beforeGeneric := registrationCount(t, "register_bad_request")

	recorder := post(t, newRegisterMux(), "/register", registerBody(t, map[string]string{"extra": "acct/1"}))

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}

	if got := registrationCount(t, "register_bad_extra"); got != beforeBad+1 {
		t.Errorf("register_bad_extra moved by %v, want 1", got-beforeBad)
	}

	if got := registrationCount(t, "register_bad_request"); got != beforeGeneric {
		t.Errorf("register_bad_request moved by %v, want 0: the request was counted twice", got-beforeGeneric)
	}

	// A rejection for some other field must still land on the generic series, or
	// the split above has swallowed the pre-existing counter.
	beforeGeneric = registrationCount(t, "register_bad_request")

	badToken := post(t, newRegisterMux(), "/register", registerBody(t, map[string]string{"deviceToken": "zz"}))

	if badToken.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", badToken.Code)
	}

	if got := registrationCount(t, "register_bad_request"); got != beforeGeneric+1 {
		t.Errorf("register_bad_request moved by %v, want 1: a non-extra rejection must still reach the generic series", got-beforeGeneric)
	}
}

// registrationCount reads a single label value out of the registry. It goes
// through Gather() rather than the counter variable so the assertion covers what
// /metrics would actually emit, including that initializeLabelSeries pre-seeded the
// outcome at zero - a series that only appears on first use cannot be charted
// against "is this zero or absent?".
func registrationCount(t *testing.T, outcome string) float64 {
	t.Helper()

	families, err := metricsRegistry.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}

	for _, family := range families {
		if family.GetName() != "relay_registrations_total" {
			continue
		}

		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				if label.GetValue() == outcome {
					return metric.GetCounter().GetValue()
				}
			}
		}
	}

	t.Fatalf("relay_registrations_total{outcome=%q} is not exported: initializeLabelSeries must pre-seed it", outcome)

	return 0
}

// TestRouteParity guards the one thing a hand-built test mux cannot guarantee:
// that main.go still registers every route this test assumes exists.
func TestRouteParity(t *testing.T) {
	for _, pattern := range registeredPatterns(t) {
		switch pattern {
		case "POST /register", "POST /unregister",
			"POST /relay-to/{environment}/{token}/{extra...}",
			"GET /relay-to/_health", "GET /status":
		default:
			t.Errorf("main.go registers an unexpected route %q; update this test deliberately", pattern)
		}
	}
}

func registeredPatterns(t *testing.T) []string {
	t.Helper()

	// http.ServeMux has no exported way to enumerate patterns, so this reads the
	// source. Cheap, and it fails loudly rather than silently passing.
	source, err := readFileForTest("main.go")
	if err != nil {
		t.Skipf("cannot read main.go: %v", err)
	}

	var patterns []string

	for _, line := range strings.Split(source, "\n") {
		marker := "mux.HandleFunc(\""

		start := strings.Index(line, marker)
		if start < 0 {
			continue
		}

		rest := line[start+len(marker):]
		end := strings.Index(rest, "\"")

		if end < 0 {
			continue
		}

		patterns = append(patterns, rest[:end])
	}

	if len(patterns) == 0 {
		t.Fatal("no routes found in main.go")
	}

	return patterns
}

// readFileForTest reads a source file from the package directory. go test runs with
// the working directory already set to the package, so the name is used as given;
// falling back to a directory-relative path keeps it working when invoked some other
// way.
func readFileForTest(name string) (string, error) {
	if data, err := os.ReadFile(name); err == nil {
		return string(data), nil
	}

	data, err := os.ReadFile(filepath.Join(filepath.Dir(thisFile()), name))

	return string(data), err
}

// thisFile is the path of this test file, used only to locate the package directory
// when the working directory is not it.
func thisFile() string {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		return "register_test.go"
	}

	return file
}

func mustReadFile(t *testing.T, name string) string {
	t.Helper()

	source, err := readFileForTest(name)
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}

	return source
}

// packageLevelVars returns the names declared at package scope in a Go source
// file: top-level `var x T`, `var x = ...`, and the entries of a top-level var
// block. Anything here outlives a request, which is what makes it worth counting.
//
// Deliberately simple: it takes the leading identifier of each declaration, so
// `var a, b = 1, 2` reports only "a". That is sufficient for the regression it is
// written for - someone adding a registry - and a false negative beats a parser
// that breaks on formatting variation.
func packageLevelVars(t *testing.T, source string) []string {
	t.Helper()

	var names []string
	inVarBlock := false

	for _, line := range strings.Split(source, "\n") {
		if strings.HasPrefix(line, "var (") {
			inVarBlock = true
			continue
		}

		if inVarBlock {
			if strings.HasPrefix(line, ")") {
				inVarBlock = false
				continue
			}

			if name := leadingIdent(line); name != "" {
				names = append(names, name)
			}

			continue
		}

		if rest, ok := strings.CutPrefix(line, "var "); ok {
			if name := leadingIdent(rest); name != "" {
				names = append(names, name)
			}
		}
	}

	return names
}

var identPattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*`)

// leadingIdent returns the first identifier of a declaration line, ignoring
// comments and blanks.
func leadingIdent(line string) string {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" || strings.HasPrefix(trimmed, "//") {
		return ""
	}

	return identPattern.FindString(trimmed)
}

// TestStatelessnessIsStructural is the answer to "did we quietly add a database?"
//
// The property this service sells is that it needs no store: the device token
// travels in the URL, so the push path never consults a lookup. That is easy to
// lose gradually - a map, a mutex, a file, and every endpoint still passes its own
// tests while the deployment story silently changes from "one restartable static
// binary" to "back this with something durable".
//
// So the test asserts the absence of state. A grep for "sql" would pass after
// someone added an in-memory map and called it a cache, which is the realistic
// regression here; this checks for package-level mutable state instead.
func TestStatelessnessIsStructural(t *testing.T) {
	// relayKeyValue is the only package-level variable in register.go, written once
	// at init from RELAY_KEY. A second one has to either join this list after being
	// argued for, or go away.
	const allowed = "relayKeyValue"

	got := packageLevelVars(t, mustReadFile(t, "register.go"))

	if len(got) != 1 || got[0] != allowed {
		t.Errorf("register.go must hold no state: expected only %q at package scope, found %v", allowed, got)
	}

	// The other half: the push path must not consult a registry either, since that
	// is the only reason one would be added.
	for _, file := range []string{"main.go", "process_apn_notification.go"} {
		body := mustReadFile(t, file)

		for _, forbidden := range []string{"registeredDevices", "deviceRegistry", "sync.Map"} {
			if strings.Contains(body, forbidden) {
				t.Errorf("%s references %q: nothing on the push path may require a device registry", file, forbidden)
			}
		}
	}

	// And no persistence layer may enter the module, directly or transitively.
	if out := modGraph(t); strings.Contains(out, "database/sql") || strings.ContainsAny(out, "") && containsAnyFold(out, "sqlite", "postgres", "mysql", "redis", "gorm", "sqlx", "mongo") {
		t.Errorf("go.mod graph now pulls a database dependency:\n%s", out)
	}
}

func containsAnyFold(haystack string, needles ...string) bool {
	lower := strings.ToLower(haystack)

	for _, n := range needles {
		if strings.Contains(lower, n) {
			return true
		}
	}

	return false
}

// modGraph shells out to the toolchain. Skips rather than fails where a sandboxed
// CI cannot resolve modules offline.
func modGraph(t *testing.T) string {
	t.Helper()

	cmd := exec.Command("go", "list", "-deps", "-f", "{{.ImportPath}}", ".")

	out, err := cmd.Output()
	if err != nil {
		t.Skipf("cannot resolve module graph in this environment: %v", err)
	}

	return string(out)
}
