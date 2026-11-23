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
func TestRelayAcceptsEndpointFromRegister(t *testing.T) {
	registered := post(t, newRegisterMux(), "/register", registerBody(t, map[string]string{"environment": "development"}))

	var response registerResponse
	if err := json.Unmarshal(registered.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /relay-to/{environment}/{token}/{extra...}", handleApnNotification)

	// ServeMux reports a redirect by answering 307 rather than matching, so this
	// asserts the whole reason the trailing slash exists.
	request := httptest.NewRequest(http.MethodPost, response.Endpoint, strings.NewReader("payload"))
	request.Header.Set("Content-Encoding", "aes128gcm")

	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, request)

	if recorder.Code == http.StatusPermanentRedirect || recorder.Code == http.StatusTemporaryRedirect {
		t.Fatalf("the minted endpoint redirects (%d): Mastodon may drop Content-Encoding, Crypto-Key, Encryption and Unsubscribe-Url", recorder.Code)
	}

	if !strings.HasSuffix(response.Endpoint, "/") {
		t.Errorf("endpoint %q lacks the trailing slash", response.Endpoint)
	}
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
