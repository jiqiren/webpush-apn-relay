package main

// Tests for GET /status and for the credential chain it reports.
//
// Two things are being tested here, and they are different in kind:
//
//   - loadAPNsCredentials is tested by *running the branch selection* over real key
//     material, because the mode /status reports is only trustworthy if the chain
//     that sets it has been exercised. The previous version of this file assigned
//     apnsAuthMode and asserted the handler echoed it back, which tested the JSON
//     encoder and proved nothing about which branch wins.
//   - handleStatus is tested for what it must not do: it is reachable from the
//     public internet, so its field set is pinned and each field is tied to the one
//     global it may read.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	goPKCS12 "software.sslmate.com/src/go-pkcs12"
)

// Credential fixtures, generated per run rather than committed: a committed .p12 or
// .p8 in a repository is a finding regardless of whether it works.
type credentialFixtures struct {
	p8Path      string // a valid PKCS#8 EC key in PEM, the shape Apple ships
	badP8Path   string // exists, but is not a key
	p12Path     string // a valid p12 with an empty password
	badP12Path  string // exists, but is not a p12
	p12Bytes    []byte
	missingPath string // deliberately never created
}

func newCredentialFixtures(t *testing.T) credentialFixtures {
	t.Helper()

	dir := t.TempDir()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "relay-test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		IsCA:         true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	p8Path := filepath.Join(dir, "auth.p8")
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	writeFixture(t, p8Path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8}))

	// The p12 must use the legacy SHA-1/PBE-SHA1-3DES ciphers apns2's decoder
	// understands; a modern OpenSSL 3+ export fails with "unknown digest algorithm",
	// which is a property of the decoder, not of this test.
	p12Bytes, err := encodeP12(key, &x509.Certificate{Raw: der})
	if err != nil {
		t.Fatalf("encode p12: %v", err)
	}

	p12Path := filepath.Join(dir, "cert.p12")
	writeFixture(t, p12Path, p12Bytes)

	badP8Path := filepath.Join(dir, "bad.p8")
	writeFixture(t, badP8Path, []byte("this is not a PEM key\n"))

	badP12Path := filepath.Join(dir, "bad.p12")
	writeFixture(t, badP12Path, []byte("this is not a p12\n"))

	return credentialFixtures{
		p8Path:      p8Path,
		badP8Path:   badP8Path,
		p12Path:     p12Path,
		badP12Path:  badP12Path,
		p12Bytes:    p12Bytes,
		missingPath: filepath.Join(dir, "absent.p12"),
	}
}

func writeFixture(t *testing.T, path string, content []byte) {
	t.Helper()

	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// TestCredentialChainSelectsMode is the test whose predecessor was a lie.
//
// It runs the real chain over real material and asserts the reported mode, so the
// claim "/status reports which branch won" is checked rather than asserted. Note what
// the table proves about the old "none": there is no row that produces it, because
// every path that does not build a client returns an error and the process dies.
func TestCredentialChainSelectsMode(t *testing.T) {
	fixture := newCredentialFixtures(t)

	tests := []struct {
		name string
		// config builds a fresh value per case, so a case cannot inherit another's.
		config func() apnsCredentialConfig
		// wantErr is matched against the returned error, which must be non-nil
		// exactly when wantErr is true.
		wantErr bool
		errText string
		mode    string
		// fingerprint asserts a non-empty fingerprint when true, and "" when false.
		fingerprint bool
	}{
		{
			name: "valid p8 selects token",
			config: func() apnsCredentialConfig {
				return apnsCredentialConfig{tokenKeyFile: fixture.p8Path, tokenKeyID: "KEYID", tokenTeamID: "TEAMID"}
			},
			mode:        "token",
			fingerprint: true,
		},
		{
			name: "unreadable p8 path is an error, not a silent fallback",
			config: func() apnsCredentialConfig {
				return apnsCredentialConfig{tokenKeyFile: fixture.badP8Path}
			},
			wantErr:     true,
			errText:     "loading token auth key",
			fingerprint: false,
		},
		{
			name: "missing p8 path is an error",
			config: func() apnsCredentialConfig {
				return apnsCredentialConfig{tokenKeyFile: fixture.missingPath}
			},
			wantErr: true,
			errText: "loading token auth key",
		},
		{
			name: "valid p12 bytes select p12",
			config: func() apnsCredentialConfig {
				return apnsCredentialConfig{p12Base64: base64.StdEncoding.EncodeToString(fixture.p12Bytes)}
			},
			mode:        "p12",
			fingerprint: true,
		},
		{
			name: "undecodable p12 base64 is an error",
			config: func() apnsCredentialConfig {
				return apnsCredentialConfig{p12Base64: "!!!not base64!!!"}
			},
			wantErr: true,
			errText: "decoding P12_BASE64",
		},
		{
			name: "bad p12 bytes are an error",
			config: func() apnsCredentialConfig {
				return apnsCredentialConfig{p12Base64: base64.StdEncoding.EncodeToString([]byte("not a p12"))}
			},
			wantErr: true,
			errText: "parsing certificate",
		},
		{
			name: "valid p12 file selects p12",
			config: func() apnsCredentialConfig {
				return apnsCredentialConfig{p12File: fixture.p12Path}
			},
			mode:        "p12",
			fingerprint: true,
		},
		{
			name: "missing p12 file is an error",
			config: func() apnsCredentialConfig {
				return apnsCredentialConfig{p12File: fixture.missingPath}
			},
			wantErr: true,
			errText: "loading certificate file",
		},
		{
			name: "bad p12 file is an error",
			config: func() apnsCredentialConfig {
				return apnsCredentialConfig{p12File: fixture.badP12Path}
			},
			wantErr: true,
			errText: "parsing certificate",
		},
		{
			// The precedence rule the relay has always had: a set
			// TOKEN_AUTH_KEY_FILENAME wins even when p12 material is also present.
			name: "token wins over p12 when both are configured",
			config: func() apnsCredentialConfig {
				return apnsCredentialConfig{
					tokenKeyFile: fixture.p8Path,
					p12Base64:    base64.StdEncoding.EncodeToString(fixture.p12Bytes),
				}
			},
			mode:        "token",
			fingerprint: true,
		},
		{
			// The regression this row exists for: a set-but-unreadable p8 must not
			// quietly become p12 auth. If this ever returns mode "p12" with no error,
			// the relay is signing with a certificate nobody configured.
			name: "broken token config does not fall through to p12",
			config: func() apnsCredentialConfig {
				return apnsCredentialConfig{
					tokenKeyFile: fixture.badP8Path,
					p12File:      fixture.p12Path,
				}
			},
			wantErr: true,
			errText: "loading token auth key",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			credentials, err := loadAPNsCredentials(tc.config())

			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got mode %q", credentials.mode)
				}

				if tc.errText != "" && !strings.Contains(err.Error(), tc.errText) {
					t.Errorf("error %q does not mention %q", err, tc.errText)
				}

				// A failed load must report nothing, not a zero-value mode that a
				// caller could mistake for a real one.
				if credentials.mode != "" {
					t.Errorf("mode = %q on error, want the empty string", credentials.mode)
				}

				if credentials.development != nil || credentials.production != nil {
					t.Error("a failed load returned clients")
				}

				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if credentials.mode != tc.mode {
				t.Errorf("mode = %q, want %q", credentials.mode, tc.mode)
			}

			// Both environments must exist: a nil production client is a nil-pointer
			// panic on the first production push, hours after startup.
			if credentials.development == nil || credentials.production == nil {
				t.Error("expected both development and production clients")
			}

			if tc.fingerprint && credentials.keyFingerprint == "" {
				t.Error("expected a key fingerprint")
			}

			if !tc.fingerprint && credentials.keyFingerprint != "" {
				t.Errorf("fingerprint = %q on a failed load, want empty", credentials.keyFingerprint)
			}
		})
	}
}

// TestAuthModeHasNoNone is a regression test on a name.
//
// "none" used to be both the zero value and the label for the p12-file branch, which
// made it read as "no credential loaded" when it meant the opposite. The value must
// not be reachable from any branch, and the zero value must be "" so that an
// uninitialised mode is visibly broken rather than plausible.
func TestAuthModeHasNoNone(t *testing.T) {
	fixture := newCredentialFixtures(t)

	configs := map[string]apnsCredentialConfig{
		"token":      {tokenKeyFile: fixture.p8Path},
		"p12-base64": {p12Base64: base64.StdEncoding.EncodeToString(fixture.p12Bytes)},
		"p12-file":   {p12File: fixture.p12Path},
	}

	for name, config := range configs {
		credentials, err := loadAPNsCredentials(config)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}

		if credentials.mode == "none" {
			t.Errorf("%s reports mode %q; none must not be a value", name, credentials.mode)
		}

		if credentials.mode != "token" && credentials.mode != "p12" {
			t.Errorf("%s reports mode %q, want token or p12", name, credentials.mode)
		}
	}

	// The zero value: what a handler would report if main() somehow served before
	// assigning. Empty, so it cannot be mistaken for a mode.
	var zero apnsCredentials

	if zero.mode != "" {
		t.Errorf("zero value mode = %q, want the empty string", zero.mode)
	}
}

// TestKeyFingerprintIsDerivedNotConfigured pins the two properties that make the
// fingerprint safe to publish: it is a function of the loaded key, and it is short.
func TestKeyFingerprintIsDerivedNotConfigured(t *testing.T) {
	fixture := newCredentialFixtures(t)

	credentials, err := loadAPNsCredentials(apnsCredentialConfig{tokenKeyFile: fixture.p8Path, tokenKeyID: "IGNORED", tokenTeamID: "IGNORED"})
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// Same key, different configured Key ID: the fingerprint must not move, because
	// it is computed from the parsed key and not quoted from configuration. This is
	// the difference between a fingerprint and an identifier.
	reloaded, err := loadAPNsCredentials(apnsCredentialConfig{tokenKeyFile: fixture.p8Path, tokenKeyID: "OTHER", tokenTeamID: "OTHER"})
	if err != nil {
		t.Fatalf("reload: %v", err)
	}

	if credentials.keyFingerprint != reloaded.keyFingerprint {
		t.Errorf("fingerprint changed with the configured Key ID: %q vs %q", credentials.keyFingerprint, reloaded.keyFingerprint)
	}

	if len(credentials.keyFingerprint) != 8 {
		t.Errorf("fingerprint %q is %d chars, want 8 hex", credentials.keyFingerprint, len(credentials.keyFingerprint))
	}

	if _, err := hex.DecodeString(credentials.keyFingerprint); err != nil {
		t.Errorf("fingerprint %q is not hex: %v", credentials.keyFingerprint, err)
	}

	// It must match a value computed independently from the key file, which is the
	// whole point: an operator verifies it locally without trusting this binary.
	key := readFixtureKey(t, fixture.p8Path)

	sum := sha256.Sum256(elliptic.Marshal(elliptic.P256(), key.X, key.Y))
	if want := hex.EncodeToString(sum[:])[:8]; want != credentials.keyFingerprint {
		t.Errorf("fingerprint = %q, want %q computed from the .p8 public key", credentials.keyFingerprint, want)
	}

	// A different key must give a different fingerprint, or the field is a constant.
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}

	if shortHash(elliptic.Marshal(elliptic.P256(), otherKey.X, otherKey.Y)) == credentials.keyFingerprint {
		t.Error("two distinct keys share a fingerprint")
	}
}

// readFixtureKey parses the fixture the way an operator would, with the standard
// library only. The point is independence: if the fingerprint were computed by some
// helper this file also uses, agreeing with it would prove nothing.
func readFixtureKey(t *testing.T, path string) *ecdsa.PrivateKey {
	t.Helper()

	contents, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	block, _ := pem.Decode(contents)
	if block == nil {
		t.Fatal("fixture is not PEM")
	}

	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse fixture: %v", err)
	}

	key, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("fixture is %T, want *ecdsa.PrivateKey", parsed)
	}

	return key
}

// statusGlobals saves and restores the package-level configuration the handler
// reports, so a test that sets them cannot leak state into a later one. These
// globals exist because main() initialises them once; the tests are the only place
// that mutates them.
func statusGlobals(t *testing.T, mutate func()) {
	t.Helper()

	previous := struct {
		topic, mode, fingerprint, ca string
	}{topic, apnsAuthMode, apnsKeyFingerprint, caFilenameResolved}

	t.Cleanup(func() {
		topic, apnsAuthMode, apnsKeyFingerprint, caFilenameResolved =
			previous.topic, previous.mode, previous.fingerprint, previous.ca
	})

	mutate()
}

func getStatus(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()

	request := httptest.NewRequest(http.MethodGet, "/status", nil)
	recorder := httptest.NewRecorder()

	handleStatus(recorder, request)

	return recorder
}

func decodeStatus(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()

	var fields map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &fields); err != nil {
		t.Fatalf("response is not a JSON object: %v (body %s)", err, recorder.Body)
	}

	return fields
}

func TestStatusReportsEvaluatedConfig(t *testing.T) {
	statusGlobals(t, func() {
		topic = "ninja.dusty.seloi.Seloi"
		apnsAuthMode = "token"
		apnsKeyFingerprint = "a1b2c3d4"
		caFilenameResolved = "/cas.crt"
	})

	recorder := getStatus(t)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}

	if got := recorder.Header().Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", got)
	}

	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", got)
	}

	fields := decodeStatus(t, recorder)

	for key, want := range map[string]string{
		"topic":          "ninja.dusty.seloi.Seloi",
		"authMode":       "token",
		"keyFingerprint": "a1b2c3d4",
		"caFilename":     "/cas.crt",
	} {
		if got, ok := fields[key]; !ok {
			t.Errorf("%s missing from response", key)
		} else if got != want {
			t.Errorf("%s = %v, want %q", key, got, want)
		}
	}

	// uptimeSeconds is a number, and the field must exist even at zero - an
	// omitted field is indistinguishable from a broken build.
	if uptime, ok := fields["uptimeSeconds"].(float64); !ok || uptime < 0 {
		t.Errorf("uptimeSeconds = %v, want a non-negative number", fields["uptimeSeconds"])
	}

	// The field set is pinned. A new field is a disclosure decision on a public
	// endpoint, and this is where it has to be argued rather than smuggled in.
	want := []string{"authMode", "caFilename", "keyFingerprint", "topic", "uptimeSeconds", "version"}

	if len(fields) != len(want) {
		t.Errorf("response has %d fields %v, want exactly %v", len(fields), keysOf(fields), want)
	}

	for _, name := range want {
		if _, ok := fields[name]; !ok {
			t.Errorf("field %s missing", name)
		}
	}

	// And the two fields that were removed stay removed. Asserted explicitly because
	// "absent" is the property, and the length check above would pass if one came
	// back and one went away.
	for _, removed := range []string{"keyId", "teamId"} {
		if _, ok := fields[removed]; ok {
			t.Errorf("%s is present: it names a specific key on an unauthenticated endpoint", removed)
		}
	}
}

// TestStatusAuthModeEmptyWhenUnset checks the zero value, which is the state a
// process would be in if it served before loadAPNsCredentials assigned.
//
// This is not a "no credential" state - that process does not exist, since every
// credential failure is fatal - which is exactly why the value is "" and not "none":
// "none" would describe a state that cannot happen and hide the one that can.
func TestStatusAuthModeEmptyWhenUnset(t *testing.T) {
	statusGlobals(t, func() { apnsAuthMode = "" })

	fields := decodeStatus(t, getStatus(t))

	if fields["authMode"] != "" {
		t.Errorf("authMode = %v, want the empty string", fields["authMode"])
	}

	if fields["authMode"] == "none" {
		t.Error("authMode is none, which is not a mode")
	}
}

// TestStatusLeavesOutKeyMaterial is the reason this endpoint can be public.
//
// The scan is structural rather than a substring grep for secret-looking text: the
// allowed field set is pinned, each field is checked against the global it derives
// from, and the response is confirmed not to grow with the size of the material the
// process holds. A word-list grep would pass while a future field leaked a key, and
// would fail on a legitimate caFilename.
func TestStatusLeavesOutKeyMaterial(t *testing.T) {
	fixture := newCredentialFixtures(t)

	// The real credential is loaded through the real chain, so the material whose
	// absence is being asserted is genuinely in this process's memory, not a
	// stand-in that was never reachable in the first place.
	credentials, err := loadAPNsCredentials(apnsCredentialConfig{
		tokenKeyFile: fixture.p8Path,
		tokenKeyID:   "2B222HKZW9",
		tokenTeamID:  "J6P2RN2GUP",
	})
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	p8Contents, err := os.ReadFile(fixture.p8Path)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}

	statusGlobals(t, func() {
		apnsAuthMode = credentials.mode
		apnsKeyFingerprint = credentials.keyFingerprint
		caFilenameResolved = "/cas.crt"
	})

	recorder := getStatus(t)
	body := recorder.Body.String()
	fields := decodeStatus(t, recorder)

	// The fields /status may report, and the only globals it reads. Anything else in
	// the response is a disclosure that has not been reviewed.
	derived := map[string]string{
		"topic":          "topic",
		"authMode":       "apnsAuthMode",
		"keyFingerprint": "apnsKeyFingerprint",
		"caFilename":     "caFilenameResolved",
		"version":        "envVersion",
	}

	for name := range fields {
		if _, ok := derived[name]; ok || name == "uptimeSeconds" {
			continue
		}

		t.Errorf("response carries %q, which maps to no reviewed global", name)
	}

	// The credential material must not be reachable from the handler at all. Today
	// it is not: the p8 bytes, the parsed key, the p12 bytes and the password are
	// locals inside loadAPNsCredentials. That holds only until someone hoists one to
	// package scope, which is what this checks for.
	if leaked := unreachableSecretGlobals(); len(leaked) > 0 {
		t.Errorf("main.go now holds credential material at package scope %v; handleStatus must not be able to read it", leaked)
	}

	// A response that grows with the credential is the shape of a leak.
	if len(body) > 512 {
		t.Errorf("status response is %d bytes, far more than six short fields: %s", len(body), body)
	}

	// The configured identifiers must not appear even though they were supplied to
	// the loader: they are configuration, and configuration is not safe to publish.
	for _, forbidden := range []string{"2B222HKZW9", "J6P2RN2GUP"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("response leaks the configured identifier %s: %s", forbidden, body)
		}
	}

	// Nor the key itself, in any encoding a buggy handler might have reached for.
	for _, probe := range []string{
		string(p8Contents[:24]),
		base64.StdEncoding.EncodeToString(p8Contents[:24]),
		base64.StdEncoding.EncodeToString(fixture.p12Bytes[:24]),
	} {
		if strings.Contains(body, probe) {
			t.Errorf("response contains credential material: %s", body)
		}
	}

	// The fingerprint is present and is not the key: eight hex characters cannot be
	// reversed, and this checks it is not accidentally carrying raw material.
	if fp, ok := fields["keyFingerprint"].(string); !ok || len(fp) != 8 {
		t.Errorf("keyFingerprint = %v, want 8 characters", fields["keyFingerprint"])
	}
}

func TestStatusVersionComesFromDDVersion(t *testing.T) {
	previous := envVersion

	t.Cleanup(func() { envVersion = previous })
	statusGlobals(t, func() {})

	envVersion = "v0.9.2"

	if got := decodeStatus(t, getStatus(t))["version"]; got != "v0.9.2" {
		t.Errorf("version = %v, want v0.9.2 (DD_VERSION)", got)
	}

	// Unset must be "" and not a guess: userAgent() substitutes "dev" for its own
	// purposes, and /status reporting "dev" would hide a missing build stamp.
	envVersion = ""

	if got := decodeStatus(t, getStatus(t))["version"]; got != "" {
		t.Errorf("version = %v, want the empty string when DD_VERSION is unset", got)
	}
}

// TestStatusDoesNotCollideWithRelayTree guards the routing: /status must not be
// swallowed by the /relay-to/ catch-all, and must not shadow the health check.
func TestStatusDoesNotCollideWithRelayTree(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /relay-to/{environment}/{token}/{extra...}", handleApnNotification)
	mux.HandleFunc("GET /relay-to/_health", handleHealthCheck)
	mux.HandleFunc("GET /status", handleStatus)

	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/status", http.StatusOK},
		{http.MethodGet, "/relay-to/_health", http.StatusOK},
		{http.MethodGet, "/relay-to/production/deadbeef/", http.StatusMethodNotAllowed},
	} {
		request := httptest.NewRequest(tc.method, tc.path, nil)
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, request)

		if recorder.Code != tc.want {
			t.Errorf("%s %s = %d, want %d", tc.method, tc.path, recorder.Code, tc.want)
		}
	}

	// /status must answer GET with JSON even though the push handler is a
	// catch-all over one tree: a body of "OK" here means the wrong handler won.
	request := httptest.NewRequest(http.MethodGet, "/status", nil)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, request)

	if !strings.HasPrefix(recorder.Body.String(), "{") {
		t.Errorf("body = %q, want a JSON object", recorder.Body.String())
	}
}

func keysOf(m map[string]any) []string {
	var out []string

	for k := range m {
		out = append(out, k)
	}

	return out
}

// unreachableSecretGlobals reads main.go and reports package-level variables whose
// names suggest they hold credential material.
//
// This is a source-level guard, which is unusual, and the reason is that the property
// it protects is invisible to a runtime test: the handler cannot leak the p8 or the
// p12 because they are locals inside loadAPNsCredentials and main(). That holds only
// for as long as nobody hoists one to package scope, and the day someone does, no
// amount of handler testing will notice. Checking the source is the only way to fail
// that change.
func unreachableSecretGlobals() []string {
	source, err := readFileForTest("main.go")
	if err != nil {
		return nil
	}

	var leaked []string

	for _, name := range credentialNames {
		if declaredAtPackageScope(source, name) {
			leaked = append(leaked, name)
		}
	}

	return leaked
}

// credentialNames are the identifiers a hoisted credential would plausibly use. The
// list is a heuristic and is deliberately paired with the structural checks above,
// which do not depend on naming.
var credentialNames = []string{
	"authKey", "signingKey", "tokenSignKey", "p12bytes", "p12Bytes", "p12password",
	"p12base64", "privateKey", "tlsKeyContents", "certBytes", "p12Password",
}

// declaredAtPackageScope reports whether name appears as a declaration at column zero
// or inside the top-level var block. Uses inside functions are indented, so an
// indented occurrence is not a package-scope declaration.
func declaredAtPackageScope(source, name string) bool {
	for _, line := range strings.Split(source, "\n") {
		if strings.HasPrefix(line, "var "+name+" ") || strings.HasPrefix(line, "var "+name+"=") {
			return true
		}
	}

	start := strings.Index(source, "var (")
	if start < 0 {
		return false
	}

	block := source[start:]
	if end := strings.Index(block, "\n)"); end > 0 {
		block = block[:end]
	}

	for _, line := range strings.Split(block, "\n") {
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, name+" ") || strings.HasPrefix(trimmed, name+"=") {
			return true
		}
	}

	return false
}

// encodeP12 writes a p12 in the encoding apns2's decoder can read.
//
// This is not a convenience. A modern `openssl pkcs12 -export` (OpenSSL 3.x/4.x
// defaults) produces AES-256-CBC/PBKDF2 with SHA-256 MACs, and golang.org/x/crypto/
// pkcs12 - the decoder apns2 v0.25.0 uses - rejects it with
// "pkcs12: unknown digest algorithm: 2.16.840.1.101.3.4.2.1". Verified on this
// machine, not assumed. So the fixture has to be built with the legacy encoder,
// which is also what Apple's own exported .p12 files have historically used.
//
// go-pkcs12 is used only from tests, so it stays an indirect dependency of the
// module rather than something the shipped binary carries.
func encodeP12(key *ecdsa.PrivateKey, cert *x509.Certificate) ([]byte, error) {
	return goPKCS12.LegacyDES.Encode(key, cert, nil, "")
}
