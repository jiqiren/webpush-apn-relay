package main

// Credential loading for APNs, extracted from main() so the branch selection can
// be tested.
//
// The reason this is a function returning an error instead of the inline if/else it
// replaced: every failure path in the original called log.Fatal, which calls
// os.Exit(1). A table test cannot observe a branch that terminates the process, so
// the obvious test - "which mode does an unreadable p8 report?" - was untestable,
// and the test that appeared to cover it only assigned the global and read it back.
// main() now does the log.Fatal on a returned error, so behaviour is unchanged and
// the chain becomes exercisable.
//
// apnsCredentials.Mode is what GET /status reports. It has exactly two values,
// "token" and "p12", because those are the only two states a *running* process can
// be in: every other path is fatal, so there is no "none" to report. The zero value
// is deliberately "" rather than a plausible-looking word — a process that got far
// enough to serve HTTP always has a real mode, so an empty authMode means
// something is genuinely wrong.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/sideshow/apns2"
	"github.com/sideshow/apns2/certificate"
	"github.com/sideshow/apns2/token"
)

// apnsCredentials is the outcome of the credential chain.
type apnsCredentials struct {
	development *apns2.Client
	production  *apns2.Client

	// mode is "token" or "p12".
	mode string

	// keyFingerprint is the first eight hex characters of the SHA-256 of the
	// material that identifies this deployment's credential: the DER of the p12
	// leaf certificate, or the DER of the parsed EC public key under token auth.
	//
	// It is a fingerprint, not an identifier: it answers "is this the key I think
	// it is?" when compared against a value computed locally from the same .p8, and
	// it cannot be used to sign anything. Unlike a Key ID it is derived from the
	// parsed key rather than quoted from configuration, so it cannot report the name
	// of a key the process failed to load.
	//
	// Cross-checking it does NOT work with `openssl x509 -fingerprint`, which hashes
	// the whole certificate and uses its own digest. For a .p12, extract the leaf and
	// hash its DER:
	//
	//	openssl pkcs12 -in cert.p12 -nokeys -noout -passin pass: \
	//	  | openssl x509 -outform der | openssl dgst -sha256 | cut -c10-17
	//
	// For a .p8, the value is SHA-256 over the uncompressed 0x04||X||P point; see
	// TestKeyFingerprintIsDerivedNotConfigured for a stdlib-only computation.
	//
	// The recipe above is verified, not assumed: it reproduces the endpoint's value
	// byte for byte against the test fixture.
	keyFingerprint string
}

// apnsCredentialConfig is the set of environment values the chain consults, passed
// in rather than read here so the function is pure with respect to the environment
// and the tests do not have to mutate process state.
type apnsCredentialConfig struct {
	tokenKeyFile string
	tokenKeyID   string
	tokenTeamID  string

	p12File     string
	p12Base64   string
	p12Password string
}

// loadAPNsCredentials picks a credential the same way main() always has: the token
// branch wins if TOKEN_AUTH_KEY_FILENAME is set, then P12_BASE64, then the p12 file
// on disk. First defined wins, and the p12 file path is the fallback because it has
// a default value and so is always "set".
//
// An error here is fatal to the process - the caller must not start serving without
// a client - but it is returned rather than logged and exited so the selection is
// observable in a test.
func loadAPNsCredentials(config apnsCredentialConfig) (apnsCredentials, error) {
	if config.tokenKeyFile != "" {
		authKey, err := token.AuthKeyFromFile(config.tokenKeyFile)
		if err != nil {
			return apnsCredentials{}, fmt.Errorf("loading token auth key %s: %w", config.tokenKeyFile, err)
		}

		// KeyID and TeamID are passed through to the signer but deliberately not
		// retained: they are configuration strings, and a status field quoting them
		// would name the exact key to attack. See apnsCredentials.keyFingerprint.
		signer := &token.Token{
			AuthKey: authKey,
			KeyID:   config.tokenKeyID,
			TeamID:  config.tokenTeamID,
		}

		return apnsCredentials{
			development:    apns2.NewTokenClient(signer).Development(),
			production:     apns2.NewTokenClient(signer).Production(),
			mode:           "token",
			keyFingerprint: fingerprintPublicKey(authKey),
		}, nil
	}

	var (
		p12bytes []byte
		source   = config.p12File
	)

	if config.p12Base64 != "" {
		decoded, err := base64.StdEncoding.DecodeString(config.p12Base64)
		if err != nil {
			return apnsCredentials{}, fmt.Errorf("decoding P12_BASE64: %w", err)
		}

		p12bytes = decoded
		source = "P12_BASE64"
	} else {
		read, err := os.ReadFile(config.p12File)
		if err != nil {
			return apnsCredentials{}, fmt.Errorf("loading certificate file: %w", err)
		}

		p12bytes = read
	}

	cert, err := certificate.FromP12Bytes(p12bytes, config.p12Password)
	if err != nil {
		return apnsCredentials{}, fmt.Errorf("parsing certificate from %s: %w", source, err)
	}

	return apnsCredentials{
		development:    apns2.NewClient(cert).Development(),
		production:     apns2.NewClient(cert).Production(),
		mode:           "p12",
		keyFingerprint: fingerprintCertificate(&cert),
	}, nil
}

// fingerprintPublicKey hashes the uncompressed SEC1 form of an EC public key, which
// is the 65-byte 0x04||X||P point the same way a VAPID key is written.
//
// The public key is hashed rather than anything derived from the private half, so
// the hash input is a public object by construction: there is no code path here that
// can turn into a hash of secret material, and anyone holding the .p8 can compute the
// same value to compare against the endpoint.
func fingerprintPublicKey(key *ecdsa.PrivateKey) string {
	if key == nil {
		return ""
	}

	return shortHash(uncompressedPoint(&key.PublicKey))
}

// uncompressedPoint returns the 0x04||X||P encoding of the point. elliptic.Marshal
// left-pads the coordinates to the field width, which is what makes the fingerprint
// stable for keys whose X or Y happens to have a leading zero byte.
func uncompressedPoint(key *ecdsa.PublicKey) []byte {
	return elliptic.Marshal(key.Curve, key.X, key.Y)
}

// fingerprintCertificate hashes the leaf certificate's DER, which is what a
// `openssl x509 -fingerprint` reports and so is comparable against a value taken
// from the .p12 without a second tool.
func fingerprintCertificate(cert *tls.Certificate) string {
	if cert == nil || cert.Leaf == nil || len(cert.Leaf.Raw) == 0 {
		return ""
	}

	return shortHash(cert.Leaf.Raw)
}

// shortHash is eight hex characters: enough to distinguish one key from another in
// a log line or a curl output, far too few to be a credential, and short enough that
// it is actually typed by hand when comparing two deployments.
func shortHash(material []byte) string {
	sum := sha256.Sum256(material)

	return hex.EncodeToString(sum[:])[:8]
}
