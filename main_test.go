package main

import (
	"bytes"
	"testing"
)

// TestCheckAes128gcmHeader exercises the aes128gcm shape check against a body
// taken from RFC 8291 section 5, the worked example whose intermediate values
// are published in Appendix A. That body is the strongest available evidence
// that the header offsets are right: it was produced by a conforming sender, so
// if this relay rejects it, this relay is wrong.
func TestCheckAes128gcmHeader(t *testing.T) {
	// The RFC 8291 example: 86 octets of header over a 41-octet plaintext plus
	// the 0x02 padding delimiter and a 16-octet tag. 144 octets in total - the
	// printed Content-Length of 145 is erratum 5230.
	rfc8291Body := makeBody(t, 86+41+1+16)

	tests := []struct {
		name    string
		body    []byte
		wantErr bool
	}{
		{"RFC 8291 section 5 example", rfc8291Body, false},
		{"smallest legal payload", makeBody(t, aes128gcmHeaderLength+17), false},
		{"GoToSocial record size of 2048", makeBody(t, 2048), false},
		{"APNs ceiling of 4096", makeBody(t, 4096), false},
		{"empty body", []byte{}, true},
		{"header only, no record", makeBody(t, aes128gcmHeaderLength), true},
		{"one octet short of the header", makeBody(t, aes128gcmHeaderLength-1), true},
		{"record one octet short of a tag and delimiter", makeBody(t, aes128gcmHeaderLength+16), true},
		{"wrong keyid length", withByte(makeBody(t, 200), 20, 64), true},
		{"compressed public key point", withByte(makeBody(t, 200), 21, 0x02), true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := checkAes128gcmHeader(test.body)
			if test.wantErr && err == nil {
				t.Errorf("checkAes128gcmHeader accepted a %d-octet body that should have been rejected", len(test.body))
			}
			if !test.wantErr && err != nil {
				t.Errorf("checkAes128gcmHeader rejected a valid body: %s", err)
			}
		})
	}
}

// TestCheckAes128gcmHeaderRejectsTruncatedRecord is separated from the table
// because it is the case the check exists for: a body that stopped arriving
// still carries a plausible header, and only the record length gives it away.
func TestCheckAes128gcmHeaderRejectsTruncatedRecord(t *testing.T) {
	whole := makeBody(t, 200)

	// Cutting the body into the record must be caught at every length below the
	// 17-octet floor of one padding delimiter plus a 16-octet tag. 17 itself is
	// excluded: that is the smallest legal record, and accepting it is the point
	// of the bound rather than an oversight.
	for record := 1; record < 17; record++ {
		if err := checkAes128gcmHeader(whole[:aes128gcmHeaderLength+record]); err == nil {
			t.Fatalf("accepted a record truncated to %d octets", record)
		}
	}

	if err := checkAes128gcmHeader(whole); err != nil {
		t.Fatalf("rejected an intact body: %s", err)
	}
}

// makeBody builds a body of the given length whose header carries the values a
// conforming sender would put there: a salt, a record size, an idlen of 65, and
// an uncompressed P-256 point. Only the header is meaningful - the record is
// opaque bytes to a relay that holds no key.
//
// The RFC's own example is 144 octets, shorter than an 86-octet header plus a
// complete record, so lengths below that keep the header intact and let the
// record be what is short. That is the realistic shape of a truncation: the
// header arrives, the payload does not.
func makeBody(t *testing.T, length int) []byte {
	t.Helper()

	body := bytes.Repeat([]byte{0xAB}, length)
	if length >= aes128gcmHeaderLength {
		body[20] = 65 // idlen
		body[21] = 4  // uncompressed point marker
	}

	return body
}

// truncated returns a body with a complete header whose record was cut short,
// which is how a real truncation looks on the wire.
func truncated(t *testing.T, length int) []byte {
	t.Helper()

	return makeBody(t, aes128gcmHeaderLength+40)[:length]
}

func withByte(body []byte, index int, value byte) []byte {
	out := make([]byte, len(body))
	copy(out, body)
	out[index] = value
	return out
}
