import Foundation

private let DecodeTable: [UInt32] = [
	0xff, 0x44, 0xff, 0x54, 0x53, 0x52, 0x48, 0xff,
	0x4b, 0x4c, 0x46, 0x41, 0xff, 0x3f, 0x3e, 0x45,
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x40, 0xff, 0x49, 0x42, 0x4a, 0x47,
	0x51, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a,
	0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32,
	0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a,
	0x3b, 0x3c, 0x3d, 0x4d, 0xff, 0x4e, 0x43, 0xff,
	0xff, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
	0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
	0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
	0x21, 0x22, 0x23, 0x4f, 0xff, 0x50, 0xff, 0xff
]

extension String {
	/// Decodes z85 extended to arbitrary lengths, the format `encode85` in the
	/// relay's main.go produces.
	///
	/// Unlike the base64 case, a trailing partial group is not a multiple of
	/// five characters: n bytes are encoded as n + 1 characters, so a body
	/// whose length is not a multiple of four ends in two, three or four
	/// characters. `n` is therefore the size of the pending group and must be
	/// reset when a group is emitted. It was not, which left the counter at
	/// four for every body of length 4k+1, 4k+2 or 4k+3 - one quarter of all
	/// payloads, since a push body's length is essentially arbitrary - and the
	/// tail was then decoded as though four characters had been pending. The
	/// first 4k octets came out right, so the AEAD tag was what reported it,
	/// as an authentication failure with nothing to point at the decoder.
	func decode85() -> Data {
		var data = Data()
		var block: UInt32 = 0
		var pending = 0

		for c in utf8 {
			guard c >= 32, c < 128, DecodeTable[Int(c - 32)] != 0xff else {
				continue
			}

			block = block &* 85 &+ DecodeTable[Int(c - 32)]
			pending += 1

			if pending == 5 {
				data.append(UInt8(block >> 24))
				data.append(UInt8((block >> 16) & 0xff))
				data.append(UInt8((block >> 8) & 0xff))
				data.append(UInt8(block & 0xff))
				block = 0
				pending = 0
			}
		}

		// A partial group holds fewer than four octets, so the accumulated value
		// is under 2^32 by construction: encode85 emits n + 1 characters for n
		// octets, and the largest four-character group is 85^4 - 1, which is
		// what a full group needs. The overflowing arithmetic the old code could
		// hit - a sixth character accumulating onto a full group's value, which
		// is a trap in a debug build - was a symptom of the same lost reset.
		switch pending {
		case 2: data.append(UInt8(block & 0xff))
		case 3: data.append(UInt8((block >> 8) & 0xff)); data.append(UInt8(block & 0xff))
		case 4: data.append(UInt8((block >> 16) & 0xff)); data.append(UInt8((block >> 8) & 0xff)); data.append(UInt8(block & 0xff))
		default: break
		}

		return data
	}
}
