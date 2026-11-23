import Foundation
import CryptoKit

/// A push message body as it arrives from the relay in the `p` field of the
/// APNs payload: an RFC 8188 "aes128gcm" content coding, restricted for web
/// push by RFC 8291 section 4.
///
/// Unlike the older "aesgcm" encoding, nothing about this message travels in
/// HTTP headers. The salt and the application server's ECDH public key are the
/// first 86 octets of the body, which is why the relay only ever has the one
/// field to give us. RFC 8291 also permits exactly one record per push message,
/// so there is no record loop and no sequence number to track.
///
/// RFC 8291 section 7 requires a receiver to reject an application server public
/// key that is not on the P-256 curve; `serverPublicKey` is a
/// `P256.KeyAgreement.PublicKey`, so that check is performed by the initializer
/// rather than by us, and a forged or corrupt key fails here instead of yielding
/// a derivable-but-wrong shared secret.
struct Aes128GcmMessage {
	/// RFC 8188 section 2.1: salt || rs || idlen || keyid.
	static let headerLength = 16 + 4 + 1 + 65

	let salt: Data
	let serverPublicKey: P256.KeyAgreement.PublicKey
	let record: Data

	init(body: Data) throws {
		guard body.count > Self.headerLength else {
			throw PushNotificationReceiverErrorType.payloadTooShort(body.count)
		}

		salt = body[body.startIndex..<body.startIndex + 16]

		// RFC 8291 section 4: the keyid is always the 65-octet uncompressed
		// point, and nothing else. A different length is not a variant that
		// could be supported even in principle, because the derivation below
		// assumes that shape.
		let keyLength = body[body.startIndex + 20]
		guard keyLength == 65 else {
			throw PushNotificationReceiverErrorType.invalidKeyLength(Int(keyLength))
		}

		let keyStart = body.startIndex + 21
		guard let key = try? P256.KeyAgreement.PublicKey(
			x963Representation: body[keyStart..<keyStart + 65]) else {
			throw PushNotificationReceiverErrorType.invalidServerKey
		}
		serverPublicKey = key

		record = body[(body.startIndex + Self.headerLength)...]
	}
}

extension PushNotificationReceiver {
	/// Decrypts an aes128gcm push message, returning the plaintext.
	///
	/// `body` is the whole decoded `p` field, content-coding header included.
	///
	/// Unlike `decrypt(payload:salt:serverPublicKeyData:)`, this derives its
	/// keys with CryptoKit rather than Security. That is not a stylistic
	/// choice: the RFC's chain interleaves two HKDFs, feeding the Expand of the
	/// first into the Extract of the second, so neither CryptoKit's
	/// `hkdfDerivedSymmetricKey` nor the `deriveKey` helper used by the aesgcm
	/// path - which does one fused Extract-plus-Expand - can express it. Each
	/// step is a plain HMAC-SHA-256 instead, which is exactly how RFC 8291
	/// section 3.4 writes it out.
	func decryptAes128Gcm(body: Data) throws -> Data {
		let message = try Aes128GcmMessage(body: body)

		// `rawRepresentation` is the bare 32-octet scalar, so it wants
		// `privateKeyScalar`, not `privateKeyData`. Passing the stored blob whole
		// fails right here, and the failure is misleading: the key is valid, it is
		// the wrapper around it that CryptoKit does not recognise.
		guard let privateKey = try? P256.KeyAgreement.PrivateKey(rawRepresentation: privateKeyScalar) else {
			throw PushNotificationReceiverErrorType.invalidKey
		}

		// CryptoKit hands back the x-coordinate of the shared point, unpadded,
		// which is the ecdh_secret of RFC 8291 section 3.1 - 32 octets, as the
		// RFC's own Appendix A value is. A sender whose key is on the curve but
		// not the one this message was encrypted to fails later, at the tag.
		let ecdhSecret: Data
		do {
			ecdhSecret = try privateKey.sharedSecretFromKeyAgreement(with: message.serverPublicKey)
				.withUnsafeBytes { Data($0) }
		} catch {
			throw PushNotificationReceiverErrorType.keyExhangedFailed(error)
		}

		// key_info = "WebPush: info" || 0x00 || ua_public || as_public
		//
		// ua_public is taken from the private key rather than from the stored
		// publicKeyData, so that a receiver whose two halves have somehow
		// drifted apart fails the tag check instead of quietly deriving keys
		// that no sender can reproduce.
		var keyInfo = Data("WebPush: info".utf8)
		keyInfo.append(0x00)
		keyInfo.append(privateKey.publicKey.x963Representation)
		keyInfo.append(message.serverPublicKey.x963Representation)

		// HKDF-Extract(salt: auth_secret, IKM: ecdh_secret) followed by
		// HKDF-Expand(PRK_key, key_info, L_key: 32).
		//
		// RFC 8291 writes these as HMAC-SHA-256(key, message), which puts the
		// authentication secret in the key position. The order is easy to
		// reverse by habit and every value downstream then fails the tag check
		// with no other symptom.
		let prkKey = hmac(key: authentication, message: ecdhSecret)
		let ikm = hmac(key: prkKey, message: keyInfo + [0x01])

		// RFC 8188's own HKDF over the same salt, then the two Expand steps. The
		// record sequence number is zero for the only record there is, so the
		// nonce is not XORed with anything (RFC 8291 section 3.4, closing note).
		let prk = hmac(key: message.salt, message: ikm)
		let contentKey = hmac(key: prk, message: Data("Content-Encoding: aes128gcm".utf8) + [0x00, 0x01])
		let nonce = hmac(key: prk, message: Data("Content-Encoding: nonce".utf8) + [0x00, 0x01])

		guard message.record.count > 16 else {
			throw PushNotificationReceiverErrorType.invalidRecord
		}

		// RFC 8188: one AEAD_AES_128_GCM record, additional data zero-length,
		// tag in the trailing 16 octets. Failing here is the correct response
		// to anything not encrypted for this subscription, including a body
		// whose header parses and whose keys are simply not ours.
		let sealed: AES.GCM.SealedBox
		do {
			sealed = try AES.GCM.SealedBox(
				nonce: AES.GCM.Nonce(data: nonce.prefix(12)),
				ciphertext: message.record.dropLast(16),
				tag: message.record.suffix(16))
		} catch {
			throw PushNotificationReceiverErrorType.invalidRecord
		}

		guard let clearText = try? AES.GCM.open(
			sealed, using: SymmetricKey(data: contentKey.prefix(16))) else {
			throw PushNotificationReceiverErrorType.authenticationFailed
		}

		return try unpadAes128Gcm(clearText)
	}

	/// Splits the RFC 8188 padding off a decrypted record.
	///
	/// Padding is one or more zero octets followed by a single non-zero
	/// delimiter, so the padding runs back to the last octet that is not zero -
	/// and since the delimiter is itself part of the padding, it has to be
	/// included in that walk rather than assumed to be the boundary. An earlier
	/// version started one octet early, which was right only for a record with
	/// no padding at all: with padding present it left the delimiter behind as
	/// the final byte of the "plaintext", and the JSON decode then failed on the
	/// trailing garbage with nothing to indicate the padding was at fault.
	///
	/// RFC 8291 section 4 additionally requires the delimiter to be 0x02 and the
	/// message to be discarded otherwise. That check is deliberately last rather
	/// than first: it is only meaningful after the walk has located the
	/// delimiter, and a record of a single zero octet is a forgery attempt, not
	/// a decoding detail.
	func unpadAes128Gcm(_ clearText: Data) throws -> Data {
		var end = clearText.count
		while end > 0, clearText[clearText.startIndex + end - 1] == 0x00 {
			end -= 1
		}

		// Either the record is nothing but zero octets, or the walk stopped at the
		// delimiter. Only the second case has an octet to inspect.
		guard end > 0 else {
			throw PushNotificationReceiverErrorType.invalidPaddingDelimiter(0x00)
		}

		let delimiter = clearText[clearText.startIndex + end - 1]
		guard delimiter == 0x02 else {
			throw PushNotificationReceiverErrorType.invalidPaddingDelimiter(delimiter)
		}

		return clearText[clearText.startIndex..<clearText.startIndex + end - 1]
	}

	private func hmac(key: Data, message: some DataProtocol) -> Data {
		Data(HMAC<SHA256>.authenticationCode(for: message, using: SymmetricKey(data: key)))
	}
}

extension PushNotificationReceiver {
	/// The 32-octet scalar CryptoKit wants, taken from `privateKeyData`.
	///
	/// The two representations differ by an eight-octet header. A key created
	/// by `PushNotificationReceiver.init()` comes out of
	/// `SecKeyCopyExternalRepresentation` as 72 octets: an unprotected PKCS#8
	/// wrapper (`04 21 30 13 06 07 2A 86 48 CE 3D 02 01 06 08 2A 86 48 CE 3D 03 01 07`),
	/// then a `04 20` OCTET STRING marker, then the scalar. The aesgcm path
	/// never notices because it hands the whole blob back to Security. The
	/// tail is the same value in either layout, so taking the last 32 octets
	/// covers keys the app generated itself and keys imported as a bare
	/// scalar.
	var privateKeyScalar: Data {
		guard privateKeyData.count >= 32 else {
			return privateKeyData
		}

		return privateKeyData.suffix(32)
	}
}
