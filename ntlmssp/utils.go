package ntlmssp

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"hash/crc32"
)

// With Extended Session Security
func mac(dst []byte, negotiateFlags uint32, handle *rc4.Cipher, signingKey []byte, seqNum uint32, msg []byte) ([]byte, uint32) {
	ret, tag := sliceForAppend(dst, 16)
	if negotiateFlags&FlgNegExtendedSessionSecurity == 0 {
		binary.LittleEndian.PutUint32(tag[:4], 0x00000001)
		binary.LittleEndian.PutUint32(tag[8:12], crc32.ChecksumIEEE(msg))
		handle.XORKeyStream(tag[4:8], tag[4:8])
		handle.XORKeyStream(tag[8:12], tag[8:12])
		handle.XORKeyStream(tag[12:16], tag[12:16])
		tag[12] ^= byte(seqNum)
		tag[13] ^= byte(seqNum >> 8)
		tag[14] ^= byte(seqNum >> 16)
		tag[15] ^= byte(seqNum >> 24)
		if negotiateFlags&FlgNegDatagram == 0 {
			seqNum++
		}
		tag[4] = 0
		tag[5] = 0
		tag[6] = 0
		tag[7] = 0
	} else {
		binary.LittleEndian.PutUint32(tag[:4], 0x00000001)
		binary.LittleEndian.PutUint32(tag[12:16], seqNum)
		h := hmac.New(md5.New, signingKey)
		h.Write(tag[12:16])
		h.Write(msg)
		copy(tag[4:12], h.Sum(nil))
		//copy(ms.Checksum, h.Sum(nil))
		//tag = ms.Bytes()
		if negotiateFlags&FlgNegKeyExch != 0 {
			handle.XORKeyStream(tag[4:12], tag[4:12])
		}
		seqNum++
	}

	return ret, seqNum
}

// Give me a slice that is of size n. Either increment or decrement the argument "in" to that end.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	tail = head[len(in):]
	return
}

func signKey(negotiateFlags uint32, randomSessionKey []byte, fromCLient bool) []byte {
	if negotiateFlags&FlgNegExtendedSessionSecurity != 0 {
		h := md5.New()
		h.Write(randomSessionKey)
		if fromCLient {
			h.Write([]byte("session key to client-to-server signing key magic constant\x00"))
		} else {
			h.Write([]byte("session key to server-to-client signing key magic constant\x00"))
		}
		return h.Sum(nil)
	}
	return nil
}

func sealKey(negotiateFlags uint32, randomSessionKey []byte, fromCLient bool) []byte {
	if negotiateFlags&FlgNegExtendedSessionSecurity != 0 {
		h := md5.New()
		switch {
		case negotiateFlags&FlgNeg128 != 0:
			h.Write(randomSessionKey)
		case negotiateFlags&FlgNeg56 != 0:
			h.Write(randomSessionKey[:7])
		default:
			h.Write(randomSessionKey[:5])
		}

		if fromCLient {
			h.Write([]byte("session key to client-to-server sealing key magic constant\x00"))
		} else {
			h.Write([]byte("session key to server-to-client sealing key magic constant\x00"))
		}
		return h.Sum(nil)
	}

	if negotiateFlags&FlgNegLmKey != 0 {
		sealingKey := make([]byte, 8)
		if negotiateFlags&FlgNeg56 != 0 {
			copy(sealingKey, randomSessionKey[:7])
			sealingKey[7] = 0xa0
		} else {
			copy(sealingKey, randomSessionKey[:5])
			sealingKey[5] = 0xe5
			sealingKey[6] = 0x38
			sealingKey[7] = 0xb0
		}
		return sealingKey
	}

	return randomSessionKey
}
