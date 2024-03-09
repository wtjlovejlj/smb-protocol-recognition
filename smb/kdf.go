package smb

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
)

func kdf(ki, label, context []byte, L uint32) []byte {

	h := hmac.New(sha256.New, ki)
	if L != 128 && L != 256 {
		panic("Unsupported L value. Only support 128 or 256.")
	}

	// Since L/h is either 128/256 = 0.5 or 256/256 = 1
	// there is only going to be one lap in the loop so we can flatten it.
	// i will be a byte array of length R with the value of 1 since there is only a single lap.
	i := append(make([]byte, 3), byte(0x01))

	//K(i) := PRF (KI, [i] || Label || 0x00 || Context || [L]),
	h.Write(i)
	h.Write(label)
	h.Write([]byte{0x00})
	h.Write(context)
	h.Write(binary.BigEndian.AppendUint32(nil, L))

	// MS-SMB2 only want 16 bytes output
	return h.Sum(nil)[:L/8]
}
