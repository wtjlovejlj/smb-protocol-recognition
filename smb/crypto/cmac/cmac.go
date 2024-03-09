package cmac

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"hash"
)

const Bsize = 16

var zero = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

type cmac struct {
	k1     []byte
	k2     []byte
	x      []byte // Previous/current block
	digest []byte // T in RFC 4493
	c      cipher.Block
	pos    int
}

func New(key []byte) (hash.Hash, error) {
	if len(key) != 16 {
		return nil, fmt.Errorf("Invalid key size. Only support 128 bit keys")
	}
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	k1, k2, err := generateSubkeys(key)
	if err != nil {
		return nil, err
	}
	return &cmac{
		k1:     k1,
		k2:     k2,
		x:      make([]byte, cipher.BlockSize()),
		digest: make([]byte, cipher.BlockSize()),
		c:      cipher,
		pos:    0,
	}, nil
}

func (self *cmac) Write(data []byte) (int, error) {
	// Step 6 in RFC 4493
	// XOR every byte with same position in previous block
	// and for each complete block we encrypt it and start over
	for _, b := range data {
		if self.pos >= len(self.x) {
			self.c.Encrypt(self.x, self.x)
			self.pos = 0
		}
		self.x[self.pos] ^= b
		self.pos++
	}
	return len(data), nil
}

func (self *cmac) Sum(buf []byte) []byte {
	last := make([]byte, len(self.x))
	copy(last, self.x[:self.pos])
	copy(self.digest, self.x)

	// Step 4
	if self.pos >= len(self.x) {
		self.digest = xor128(last, self.k1)
	} else {
		// Padding(M_n)
		// Only the highest bit (0x80 bit) will have effect on xor since rest of the padding is 0
		self.digest[self.pos] ^= 0x80
		self.digest = xor128(self.digest, self.k2)
	}

	self.c.Encrypt(self.digest, self.digest)
	return append(buf, self.digest[:self.c.BlockSize()]...)
}

func (self *cmac) Size() int {
	return len(self.digest)
}

func (self *cmac) BlockSize() int {
	return self.c.BlockSize()
}

func (self *cmac) Reset() {
	for i := range self.x {
		self.x[i] = 0
	}
	self.pos = 0
}

func generateSubkeys(k []byte) ([]byte, []byte, error) {
	//   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	//   +                    Algorithm Generate_Subkey                      +
	//   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
	//   +                                                                   +
	//   +   Input    : K (128-bit key)                                      +
	//   +   Output   : K1 (128-bit first subkey)                            +
	//   +              K2 (128-bit second subkey)                           +
	//   +-------------------------------------------------------------------+
	//   +                                                                   +
	//   +   Constants: const_Zero is 0x00000000000000000000000000000000     +
	//   +              const_Rb   is 0x00000000000000000000000000000087     +
	//   +   Variables: L          for output of AES-128 applied to 0^128    +
	//   +                                                                   +
	//   +   Step 1.  L := AES-128(K, const_Zero);                           +
	//   +   Step 2.  if MSB(L) is equal to 0                                +
	//   +            then    K1 := L << 1;                                  +
	//   +            else    K1 := (L << 1) XOR const_Rb;                   +
	//   +   Step 3.  if MSB(K1) is equal to 0                               +
	//   +            then    K2 := K1 << 1;                                 +
	//   +            else    K2 := (K1 << 1) XOR const_Rb;                  +
	//   +   Step 4.  return K1, K2;                                         +
	//   +                                                                   +
	//   +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

	aes128, err := aes.NewCipher(k)
	if err != nil {
		return nil, nil, err
	}

	l := make([]byte, 16)
	aes128.Encrypt(l, l)

	k1 := make([]byte, 16)
	k2 := make([]byte, 16)
	tmp := make([]byte, 16)
	if (l[0] & 0x80) == 0 {
		// If MSB(L) = 0 then k1 = L << 1
		leftshift(l, k1)
	} else {
		// k1 = (l << 1) + Rb
		leftshift(l, tmp)
		copy(k1, tmp)
		k1[len(k1)-1] ^= 0x87
	}

	if (k1[0] & 0x80) == 0 {
		leftshift(k1, k2)
	} else {
		leftshift(k1, tmp)
		copy(k2, tmp)
		k2[len(k2)-1] ^= 0x87
	}

	return k1, k2, nil
}

func xor128(a, b []byte) []byte {
	res := []byte{}
	for i := 0; i < len(a); i++ {
		res = append(res, a[i]^b[i])
	}

	return res
}

func pad(n []byte) []byte {
	padLen := 16 - len(n)
	padding := []byte{0x80}
	padding = append(padding, make([]byte, padLen-1)...)

	return append(n, padding...)
}

func leftshift(input, output []byte) byte {
	overflow := byte(0)

	for i := len(input) - 1; i >= 0; i-- {
		output[i] = input[i] << 1
		output[i] |= overflow
		if (input[i] & 0x80) == 0x80 {
			overflow = 1
		} else {
			overflow = 0
		}
	}
	return overflow
}
