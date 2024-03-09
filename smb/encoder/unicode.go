package encoder

import (
	"bytes"
	"encoding/binary"
	"errors"
	"unicode/utf16"
)

func Utf16ToUtf8(in []uint16) []byte {
	t := make([]byte, 0, len(in)*2)
	for i := 0; i < len(in); i++ {
		t = binary.LittleEndian.AppendUint16(t, in[i])
	}
	return t
}

func Utf8ToUtf16(in []byte) ([]uint16, error) {
	if len(in)%2 != 0 {
		return nil, errors.New("Uneven length of UTF8 array")
	}
	t := make([]uint16, len(in)/2)
	for i := 0; i < len(t); i++ {
		t[i] = binary.LittleEndian.Uint16(in[i*2:])
	}
	return t, nil
}

func FromUnicodeString(d []byte) (string, error) {
	// Credit to https://github.com/Azure/go-ntlmssp/blob/master/unicode.go for logic
	if len(d)%2 > 0 {
		return "", errors.New("Unicode (UTF 16 LE) specified, but uneven data length")
	}
	s := make([]uint16, len(d)/2)
	err := binary.Read(bytes.NewReader(d), binary.LittleEndian, &s)
	if err != nil {
		return "", err
	}
	return string(utf16.Decode(s)), nil
}

func FromUnicode(d []byte) ([]byte, error) {
	s, err := FromUnicodeString(d)
	return []byte(s), err
}

func ToUnicode(s string) []byte {
	// Credit to https://github.com/Azure/go-ntlmssp/blob/master/unicode.go for logic
	uints := utf16.Encode([]rune(s))
	b := bytes.Buffer{}
	binary.Write(&b, binary.LittleEndian, &uints)
	return b.Bytes()
}
