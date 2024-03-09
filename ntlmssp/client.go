package ntlmssp

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"fmt"
	"github.com/jfjallid/golog"
	"scan_smb/smb/encoder"
	"time"
)

var le = binary.LittleEndian

var log = golog.Get("ntlmssp")

var version = []byte{
	0: WINDOWS_MAJOR_VERSION_10,
	1: WINDOWS_MINOR_VERSION_0,
	7: NTLMSSP_REVISION_W2K3,
}

type Client struct {
	User               string
	Password           string
	Hash               []byte // Password Hash
	NTHash             []byte // Output from Ntowfv2
	LMHash             []byte // Output from Lmowfv2
	LocalUser          bool   // Don't use domain name from server
	Domain             string
	Workstation        string
	NullSession        bool
	guestSession       bool
	SigningDisabled    bool
	EncryptionDisabled bool
	session            *Session
	neg                *Negotiate
	TargetSPN          string
	channelBinding     *channelBindings // Reserved for future use

}

func (c *Client) Negotiate() ([]byte, error) {
	req := Negotiate{
		Header: Header{
			Signature:   []byte(Signature),
			MessageType: TypeNtLmNegotiate,
		},
		NegotiateFlags: FlgNeg56 |
			FlgNeg128 |
			FlgNegTargetInfo |
			FlgNegExtendedSessionSecurity |
			FlgNegNtLm |
			FlgNegSign |
			FlgNegRequestTarget |
			FlgNegUnicode |
			FlgNegVersion,
	}

	if c.Domain != "" {
		req.DomainName = []byte(c.Domain)
		req.NegotiateFlags |= FlgNegOEMDomainSupplied
	}

	if c.Workstation != "" {
		req.Workstation = []byte(c.Workstation)
		req.NegotiateFlags |= FlgNegOEMWorkstationSupplied
	}

	if !c.EncryptionDisabled {
		req.NegotiateFlags |= FlgNegSeal
	}

	req.NegotiateFlags |= FlgNegKeyExch
	req.Version = le.Uint64(version)
	c.neg = &req
	return encoder.Marshal(req)
}

func (c *Client) Authenticate(cmsg []byte) (amsg []byte, err error) {
	chall := NewChallenge()
	err = encoder.Unmarshal(cmsg, &chall)
	if err != nil {
		log.Errorln(err)
		return
	}

	if len(cmsg) < 48 {
		err := fmt.Errorf("message length is too short")
		log.Errorln(err)
		return nil, err
	}

	if !bytes.Equal(chall.Signature, []byte(Signature)) {
		err := fmt.Errorf("invalid signature")
		log.Errorln(err)
		return nil, err
	}

	if chall.MessageType != TypeNtLmChallenge {
		err := fmt.Errorf("invalid message type")
		log.Errorln(err)
		return nil, err
	}

	flags := c.neg.NegotiateFlags & chall.NegotiateFlags

	if flags&FlgNegRequestTarget == 0 {
		err := fmt.Errorf("invalid negotiate flags")
		log.Errorln(err)
		return nil, err
	}
	targetName := chall.TargetName

	if flags&FlgNegTargetInfo == 0 {
		err := fmt.Errorf("invalid negotiate flags")
		log.Errorln(err)
		return nil, err
	}

	if chall.TargetInfo == nil {
		err := fmt.Errorf("invalid target info format")
		log.Errorln(err)
		return nil, err
	}

	if c.User == "" && (!c.NullSession) {
		c.guestSession = true
	}

	// Assumes domain, user, and workstation are not unicode
	var domain []byte
	if c.Domain != "" {
		domain = encoder.ToUnicode(c.Domain)
	} else if !c.LocalUser {
		domain = targetName
	}

	domainstr, err := encoder.FromUnicodeString(domain)
	if err != nil {
		log.Errorln(err)
		return
	}

	clientChallenge := make([]byte, 8)
	rand.Reader.Read(clientChallenge)
	serverChallenge := make([]byte, 8)
	w := bytes.NewBuffer(make([]byte, 0))
	binary.Write(w, binary.LittleEndian, chall.ServerChallenge)
	serverChallenge = w.Bytes()
	w = bytes.NewBuffer(make([]byte, 0))

	flagsFound := false
	channelBindingsFound := false
	timestampFound := false
	timestamp := make([]byte, 8)

	// NOTE An alternative approach to this is to parse the AV Pairs into a map and then
	// check if keys exist and to serialize that map when needed.
	for _, av := range *chall.TargetInfo {
		if av.AvID == MsvAvFlags {
			flagsFound = true
			le.PutUint32(av.Value, le.Uint32(av.Value)|0x02)
		} else if av.AvID == MsvAvChannelBindings {
			channelBindingsFound = true
		} else if av.AvID == MsvAvTimestamp {
			timestampFound = true
			copy(timestamp, av.Value[:8])
		} else if av.AvID == 0 {
			continue
		}
		binary.Write(w, binary.LittleEndian, av.AvID)
		binary.Write(w, binary.LittleEndian, av.AvLen)
		binary.Write(w, binary.LittleEndian, av.Value)
	}

	//If timestamp was not found in AV Pairs I should add a timestamp with current time
	if !timestampFound {
		// Credit to https://github.com/Azure/go-ntlmssp/blob/master/unicode.go for logic
		ft := uint64(time.Now().UnixNano()) / 100
		ft += 116444736000000000 // add time between unix & windows offset
		binary.LittleEndian.PutUint64(timestamp, ft)
	}

	if !flagsFound {
		temp := make([]byte, 2)
		le.PutUint16(temp, MsvAvFlags)
		temp = le.AppendUint16(temp, 4)
		temp = le.AppendUint32(temp, 0x02)
		binary.Write(w, binary.LittleEndian, temp)
	}

	// MS-NLMP Section 3.1.5.1.2, If the ClientChannelBindingsUnhashed is NULL
	// Add an empty MsAvChannelBindings
	if !channelBindingsFound {
		temp := make([]byte, 2)
		le.PutUint16(temp, MsvAvChannelBindings)
		temp = le.AppendUint16(temp, 16)
		temp = append(temp, make([]byte, 16)...)
		binary.Write(w, binary.LittleEndian, temp)
	}

	// MS-NLMP Section 3.1.5.1.2, If the ClientSuppliedTargetName (TargetSPN) is NULL
	// Add an empty MsvAvTargetName, else if it is not null, set the value without
	// terminating NULL character.
	temp := make([]byte, 2)
	le.PutUint16(temp, MsvAvTargetName)
	if c.TargetSPN != "" {
		spn := encoder.ToUnicode(c.TargetSPN)
		le.AppendUint16(temp, uint16(len(spn)))
		temp = append(temp, spn...)
	} else {
		temp = le.AppendUint32(temp, 0)
	}
	binary.Write(w, binary.LittleEndian, temp)

	// Add MsAvEOL
	temp = make([]byte, 4)
	w.Write(temp)

	// Calc NT Hash
	if c.Hash != nil {
		c.NTHash = Ntowfv2Hash(c.User, domainstr, c.Hash)
	} else {
		c.NTHash = Ntowfv2(c.Password, c.User, domainstr)
	}

	//NOTE c.LMHash is likely empty but is currently not used
	response := ComputeResponseNTLMv2(c.NTHash, c.LMHash, clientChallenge, serverChallenge, timestamp, w.Bytes())

	/*
	   MS-NLMP Section 3.1.5.1.2
	   If NTLM v2 authentication is used and the CHALLENGE_MESSAGE TargetInfo field (section 2.2.1.2)
	   has an MsvAvTimestamp present, the client SHOULD NOT send the LmChallengeResponse and
	   SHOULD send Z(24) instead
	*/
	var lmChallengeResponse []byte
	if !timestampFound {
		h := hmac.New(md5.New, c.LMHash)
		h.Write(append(serverChallenge, clientChallenge...))
		lmChallengeResponse = h.Sum(nil)
		lmChallengeResponse = append(lmChallengeResponse, clientChallenge...)
	} else {
		lmChallengeResponse = make([]byte, 24)
	}

	auth := Authenticate{
		Header: Header{
			Signature:   []byte(Signature),
			MessageType: TypeNtLmAuthenticate,
		},
		DomainName:  domain,
		Workstation: encoder.ToUnicode(c.Workstation),
		MIC:         make([]byte, 16),
	}
	// Anonymous auth attempt
	if c.NullSession {
		auth.NtChallengeResponse = nil
		auth.LmChallengeResponse = nil
	} else if c.guestSession {
		auth.NtChallengeResponse = response
		auth.LmChallengeResponse = lmChallengeResponse
	} else {
		auth.NtChallengeResponse = response
		auth.LmChallengeResponse = lmChallengeResponse
		auth.UserName = encoder.ToUnicode(c.User)
	}

	session := new(Session)
	session.isClientSide = true
	session.user = c.User

	if c.guestSession || c.NullSession {
		flags |= FlgNegAnonymous
	}

	session.negotiateFlags = flags

	//Create SessionKey
	h := hmac.New(md5.New, c.NTHash)
	h.Write(response[:16])
	sessionBaseKey := h.Sum(nil)

	// MS-NLMP Secion 3.4.5.1 KXKey
	keyExchangeKey := sessionBaseKey // if ntlm version == 2

	if flags&FlgNegKeyExch != 0 {
		session.exportedSessionKey = make([]byte, 16)
		_, err := rand.Read(session.exportedSessionKey)
		if err != nil {
			return nil, err
		}
		cipher, err := rc4.NewCipher(keyExchangeKey)
		if err != nil {
			return nil, err
		}
		encryptedRandomSessionKey := make([]byte, 16)

		// MS-NLMP Section 4.2.4.2.3
		cipher.XORKeyStream(encryptedRandomSessionKey, session.exportedSessionKey)

		auth.EncryptedRandomSessionKey = encryptedRandomSessionKey
		auth.EncryptedRandomSessionKeyLen = uint16(len(encryptedRandomSessionKey))
		auth.EncryptedRandomSessionKeyMaxLen = uint16(len(encryptedRandomSessionKey))
		// Buffer offset set automatically
	} else {
		session.exportedSessionKey = keyExchangeKey
	}

	auth.NegotiateFlags = flags

	auth.Version = c.neg.Version

	// Calc MIC of Neg, Chall, and Auth messages
	h = hmac.New(md5.New, session.exportedSessionKey)
	nmsgBuf, err := encoder.Marshal(c.neg)
	if err != nil {
		log.Errorln(err)
		return
	}
	h.Write(nmsgBuf)
	cmsgBuf, err := encoder.Marshal(chall)
	if err != nil {
		log.Errorln(err)
		return
	}
	h.Write(cmsgBuf)

	authBytes, err := encoder.Marshal(&auth)
	if err != nil {
		log.Errorln(err)
		return
	}
	h.Write(authBytes)
	mic := h.Sum(nil)
	copy(auth.MIC, mic[:16])

	session.clientSigningKey = signKey(flags, session.exportedSessionKey, true)
	session.serverSigningKey = signKey(flags, session.exportedSessionKey, false)

	session.clientHandle, err = rc4.NewCipher(sealKey(flags, session.exportedSessionKey, true))
	if err != nil {
		log.Errorln(err)
		return nil, err
	}
	session.serverHandle, err = rc4.NewCipher(sealKey(flags, session.exportedSessionKey, false))
	if err != nil {
		log.Errorln(err)
		return nil, err
	}

	c.session = session

	return encoder.Marshal(&auth)
}

func (c *Client) Session() *Session {
	return c.session
}
