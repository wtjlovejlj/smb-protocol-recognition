package smb

import (
	"encoding/asn1"

	"scan_smb/gss"
	"scan_smb/ntlmssp"
)

type Initiator interface {
	oid() asn1.ObjectIdentifier
	initSecContext() ([]byte, error)            // GSS_Init_sec_context
	acceptSecContext(sc []byte) ([]byte, error) // GSS_Accept_sec_context
	sum(bs []byte) []byte                       // GSS_getMIC
	sessionKey() []byte                         // QueryContextAttributes(ctx, SECPKG_ATTR_SESSION_KEY, &out)
	isNullSession() bool
}

// NTLMInitiator implements session setup through NTLMv2.
// It does not support NTLMv1. It is possible to use hash instead of password.
type NTLMInitiator struct {
	User               string
	Password           string
	Hash               []byte
	Domain             string
	LocalUser          bool
	NullSession        bool
	Workstation        string
	TargetSPN          string
	DisableSigning     bool
	EncryptionDisabled bool

	ntlm   *ntlmssp.Client
	seqNum uint32
}

func (i *NTLMInitiator) oid() asn1.ObjectIdentifier {
	return gss.NtLmSSPMechTypeOid
}

func (i *NTLMInitiator) initSecContext() ([]byte, error) {
	//if !((i.User != "") && (i.Password != "")) && !((i.User != "") && (i.Hash != nil)) {
	//	return nil, fmt.Errorf("Invalid NTLMInitiator! Must specify username + password or username + hash")
	//}
	i.ntlm = &ntlmssp.Client{
		User:               i.User,
		Password:           i.Password,
		Domain:             i.Domain,
		LocalUser:          i.LocalUser,
		NullSession:        i.NullSession,
		Hash:               i.Hash,
		Workstation:        i.Workstation,
		TargetSPN:          i.TargetSPN,
		SigningDisabled:    i.DisableSigning,
		EncryptionDisabled: i.EncryptionDisabled,
	}

	if len(i.Hash) == 0 {
		i.Hash = ntlmssp.Ntowfv1(i.Password)
		i.ntlm.Hash = i.Hash
	}
	nmsg, err := i.ntlm.Negotiate()
	if err != nil {
		return nil, err
	}
	return nmsg, nil
}

func (i *NTLMInitiator) acceptSecContext(sc []byte) ([]byte, error) {
	amsg, err := i.ntlm.Authenticate(sc)
	if err != nil {
		return nil, err
	}
	return amsg, nil
}

func (i *NTLMInitiator) sum(bs []byte) []byte {
	mic, _ := i.ntlm.Session().Sum(bs, i.seqNum)
	return mic
}

func (i *NTLMInitiator) sessionKey() []byte {
	return i.ntlm.Session().SessionKey()
}

func (i *NTLMInitiator) isNullSession() bool {
	return i.NullSession
}
