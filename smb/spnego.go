package smb

import (
	"encoding/asn1"

	"scan_smb/gss"
	"scan_smb/smb/encoder"
)

type spnegoClient struct {
	mechs        []Initiator
	mechTypes    []asn1.ObjectIdentifier
	selectedMech Initiator
}

func newSpnegoClient(mechs []Initiator) *spnegoClient {
	mechTypes := make([]asn1.ObjectIdentifier, len(mechs))
	for i, mech := range mechs {
		mechTypes[i] = mech.oid()
	}
	return &spnegoClient{
		mechs:     mechs,
		mechTypes: mechTypes,
	}
}

func (c *spnegoClient) oid() asn1.ObjectIdentifier {
	return gss.SpnegoOid
}

func (c *spnegoClient) initSecContext() (negTokenInitBytes []byte, err error) {
	// Serialized Negotiate request
	mechToken, err := c.mechs[0].initSecContext()
	if err != nil {
		return nil, err
	}
	return gss.NewNegTokenInit(c.mechTypes, mechToken)
}

func (c *spnegoClient) acceptSecContext(negTokenRespBytes []byte) (res []byte, err error) {
	var token gss.NegTokenResp
	err = encoder.Unmarshal(negTokenRespBytes, &token)
	if err != nil {
		return
	}
	for i, mechType := range c.mechTypes {
		if mechType.Equal(token.SupportedMech) {
			c.selectedMech = c.mechs[i]
			break
		}
	}

	responseToken, err := c.selectedMech.acceptSecContext(token.ResponseToken)

	negTokenResp, _ := gss.NewNegTokenResp()
	negTokenResp.ResponseToken = responseToken
	negTokenResp.State = 1

	ms, err := asn1.Marshal(c.mechTypes)
	if err != nil {
		return
	}

	mecListMIC := c.selectedMech.sum(ms)
	negTokenResp.MechListMIC = mecListMIC

	return encoder.Marshal(&negTokenResp)
}

func (c *spnegoClient) sum(bs []byte) []byte {
	return c.selectedMech.sum(bs)
}

func (c *spnegoClient) sessionKey() []byte {
	return c.selectedMech.sessionKey()
}
