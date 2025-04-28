package authenticatordata

import (
	cose_key "github.com/ldclabs/cose/key"
)

const (
	ADF_USER_PRESENT                 = byte(1)
	ADF_RFU1                         = byte(1 << 1)
	ADF_USER_VERIFIED                = byte(1 << 2)
	ADF_HAS_ATTESTED_CREDENTIAL_DATA = byte(1 << 6)
	ADF_HAS_EXTENSION_DATA           = byte(1 << 7)
)

type T struct {
	RelayingPartyHash      []byte
	Flags                  byte
	SignCount              uint32
	AttestedCredentialData AttestedCredentialData
	// Extensions (ignored)
}

type AttestedCredentialData struct {
	AAGUID              []byte
	CredentialID        []byte
	CredentialPublicKey cose_key.Key
}
