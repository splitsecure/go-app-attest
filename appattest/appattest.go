package appattest

import (
	"crypto/ecdsa"
	"crypto/x509"

	"github.com/predicat-inc/go-app-attest/authenticatordata"
)

type AttestInput struct {
	ServerChallenge []byte
	AttestationCBOR []byte
	KeyIdentifier   []byte

	OutAuthenticatorData *authenticatordata.T
}

type AttestOutput struct {
	AuthenticatorData *authenticatordata.T
	LeafCert          *x509.Certificate
}

// AttestedPubkey returns the key from the leaf certificate
func (o *AttestOutput) AttestedPubkey() *ecdsa.PublicKey {
	return o.LeafCert.PublicKey.(*ecdsa.PublicKey)
}

type Attestor interface {
	Attest(*AttestInput) (AttestOutput, error)
}
