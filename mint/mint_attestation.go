package mint

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/splitsecure/go-app-attest/appattest"
	"github.com/splitsecure/go-app-attest/authenticatordata"
)

// This package provides an API for minting attestation documents.

type AttestInput struct {
	IntermediatesDER  [][]byte
	IssuerCertificate *x509.Certificate
	IssuerKey         *ecdsa.PrivateKey
	AttestedKey       *ecdsa.PublicKey
	AAGUID            []byte

	NotBefore time.Time
	NotAfter  time.Time

	ServerChallenge []byte
	BundleIDHash    []byte

	SignCount uint32

	// MutateLeaf provides the caller with an opportunity to modify the certificate template before
	// it is processed.
	MutateLeafTemplate func(*x509.Certificate)
}

type AttestOutput struct {
	Attestation []byte
}

func AttestKey(input *AttestInput) (AttestOutput, error) {
	// compute the key hash
	keyIdentifier := appattest.ComputeKeyHash(input.AttestedKey)

	// build and marshal the authenticator data
	ad := authenticatordata.T{
		RelayingPartyHash: input.BundleIDHash,
		SignCount:         input.SignCount,
		Flags:             authenticatordata.ADF_HAS_ATTESTED_CREDENTIAL_DATA,
		AttestedCredentialData: authenticatordata.AttestedCredentialData{
			AAGUID:       input.AAGUID,
			CredentialID: keyIdentifier[:],
		},
	}

	adb, err := authenticatordata.Marshal(&ad)
	if err != nil {
		return AttestOutput{}, err
	}

	// serverChallengeDigest := sha256.Sum256(input.ServerChallenge)

	// compute rawnonce which will be put in an ASN.1 container
	rawnonce, err := appattest.ComputeNonce(adb, input.ServerChallenge)
	// rawnonce, err := appattest.ComputeNonce(adb, serverChallengeDigest[:])
	if err != nil {
		return AttestOutput{}, err
	}

	// nonce is an asn.1 container containing the computed nonce
	nonce, err := asn1.Marshal(appattest.ASN1AANonceContainer{Nonce: rawnonce[:]})
	if err != nil {
		return AttestOutput{}, err
	}

	// mint the leaf certificate
	exts := []pkix.Extension{
		{
			Id:    appattest.NonceOID,
			Value: nonce,
		},
	}

	leafder, err := generateLeafCert(input.AttestedKey,
		"mock leaf",
		input.IssuerCertificate,
		input.IssuerKey,
		exts,
		input.NotBefore,
		input.NotAfter,
		input.MutateLeafTemplate,
	)
	if err != nil {
		return AttestOutput{}, err
	}

	x5c := make([][]byte, 1+len(input.IntermediatesDER))
	x5c[0] = leafder
	_ = copy(x5c[1:], input.IntermediatesDER)

	// build the attestation statement
	as := appattest.AttestationStatement{
		X509CertChain: x5c,
		Receipt:       nil, // do not provide a receipt yet as the server part is not mocked
	}

	// build and marshal the attestation object
	ao := &appattest.AttestationObject{
		AttestationStatement: as,
		AuthData:             adb,
		Format:               appattest.Format,
	}

	// marshal the attestation object
	aob, err := cbor.Marshal(ao)
	if err != nil {
		return AttestOutput{}, err
	}

	return AttestOutput{
		Attestation: aob,
	}, nil
}

func generateLeafCert(
	pubkey *ecdsa.PublicKey,
	commonName string,
	parentCert *x509.Certificate,
	parentKey *ecdsa.PrivateKey,
	exts []pkix.Extension,
	notBefore time.Time,
	notAfter time.Time,
	mutateLeaf func(cert *x509.Certificate),
) ([]byte, error) {
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		ExtraExtensions:       exts,
	}

	if mutateLeaf != nil {
		mutateLeaf(&template)
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, parentCert, pubkey, parentKey)
	if err != nil {
		return nil, err
	}
	return certDER, nil
}
