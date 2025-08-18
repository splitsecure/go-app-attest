package appattest

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/pkg/errors"
	"github.com/splitsecure/go-app-attest/authenticatordata"
)

const appattestRootCAPEM = `-----BEGIN CERTIFICATE-----
MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
oyFraWVIyd/dganmrduC1bmTBGwD
-----END CERTIFICATE-----`

type Attestor interface {
	VerifyAttestation(*VerifyAttestationInput) (VerifyAttestationOutput, error)
}

type AttestorImpl struct {
	aaroots []*x509.Certificate
}

type optionsState struct {
	aaroots []*x509.Certificate
}

type option struct {
	apply func(*optionsState)
}

func newoption(fn func(*optionsState)) option {
	return option{
		apply: fn,
	}
}

// WithAppAttestRoots lets the user provide its own authoritative certificates
func WithAppAttestRoots(certs []*x509.Certificate) option {
	return newoption(func(s *optionsState) {
		s.aaroots = certs
	})
}

func New(
	options ...option,
) (*AttestorImpl, error) {
	att := &AttestorImpl{}

	optionsState := optionsState{}

	// compute the options state from the provided options
	for _, option := range options {
		option.apply(&optionsState)
	}

	// determine root certificates
	if optionsState.aaroots == nil {
		// use the certificate provided by the library
		block, _ := pem.Decode([]byte(appattestRootCAPEM))
		if block == nil {
			return nil, errors.New("failed to parse app attest root CA PEM")
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parsing app attest root CA: %w", err)
		}
		att.aaroots = []*x509.Certificate{cert}
	} else {
		// use the user provided certificates
		att.aaroots = optionsState.aaroots
	}

	return att, nil
}

type VerifyAttestationInput struct {
	ServerChallenge []byte
	AttestationCBOR []byte

	OutAuthenticatorData *authenticatordata.T
}

func (at *AttestorImpl) VerifyAttestation(in *VerifyAttestationInput) (VerifyAttestationOutput, error) {
	subtleIn := VerifyAttestationInputPure{
		AttestationInput: in,
		AARoots:          at.aaroots,
	}
	return VerifyAttestationPure(&subtleIn)
}
