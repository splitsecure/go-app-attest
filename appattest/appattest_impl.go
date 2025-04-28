package appattest

import (
	"crypto/x509"
	"fmt"
	"time"

	"github.com/pkg/errors"
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

type AttestorImpl struct {
	aaroots                *x509.CertPool
	nowfn                  func() time.Time
	expectedAAGUIDs        []Environment
	expectedBundleIDHashes [][]byte
}

type optionsState struct {
	into *AttestorImpl

	aaroots      *x509.CertPool
	nowfn        func() time.Time
	bundleIDHash []byte

	// defaults to prod
	environments []Environment
}

type option struct {
	apply func(*optionsState)
}

func newoption(fn func(*optionsState)) option {
	return option{
		apply: fn,
	}
}

func WithEnvironments(env []Environment) option {
	return newoption(func(os *optionsState) {
		os.environments = env
	})
}

// WithAppAttestRoots lets the user provide its own authoritative certs pool
func WithAppAttestRoots(pool *x509.CertPool) option {
	return newoption(func(s *optionsState) {
		s.aaroots = pool
	})
}

func WithNowFn(now func() time.Time) option {
	return newoption(func(os *optionsState) {
		os.nowfn = now
	})
}

func New(
	bundleIDHashes [][]byte,
	options ...option,
) (*AttestorImpl, error) {

	att := &AttestorImpl{}

	optionsState := optionsState{}

	// compute the options state from the provided options
	for _, option := range options {
		option.apply(&optionsState)
	}

	// determine pool
	if optionsState.aaroots == nil {
		// use the certificate provided by the library
		att.aaroots = x509.NewCertPool()
		if !att.aaroots.AppendCertsFromPEM([]byte(appattestRootCAPEM)) {
			return nil, errors.New("loading library provided app attest ca")
		}
	} else {
		// use the user provided pool
		att.aaroots = optionsState.aaroots
	}

	// determine timefn
	if optionsState.nowfn == nil {
		att.nowfn = time.Now
	} else {
		att.nowfn = optionsState.nowfn
	}

	// set expected AAGUID
	if len(optionsState.environments) == 0 {
		att.expectedAAGUIDs = []Environment{AAGUIDProd}
	} else {
		att.expectedAAGUIDs = optionsState.environments
	}

	// determine bundle id hash
	if len(bundleIDHashes) == 0 {
		return nil, fmt.Errorf("bundle id hash must be provided")
	} else {
		att.expectedBundleIDHashes = bundleIDHashes
	}

	return att, nil
}

func (at *AttestorImpl) Attest(in *AttestInput) (AttestOutput, error) {
	subtleIn := SubtleAttestInput{
		AttestationInput: in,

		BundleIDHashes:  at.expectedBundleIDHashes,
		Time:            at.nowfn(),
		ExpectedAAGUIDs: at.expectedAAGUIDs,
		AARoots:         at.aaroots,
	}
	return SubtleAttest(&subtleIn)
}
