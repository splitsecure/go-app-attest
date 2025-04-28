package mint_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"testing"
	"time"

	appattest "github.com/predicat-inc/go-app-attest/appattest"
	"github.com/predicat-inc/go-app-attest/mint"
	"github.com/stretchr/testify/require"
)

func TestMint(t *testing.T) {
	appIDDigest := sha256.Sum256([]byte("myapp"))

	mintctx, err := mint.NewMintContext()
	require.NoError(t, err)

	intCert, err := x509.ParseCertificate(mintctx.IntCertDer)
	require.NoError(t, err)

	attKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	mintout, err := mint.AttestKey(&mint.AttestInput{
		IntermediatesDER:  [][]byte{mintctx.IntCertDer},
		IssuerCertificate: intCert,
		IssuerKey:         mintctx.IntKey,
		AttestedKey:       &attKey.PublicKey,
		AAGUID:            appattest.AAGUIDDev,

		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour),

		BundleIDHash:    appIDDigest[:],
		ServerChallenge: []byte("server data"),
	})
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(mintctx.CACertDer)
	require.NoError(t, err)

	keyid := appattest.ComputeKeyHash(&attKey.PublicKey)

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	_, err = appattest.SubtleAttest(&appattest.SubtleAttestInput{
		AttestationInput: &appattest.AttestInput{
			ServerChallenge: []byte("server data"),
			AttestationCBOR: mintout.Attestation,
			KeyIdentifier:   keyid[:],
		},
		BundleIDHashes:  [][]byte{appIDDigest[:]},
		ExpectedAAGUIDs: []appattest.Environment{appattest.AAGUIDDev},
		Time:            time.Now(),
		AARoots:         caPool,
	})
	require.NoError(t, err)
}
