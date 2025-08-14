package mint_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/predicat-inc/go-app-attest/appattest"
	"github.com/predicat-inc/go-app-attest/mint"
	"github.com/stretchr/testify/require"
)

func TestAssertionRoundtrip(t *testing.T) {
	bundleHash := sha256.Sum256([]byte("myapp"))
	attKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	clientData := []byte("my_client_data")

	mao, err := mint.GenerateAssertion(&mint.AssertInput{
		PrivateKey:      attKey,
		ClientData:      clientData,
		ClientAppIDHash: bundleHash[:],
		SignCount:       4,
	})
	require.NoError(t, err)

	res, err := appattest.VerifyAssertion(
		&appattest.VerifyAssertionInput{
			Pubkey:           &attKey.PublicKey,
			Assertion:        mao.Assertion,
			ClientDataSHA256: clientData,
		},
	)

	require.NoError(t, err)
	require.Equal(t, uint32(4), res.SignCount)
	require.Equal(t, bundleHash[:], res.BundleHash)
}
