package appattest

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/predicat-inc/go-app-attest/authenticatordata"
)

type VerifyAssertionInput struct {
	Pubkey           *ecdsa.PublicKey
	Assertion        []byte
	ClientDataSHA256 []byte
}

type VerifyAssertionOutput struct {
	SignCount  uint32
	BundleHash []byte
}

type AssertionObject struct {
	Signature         []byte `cbor:"signature"`
	AuthenticatorData []byte `cbor:"authenticatorData"`
}

// https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server#Verify-the-assertion
func VerifyAssertion(
	input *VerifyAssertionInput,
) (VerifyAssertionOutput, error) {
	ao := AssertionObject{}
	if err := cbor.Unmarshal(input.Assertion, &ao); err != nil {
		return VerifyAssertionOutput{}, fmt.Errorf("failed to unmarshal assertion object: %w", err)
	}

	nonceDigester := sha256.New()
	nonceDigester.Write(ao.AuthenticatorData)
	nonceDigester.Write(input.ClientDataSHA256)
	nonce := [sha256.Size]byte{}

	// write the sum of nonceDigester to nonce
	_ = nonceDigester.Sum(nonce[:0])

	// re-image nonce
	nonce = sha256.Sum256(nonce[:])

	if !ecdsa.VerifyASN1(input.Pubkey, nonce[:], ao.Signature) {
		return VerifyAssertionOutput{}, fmt.Errorf("failed to verify signature: nonce=%s sig=%s", hex.EncodeToString(nonce[:]), hex.EncodeToString(ao.Signature))
	}

	ad := authenticatordata.T{}
	authenticatordata.UnmarshalFromAssertion(ao.AuthenticatorData, &ad)

	return VerifyAssertionOutput{
		SignCount:  ad.SignCount,
		BundleHash: ad.RelayingPartyHash,
	}, nil
}
