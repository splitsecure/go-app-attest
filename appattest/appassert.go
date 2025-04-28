package appattest

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/predicat-inc/go-app-attest/authenticatordata"
)

type AssertInput struct {
	Pubkey           *ecdsa.PublicKey
	Assertion        []byte
	ClientDataSHA256 []byte
	AppIDDigests     [][]byte
}

type AssertOutput struct {
	SignCount uint32
}

type AssertionObject struct {
	Signature         []byte `cbor:"signature"`
	AuthenticatorData []byte `cbor:"authenticatorData"`
}

// https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server#Verify-the-assertion
func Assert(
	input *AssertInput,
) (AssertOutput, error) {
	ao := AssertionObject{}
	if err := cbor.Unmarshal(input.Assertion, &ao); err != nil {
		return AssertOutput{}, fmt.Errorf("failed to unmarshal assertion object: %w", err)
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
		return AssertOutput{}, fmt.Errorf("failed to verify signature: nonce=%s sig=%s", hex.EncodeToString(nonce[:]), hex.EncodeToString(ao.Signature))
	}

	ad := authenticatordata.T{}
	authenticatordata.UnmarshalFromAssertion(ao.AuthenticatorData, &ad)

	appidhashOk := false
	for _, aid := range input.AppIDDigests {
		if slices.Equal(ad.RelayingPartyHash, aid) {
			appidhashOk = true
			break
		}
	}
	if !appidhashOk {
		return AssertOutput{}, fmt.Errorf("invalid relaying party %q", hex.EncodeToString(ad.RelayingPartyHash))
	}

	return AssertOutput{SignCount: ad.SignCount}, nil
}
