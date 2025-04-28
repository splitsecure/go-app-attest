package mint

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"github.com/predicat-inc/go-app-attest/appattest"
	"github.com/predicat-inc/go-app-attest/authenticatordata"
)

type AssertInput struct {
	PrivateKey      *ecdsa.PrivateKey
	ClientData      []byte
	ClientAppIDHash []byte
	SignCount       uint32
}

type AssertOutput struct {
	Assertion []byte
}

func GenerateAssertion(in *AssertInput) (AssertOutput, error) {
	authenticatorData := authenticatordata.T{
		RelayingPartyHash: in.ClientAppIDHash,
		SignCount:         in.SignCount,
	}

	authenticatorDataB, err := authenticatordata.Marshal(&authenticatorData)
	if err != nil {
		return AssertOutput{}, err
	}

	nonceDigester := sha256.New()
	nonceDigester.Write(authenticatorDataB)
	nonceDigester.Write(in.ClientData)

	nonce := nonceDigester.Sum(nil)
	fmt.Println("noncedigester on mint", base64.StdEncoding.EncodeToString(nonce[:]))

	nonced := sha256.Sum256(nonce)

	sig, err := ecdsa.SignASN1(rand.Reader, in.PrivateKey, nonced[:])
	if err != nil {
		return AssertOutput{}, err
	}

	// sig, err := in.PrivateKey.Sign(rand.Reader, nonce[:], crypto.Hash(crypto.SHA256))
	// if err != nil {
	// 	return AssertOutput{}, err
	// }

	ao := appattest.AssertionObject{
		Signature:         sig,
		AuthenticatorData: authenticatorDataB,
	}

	aob, err := cbor.Marshal(&ao)
	if err != nil {
		return AssertOutput{}, err
	}

	return AssertOutput{Assertion: aob}, nil
}
