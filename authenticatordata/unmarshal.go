package authenticatordata

import (
	"bytes"
	"encoding/binary"

	"github.com/fxamacker/cbor/v2"
)

// Unmarshal unmarshals authenticator data
// according to https://www.w3.org/TR/webauthn/#sctn-authenticator-data
func Unmarshal(src []byte, dst *T) error {
	src = unmarshalBase(src, dst)
	if dst.Flags&ADF_HAS_ATTESTED_CREDENTIAL_DATA != 0 {
		var err error
		_ /*src*/, err = UnmarshalAttestedCredentialData(src, &dst.AttestedCredentialData)
		if err != nil {
			return err
		}
	}

	// ignoring extensions
	return nil
}

// UnmarshalFromAssertion unmarshals authenticator data from Apple App Attest Assertion
// It's not possible to use `Unmarshal` because they decided to omit the attested
// credentials _WITHOUT REMOVING IT FROM THE FLAGS_.
// If they removed the `attestedCredentialData` from the flags they would be able to use `Unmarshal`.`
// From the docs @ https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server#Verify-the-assertion :
// > The client creates the assertion by packaging the request as clientData,
// > and asking the App Attest service to sign the data with the attested private key.
// > Along with the signature, App Attest includes a simplified authenticator data instance in the assertion object,
// > similar to the one in the attestation object, but containing only the first few fields, including RP ID and counter.

func UnmarshalFromAssertion(src []byte, dst *T) {
	unmarshalBase(src, dst)
}

func unmarshalBase(src []byte, dst *T) (rest []byte) {
	cursor := src

	dst.RelayingPartyHash = cursor[0:32]
	cursor = cursor[32:]

	dst.Flags = cursor[0]
	cursor = cursor[1:]

	dst.SignCount = binary.BigEndian.Uint32(cursor)
	cursor = cursor[4:]

	return cursor
}

func UnmarshalAttestedCredentialData(src []byte, dst *AttestedCredentialData) (rest []byte, err error) {
	dst.AAGUID = src[0:16]

	credLen := binary.BigEndian.Uint16(src[16:18])
	dst.CredentialID = src[18 : 18+credLen]

	dec := cbor.NewDecoder(bytes.NewReader(src[18+credLen:]))

	if err := dec.Decode(&dst.CredentialPublicKey); err != nil {
		return nil, err
	}

	return src[18+int(uint(credLen))+dec.NumBytesRead():], err
}
