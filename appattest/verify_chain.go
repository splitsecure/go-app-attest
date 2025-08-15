package appattest

import (
	"bytes"
	"crypto/x509"
	"fmt"

	"github.com/pkg/errors"
)

// validateSignatureAlgorithm checks if the signature algorithm is acceptable
func validateSignatureAlgorithm(cert *x509.Certificate) error {
	switch cert.SignatureAlgorithm {
	case x509.MD2WithRSA, x509.MD5WithRSA, x509.SHA1WithRSA:
		return fmt.Errorf("weak signature algorithm: %v", cert.SignatureAlgorithm)
	}
	return nil
}

// validateBasicConstraints checks basic constraints for CA certificates
func validateBasicConstraints(cert *x509.Certificate, isCA bool, pathLen int) error {
	if isCA {
		if !cert.IsCA {
			return fmt.Errorf("certificate must be a CA certificate")
		}
		if cert.MaxPathLen >= 0 && pathLen > cert.MaxPathLen {
			return fmt.Errorf("path length %d exceeds maximum allowed %d", pathLen, cert.MaxPathLen)
		}
	} else {
		// End entity certificate should not be a CA
		if cert.IsCA {
			return fmt.Errorf("end entity certificate cannot be a CA")
		}
	}
	return nil
}

// validateKeyUsage checks key usage for certificates
func validateKeyUsage(cert *x509.Certificate, isCA bool) error {
	if isCA {
		if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
			return fmt.Errorf("CA certificate missing Certificate Sign key usage")
		}
	} else {
		fmt.Println(cert.KeyUsage)
		if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
			return fmt.Errorf("end entity certificate missing required key usage (Digital Signature)")
		}
	}
	return nil
}

// validateCriticalExtensions checks for unknown critical extensions
func validateCriticalExtensions(cert *x509.Certificate) error {
	knownCriticalExtensions := map[string]struct{}{
		"2.5.29.19":         {}, // Basic Constraints
		"2.5.29.15":         {}, // Key Usage
		"2.5.29.37":         {}, // Extended Key Usage
		"2.5.29.17":         {}, // Subject Alternative Name
		"2.5.29.35":         {}, // Authority Key Identifier
		"2.5.29.14":         {}, // Subject Key Identifier
		"2.5.29.32":         {}, // Certificate Policies
		"2.5.29.31":         {}, // CRL Distribution Points
		"1.3.6.1.5.5.7.1.1": {}, // Authority Information Access
	}

	for _, ext := range cert.Extensions {
		if ext.Critical {
			if _, ok := knownCriticalExtensions[ext.Id.String()]; !ok {
				return fmt.Errorf("unknown critical extension: %s", ext.Id.String())
			}
		}
	}
	return nil
}

// VerifyChain is a simplified verification routine.
// Since it might be desireable to verify the validity of an attestation
// beyond its lifetime, this function returns the timerange in which it was valid.
// It assumes that the chain will be passed in the order of leaf to root.
func VerifyChain(chain []*x509.Certificate, roots []*x509.Certificate) error {
	if len(chain) == 0 {
		return fmt.Errorf("chain is empty")
	}

	// Validate each certificate in the chain
	for i, cert := range chain {
		// Validate signature algorithm
		if err := validateSignatureAlgorithm(cert); err != nil {
			return fmt.Errorf("certificate at index %d has invalid signature algorithm: %w", i, err)
		}

		// Validate critical extensions
		if err := validateCriticalExtensions(cert); err != nil {
			return fmt.Errorf("certificate at index %d has invalid critical extensions: %w", i, err)
		}

		// Determine if this certificate is a CA (all except leaf are CAs)
		isCA := i != 0
		pathLen := len(chain) - 1 - i // Path length remaining after this cert

		// Validate basic constraints
		if err := validateBasicConstraints(cert, isCA, pathLen); err != nil {
			return fmt.Errorf("certificate at index %d fails basic constraints validation: %w", i, err)
		}

		// Validate key usage
		if err := validateKeyUsage(cert, isCA); err != nil {
			return fmt.Errorf("certificate at index %d fails key usage validation: %w", i, err)
		}
	}

	if len(chain) > 1 {
		for i := len(chain) - 1; i >= 1; i-- {
			parent := chain[i]
			child := chain[i-1]

			// Validate Subject/Issuer name chaining
			if !bytes.Equal(parent.RawSubject, child.RawIssuer) {
				return fmt.Errorf("certificate at index %d: issuer name does not match parent subject at index %d", i-1, i)
			}

			if err := child.CheckSignatureFrom(parent); err != nil {
				return fmt.Errorf("certificate at index %d not signed by parent at index %d: %w", i-1, i, err)
			}

			// Ensure child certificate validity period is within parent's validity period
			if child.NotBefore.Before(parent.NotBefore) {
				return fmt.Errorf("certificate at index %d NotBefore (%v) is before parent NotBefore (%v)", i-1, child.NotBefore, parent.NotBefore)
			}
			if child.NotAfter.After(parent.NotAfter) {
				return fmt.Errorf("certificate at index %d NotAfter (%v) is after parent NotAfter (%v)", i-1, child.NotAfter, parent.NotAfter)
			}
		}
	}

	// top of chain must be valid against one of the roots
	topOfChain := chain[len(chain)-1]
	var validRoot *x509.Certificate

	for _, root := range roots {
		// Check signature from root to top of chain
		if err := topOfChain.CheckSignatureFrom(root); err == nil {
			// Validate Subject/Issuer name chaining with root
			if !bytes.Equal(root.RawSubject, topOfChain.RawIssuer) {
				continue // Skip root with mismatched subject/issuer
			}

			// Also check that the top certificate's validity period is within the root's validity period
			if topOfChain.NotBefore.Before(root.NotBefore) || topOfChain.NotAfter.After(root.NotAfter) {
				continue // This root can't validate this certificate due to timing constraints
			}
			validRoot = root
			break
		}
	}

	if validRoot == nil {
		return errors.New("chain is not issued by any known CA or validity periods don't align")
	}

	return nil
}
