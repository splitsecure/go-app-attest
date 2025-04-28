package mint

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

type MintContext struct {
	CAKey     *ecdsa.PrivateKey
	CACertDer []byte

	IntKey     *ecdsa.PrivateKey
	IntCertDer []byte
}

func (mc *MintContext) DumpToDir(p string) error {
	err := os.MkdirAll(p, 0700)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}

	blk := pem.Block{
		Bytes: mc.CACertDer,
		Type:  "CERTIFICATE",
	}

	if err := os.WriteFile(filepath.Join(p, "ca.crt"), pem.EncodeToMemory(&blk), 0755); err != nil {
		return err
	}

	cakeybuf, err := x509.MarshalECPrivateKey(mc.CAKey)
	if err != nil {
		return err
	}
	blk = pem.Block{
		Bytes: cakeybuf,
		Type:  "EC PRIVATE KEY",
	}
	if err := os.WriteFile(filepath.Join(p, "ca.key"), pem.EncodeToMemory(&blk), 0755); err != nil {
		return err
	}

	blk = pem.Block{
		Bytes: mc.IntCertDer,
		Type:  "CERTIFICATE",
	}
	if err := os.WriteFile(filepath.Join(p, "int.crt"), pem.EncodeToMemory(&blk), 0755); err != nil {
		return err
	}

	intkeybuf, err := x509.MarshalECPrivateKey(mc.IntKey)
	if err != nil {
		return err
	}
	blk = pem.Block{
		Bytes: intkeybuf,
		Type:  "EC PRIVATE KEY",
	}
	if err := os.WriteFile(filepath.Join(p, "int.key"), pem.EncodeToMemory(&blk), 0755); err != nil {
		return err
	}

	return nil
}

func NewMintContext() (*MintContext, error) {

	cader, capriv, err := generateCACert("SplitSecure Apple App Attest Dev/Mock CA")
	if err != nil {
		return nil, err
	}

	intder, intpriv, err := generateIntermediateCert("SplitSecure Apple App Attest Dev/Mock Intermediate", cader, capriv)
	if err != nil {
		return nil, err
	}

	return &MintContext{
		CAKey:     capriv,
		CACertDer: cader,

		IntKey:     intpriv,
		IntCertDer: intder,
	}, nil
}

func generateCACert(commonName string) ([]byte, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(50, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            2,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}

	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}
	if err := pem.Encode(os.Stdout, pemBlock); err != nil {
		panic(err)
	}

	priv, err := x509.MarshalECPrivateKey(key)
	pemBlock = &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: priv,
	}
	if err := pem.Encode(os.Stdout, pemBlock); err != nil {
		panic(err)
	}

	return certDER, key, nil
}

func generateIntermediateCert(commonName string, parentCertDER []byte, parentKey *ecdsa.PrivateKey) ([]byte, *ecdsa.PrivateKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	parentCert, _ := x509.ParseCertificate(parentCertDER)

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(49, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	certDER, _ := x509.CreateCertificate(rand.Reader, &template, parentCert, &key.PublicKey, parentKey)
	return certDER, key, nil
}
