package ca

import (
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"
)

func generateTemplate(caRoot *x509.Certificate, csr *x509.CertificateRequest) (*x509.Certificate, error) {

	// Generate certificate template, copying the raw subject and raw
	// SubjectAltName extension from the CSR.
	sn, err := rand.Int(rand.Reader, big.NewInt(1).Exp(big.NewInt(2), big.NewInt(128), nil))
	if err != nil {
		return nil, fmt.Errorf("failed to make serial number: %w", err)
	}

	ski, err := createKeyIdentifier(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to make public key identifier: %w", err)
	}

	now := time.Now()
	notAfter := now.Add(defaultCertificateDuration)
	if latest := caRoot.NotAfter.Sub(notAfter); latest < 0 {
		// Don't issue any certificates which expire after the CA certificate.
		notAfter = caRoot.NotAfter
	}

	template := &x509.Certificate{
		SerialNumber:          sn,
		NotBefore:             now,
		NotAfter:              notAfter,
		RawSubject:            csr.RawSubject,
		SubjectKeyId:          ski,
		BasicConstraintsValid: true,
		IsCA:                  false,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	for _, ext := range csr.Extensions {
		if ext.Id.Equal(oidSubjectAltName) {
			template.ExtraExtensions = append(template.ExtraExtensions, ext)
			break
		}
	}

	return template, nil

}

// createKeyIdentifier create an identifier for public keys
// according to the first method in RFC5280 section 4.2.1.2.
func createKeyIdentifier(pub crypto.PublicKey) ([]byte, error) {

	keyBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	id := sha1.Sum(keyBytes)

	return id[:], nil
}
