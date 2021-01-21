// Copyright 2021 Herman Slatman
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package ca

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha1"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/caddyserver/caddy/v2/modules/caddypki"
	"github.com/globalsign/est"
)

const (
	csrAttrsAPS      = "csrattrs"
	triggerErrorsAPS = "triggererrors"

	defaultCertificateDuration = time.Hour * 24 * 90
)

var (
	oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}
)

type CA struct {
	pki *caddypki.CA
}

func New(pkiCA *caddypki.CA) *CA {
	return &CA{
		pki: pkiCA,
	}
}

func (c *CA) CACerts(ctx context.Context, aps string, r *http.Request) ([]*x509.Certificate, error) {
	rootCert := c.pki.RootCertificate()
	return []*x509.Certificate{rootCert}, nil
}

func (c *CA) CSRAttrs(ctx context.Context, aps string, r *http.Request) (est.CSRAttrs, error) {
	fmt.Println("CSRAttrs")
	return est.CSRAttrs{}, nil
}

func (c *CA) Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, error) {
	fmt.Println("ENROLL")
	// Process any requested triggered errors.
	if aps == triggerErrorsAPS {
		switch csr.Subject.CommonName {
		case "Trigger Error Forbidden":
			return nil, caError{
				status: http.StatusForbidden,
				desc:   "triggered forbidden response",
			}

		case "Trigger Error Deferred":
			return nil, caError{
				status:     http.StatusAccepted,
				desc:       "triggered deferred response",
				retryAfter: 600,
			}

		case "Trigger Error Unknown":
			return nil, errors.New("triggered error")
		}
	}

	// Generate certificate template, copying the raw subject and raw
	// SubjectAltName extension from the CSR.
	sn, err := rand.Int(rand.Reader, big.NewInt(1).Exp(big.NewInt(2), big.NewInt(128), nil))
	if err != nil {
		return nil, fmt.Errorf("failed to make serial number: %w", err)
	}

	ski, err := makePublicKeyIdentifier(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to make public key identifier: %w", err)
	}

	now := time.Now()
	notAfter := now.Add(defaultCertificateDuration)
	if latest := c.pki.RootCertificate().NotAfter.Sub(notAfter); latest < 0 {
		// Don't issue any certificates which expire after the CA certificate.
		notAfter = c.pki.RootCertificate().NotAfter
	}

	var tmpl = &x509.Certificate{
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
			tmpl.ExtraExtensions = append(tmpl.ExtraExtensions, ext)
			break
		}
	}

	key, err := c.pki.RootKey()
	if err != nil {
		return nil, fmt.Errorf("failed to get private key: %w", err)
	}

	// Create and return certificate.
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.pki.RootCertificate(), csr.PublicKey, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	fmt.Println("cert created")

	// TODO: probably might want to audit this creation + store (metadata of) the cert?

	return cert, nil
}

func (c *CA) Reenroll(ctx context.Context, cert *x509.Certificate, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, error) {
	fmt.Println("REENROLL")
	// TODO: a bit more with the existing cert?
	return c.Enroll(ctx, csr, aps, r)
	//return nil, nil
}

func (c *CA) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, []byte, error) {
	fmt.Println("SERVERKEYGEN")
	return nil, nil, nil
}

func (c *CA) TPMEnroll(ctx context.Context, csr *x509.CertificateRequest, ekcerts []*x509.Certificate, ekPub, akPub []byte, aps string, r *http.Request) ([]byte, []byte, []byte, error) {
	fmt.Println("TPMENROLL")
	return nil, nil, nil, nil
}

// makePublicKeyIdentifier builds a public key identifier in accordance with the
// first method described in RFC5280 section 4.2.1.2.
func makePublicKeyIdentifier(pub crypto.PublicKey) ([]byte, error) {
	keyBytes, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, err
	}

	id := sha1.Sum(keyBytes)

	return id[:], nil
}

type caError struct {
	status     int
	desc       string
	retryAfter int
}

// StatusCode returns the HTTP status code.
func (e caError) StatusCode() int {
	return e.status
}

// Error returns a human-readable description of the error.
func (e caError) Error() string {
	return e.desc
}

// RetryAfter returns the value in seconds after which the client should
// retry the request.
func (e caError) RetryAfter() int {
	return e.retryAfter
}

// type CA interface {
// 	// CACerts requests a copy of the current CA certificates. See RFC7030 4.1.
// 	CACerts(ctx context.Context, aps string, r *http.Request) ([]*x509.Certificate, error)

// 	// CSRAttrs requests a list of CA-desired CSR attributes. The returned list
// 	// may be empty. See RFC7030 4.5.
// 	CSRAttrs(ctx context.Context, aps string, r *http.Request) (CSRAttrs, error)

// 	// Enroll requests a new certificate. See RFC7030 4.2.
// 	Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, error)

// 	// Reenroll requests renewal/rekey of an existing certificate. See RFC7030
// 	// 4.2.
// 	Reenroll(ctx context.Context, cert *x509.Certificate, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, error)

// 	// ServerKeyGen requests a new certificate and a private key. The key must
// 	// be returned as a DER-encoded PKCS8 PrivateKeyInfo structure if additional
// 	// encryption is not being employed, or returned inside a CMS SignedData
// 	// structure which itself is inside a CMS EnvelopedData structure. See
// 	// RFC7030 4.4.
// 	ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, []byte, error)

// 	// TPMEnroll requests a new certificate using the TPM 2.0 privacy-preserving
// 	// protocol. An EK certificate chain with a length of at least one must be
// 	// provided, along with the EK and AK public areas. The return values are an
// 	// encrypted credential blob, an encrypted seed, and the certificate itself
// 	// inside a CMS EnvelopedData encrypted with the credential as a pre-shared
// 	// key.
// 	TPMEnroll(ctx context.Context, csr *x509.CertificateRequest, ekcerts []*x509.Certificate, ekPub, akPub []byte, aps string, r *http.Request) ([]byte, []byte, []byte, error)
// }
