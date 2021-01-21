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

package est

import (
	"context"
	"crypto/x509"
	"net/http"

	"github.com/caddyserver/caddy/v2/modules/caddypki"
	"github.com/globalsign/est"
)

type CA struct {
	pki *caddypki.CA
}

func NewCA(pkiCA *caddypki.CA) *CA {
	return &CA{
		pki: pkiCA,
	}
}

func (c *CA) CACerts(ctx context.Context, aps string, r *http.Request) ([]*x509.Certificate, error) {
	rootCert := c.pki.RootCertificate()
	return []*x509.Certificate{rootCert}, nil
}

func (c *CA) CSRAttrs(ctx context.Context, aps string, r *http.Request) (est.CSRAttrs, error) {
	return est.CSRAttrs{}, nil
}

func (c *CA) Enroll(ctx context.Context, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, error) {
	return nil, nil
}

func (c *CA) Reenroll(ctx context.Context, cert *x509.Certificate, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, error) {
	return nil, nil
}

func (c *CA) ServerKeyGen(ctx context.Context, csr *x509.CertificateRequest, aps string, r *http.Request) (*x509.Certificate, []byte, error) {
	return nil, nil, nil
}

func (c *CA) TPMEnroll(ctx context.Context, csr *x509.CertificateRequest, ekcerts []*x509.Certificate, ekPub, akPub []byte, aps string, r *http.Request) ([]byte, []byte, []byte, error) {
	return nil, nil, nil, nil
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
