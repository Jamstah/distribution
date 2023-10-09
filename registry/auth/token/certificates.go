package token

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"
)

// NOTE(milosgajdos): certTemplateInfo type as well
// as some of the functions in this file have been
// adopted from https://github.com/docker/libtrust
// and modiified to fit the purpose of the token package.

type certTemplateInfo struct {
	commonName  string
	domains     []string
	ipAddresses []net.IP
	isCA        bool
	clientAuth  bool
	serverAuth  bool
}

func generateCertTemplate(info *certTemplateInfo) *x509.Certificate {
	// Generate a certificate template which is valid from the past week to
	// 10 years from now. The usage of the certificate depends on the
	// specified fields in the given certTempInfo object.
	var (
		keyUsage    x509.KeyUsage
		extKeyUsage []x509.ExtKeyUsage
	)

	if info.isCA {
		keyUsage = x509.KeyUsageCertSign
	}

	if info.clientAuth {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageClientAuth)
	}

	if info.serverAuth {
		extKeyUsage = append(extKeyUsage, x509.ExtKeyUsageServerAuth)
	}

	return &x509.Certificate{
		SerialNumber: big.NewInt(0),
		Subject: pkix.Name{
			CommonName: info.commonName,
		},
		NotBefore:             time.Now().Add(-time.Hour * 24 * 7),
		NotAfter:              time.Now().Add(time.Hour * 24 * 365 * 10),
		DNSNames:              info.domains,
		IPAddresses:           info.ipAddresses,
		IsCA:                  info.isCA,
		KeyUsage:              keyUsage,
		ExtKeyUsage:           extKeyUsage,
		BasicConstraintsValid: info.isCA,
	}
}

func generateCert(priv crypto.PrivateKey, pub crypto.PublicKey, subInfo, issInfo *certTemplateInfo) (*x509.Certificate, error) {
	pubCertTemplate := generateCertTemplate(subInfo)
	privCertTemplate := generateCertTemplate(issInfo)

	certDER, err := x509.CreateCertificate(
		rand.Reader, pubCertTemplate, privCertTemplate,
		pub, priv,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %s", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %s", err)
	}

	return cert, nil
}

// GenerateCACert creates a certificate which can be used as a trusted
// certificate authority.
func GenerateCACert(signer key, trustedKey key) (*x509.Certificate, error) {
	subjectInfo := &certTemplateInfo{
		commonName: trustedKey.KeyID(),
		isCA:       true,
	}
	issuerInfo := &certTemplateInfo{
		commonName: signer.KeyID(),
	}

	return generateCert(signer.priv, trustedKey.pub, subjectInfo, issuerInfo)
}
