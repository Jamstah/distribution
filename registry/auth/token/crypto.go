package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base32"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// NOTE(milosgajdos): some of the functions in this
// file have been adopted from https://github.com/docker/libtrust
// and modiified to fit the purpose of the token package.

// key is an asymetric pair of cryptographic keys.
type key struct {
	priv crypto.PrivateKey
	pub  crypto.PublicKey
}

// KeyID returns a kid compatible with
// libtrust fingerprint format.
func (k *key) KeyID() string {
	return keyIDFromCryptoKey(k.pub)
}

// PEMBlock serializes this Private Key to DER-encoded PKIX format.
func (k *key) PEMBlock() (*pem.Block, error) {
	var (
		err      error
		derBytes []byte
	)
	switch cryptoPrivateKey := k.priv.(type) {
	case *ecdsa.PrivateKey:
		derBytes, err = x509.MarshalECPrivateKey(cryptoPrivateKey)
	case *rsa.PrivateKey:
		derBytes = x509.MarshalPKCS1PrivateKey(cryptoPrivateKey)
	default:
		return nil, fmt.Errorf("private key type %T is not supported", cryptoPrivateKey)
	}

	if err != nil {
		return nil, fmt.Errorf("unable to serialize EC PrivateKey to DER-encoded PKIX format: %s", err)
	}
	headers := map[string]interface{}{
		"keyID": k.KeyID(),
	}
	return createPemBlock("PRIVATE KEY", derBytes, headers)
}

func createPemBlock(name string, derBytes []byte, headers map[string]interface{}) (*pem.Block, error) {
	pemBlock := &pem.Block{Type: name, Bytes: derBytes, Headers: map[string]string{}}
	for k, v := range headers {
		switch val := v.(type) {
		case string:
			pemBlock.Headers[k] = val
		case []string:
			if k == "hosts" {
				pemBlock.Headers[k] = strings.Join(val, ",")
			} else {
				return nil, fmt.Errorf("unsupported header type: %s", k)
			}
		default:
			return nil, errors.New("unsupported header value")
		}
	}

	return pemBlock, nil
}

func keyIDEncode(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	s := strings.TrimRight(base32.StdEncoding.EncodeToString(b), "=")
	var buf strings.Builder
	buf.Grow(len(s) * 5 / 4)
	for len(s) > 4 {
		buf.WriteString(s[:4])
		buf.WriteByte(':')
		s = s[4:]
	}
	buf.WriteString(s)
	return buf.String()
}

func keyIDFromCryptoKey(pubKey crypto.PublicKey) string {
	// Generate and return a fingerprint of the public key.
	// For an RSA key this should be:
	//   SHA256(DER encoded ASN1)
	// Then truncated to 240 bits and encoded into 12 base32 groups like so:
	//   ABCD:EFGH:IJKL:MNOP:QRST:UVWX:YZ23:4567:ABCD:EFGH:IJKL:MNOP
	derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return ""
	}
	hasher := crypto.SHA256.New()
	hasher.Write(derBytes)
	return keyIDEncode(hasher.Sum(nil)[:30])
}
