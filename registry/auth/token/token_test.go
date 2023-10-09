package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/distribution/distribution/v3/context"
	"github.com/distribution/distribution/v3/registry/auth"
	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
)

func makeTrustedKeyMap(rootKeys []key) map[string]crypto.PublicKey {
	trustedKeys := make(map[string]crypto.PublicKey, len(rootKeys))

	for _, rootKey := range rootKeys {
		trustedKeys[rootKey.KeyID()] = rootKey.pub
	}

	return trustedKeys
}

func makeRootKeys(numKeys int) ([]key, error) {
	rootKeys := make([]key, 0, numKeys)

	for i := 0; i < numKeys; i++ {
		pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		rootKey := key{priv: pk, pub: pk.Public()}
		rootKeys = append(rootKeys, rootKey)
	}

	return rootKeys, nil
}

func makeRootCerts(rootKeys []key) ([]*x509.Certificate, error) {
	rootCerts := make([]*x509.Certificate, 0, len(rootKeys))

	for _, rootKey := range rootKeys {
		cert, err := GenerateCACert(rootKey, rootKey)
		if err != nil {
			return nil, err
		}
		rootCerts = append(rootCerts, cert)
	}

	return rootCerts, nil
}

func makeSigningKeyWithChain(rootKey key, depth int) (*jose.JSONWebKey, error) {
	if depth == 0 {
		// Don't need to build a chain.
		return &jose.JSONWebKey{
			Key:       rootKey.priv,
			KeyID:     rootKey.KeyID(),
			Algorithm: string(jose.ES256),
		}, nil
	}

	var (
		certs     = make([]*x509.Certificate, depth)
		parentKey = rootKey

		pk   *ecdsa.PrivateKey
		cert *x509.Certificate
		err  error
	)

	for depth > 0 {
		if pk, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
			return nil, err
		}

		trustedKey := key{priv: pk, pub: pk.Public()}
		if cert, err = GenerateCACert(parentKey, trustedKey); err != nil {
			return nil, err
		}

		depth--
		certs[depth] = cert
		parentKey = key{priv: pk, pub: pk.Public()}
	}

	return &jose.JSONWebKey{
		Key:          parentKey.priv,
		KeyID:        rootKey.KeyID(),
		Algorithm:    string(jose.ES256),
		Certificates: certs,
	}, nil
}

func makeTestToken(issuer, audience string, access []*ResourceActions, rootKey key, depth int, now time.Time, exp time.Time) (*Token, error) {
	jwk, err := makeSigningKeyWithChain(rootKey, depth)
	if err != nil {
		return nil, fmt.Errorf("unable to make signing key with chain: %s", err)
	}

	signingKey := jose.SigningKey{
		Algorithm: jose.ES256,
		Key:       jwk,
	}
	signerOpts := jose.SignerOptions{
		EmbedJWK: true,
	}
	signerOpts.WithType("JWT")

	signer, err := jose.NewSigner(signingKey, &signerOpts)
	if err != nil {
		return nil, fmt.Errorf("unable to create a signer: %s", err)
	}

	randomBytes := make([]byte, 15)
	if _, err = rand.Read(randomBytes); err != nil {
		return nil, fmt.Errorf("unable to read random bytes for jwt id: %s", err)
	}

	claimSet := &ClaimSet{
		Issuer:     issuer,
		Subject:    "foo",
		Audience:   []string{audience},
		Expiration: exp.Unix(),
		NotBefore:  now.Unix(),
		IssuedAt:   now.Unix(),
		JWTID:      base64.URLEncoding.EncodeToString(randomBytes),
		Access:     access,
	}

	tokenString, err := jwt.Signed(signer).Claims(claimSet).CompactSerialize()
	if err != nil {
		return nil, fmt.Errorf("unable to build token string: %v", err)
	}

	return NewToken(tokenString)
}

// This test makes 4 tokens with a varying number of intermediate
// certificates ranging from no intermediate chain to a length of 3
// intermediates.
func TestTokenVerify(t *testing.T) {
	var (
		numTokens = 4
		issuer    = "test-issuer"
		audience  = "test-audience"
		access    = []*ResourceActions{
			{
				Type:    "repository",
				Name:    "foo/bar",
				Actions: []string{"pull", "push"},
			},
		}
	)

	rootKeys, err := makeRootKeys(numTokens)
	if err != nil {
		t.Fatal(err)
	}

	rootCerts, err := makeRootCerts(rootKeys)
	if err != nil {
		t.Fatal(err)
	}

	rootPool := x509.NewCertPool()
	for _, rootCert := range rootCerts {
		rootPool.AddCert(rootCert)
	}

	trustedKeys := makeTrustedKeyMap(rootKeys)

	tokens := make([]*Token, 0, numTokens)

	for i := 0; i < numTokens; i++ {
		token, err := makeTestToken(issuer, audience, access, rootKeys[i], i, time.Now(), time.Now().Add(5*time.Minute))
		if err != nil {
			t.Fatal(err)
		}
		tokens = append(tokens, token)
	}

	verifyOps := VerifyOptions{
		TrustedIssuers:    []string{issuer},
		AcceptedAudiences: []string{audience},
		Roots:             rootPool,
		TrustedKeys:       trustedKeys,
	}

	for _, token := range tokens {
		if _, err := token.Verify(verifyOps); err != nil {
			t.Fatal(err)
		}
	}
}

// This tests that we don't fail tokens with nbf within
// the defined leeway in seconds
func TestLeeway(t *testing.T) {
	var (
		issuer   = "test-issuer"
		audience = "test-audience"
		access   = []*ResourceActions{
			{
				Type:    "repository",
				Name:    "foo/bar",
				Actions: []string{"pull", "push"},
			},
		}
	)

	rootKeys, err := makeRootKeys(1)
	if err != nil {
		t.Fatal(err)
	}

	trustedKeys := makeTrustedKeyMap(rootKeys)

	verifyOps := VerifyOptions{
		TrustedIssuers:    []string{issuer},
		AcceptedAudiences: []string{audience},
		Roots:             nil,
		TrustedKeys:       trustedKeys,
	}

	// nbf verification should pass within leeway
	futureNow := time.Now().Add(time.Duration(5) * time.Second)
	token, err := makeTestToken(issuer, audience, access, rootKeys[0], 0, futureNow, futureNow.Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := token.Verify(verifyOps); err != nil {
		t.Fatal(err)
	}

	// nbf verification should fail with a skew larger than leeway
	futureNow = time.Now().Add(time.Duration(61) * time.Second)
	token, err = makeTestToken(issuer, audience, access, rootKeys[0], 0, futureNow, futureNow.Add(5*time.Minute))
	if err != nil {
		t.Fatal(err)
	}

	if _, err = token.Verify(verifyOps); err == nil {
		t.Fatal("Verification should fail for token with nbf in the future outside leeway")
	}

	// exp verification should pass within leeway
	token, err = makeTestToken(issuer, audience, access, rootKeys[0], 0, time.Now(), time.Now().Add(-59*time.Second))
	if err != nil {
		t.Fatal(err)
	}

	if _, err = token.Verify(verifyOps); err != nil {
		t.Fatal(err)
	}

	// exp verification should fail with a skew larger than leeway
	token, err = makeTestToken(issuer, audience, access, rootKeys[0], 0, time.Now(), time.Now().Add(-60*time.Second))
	if err != nil {
		t.Fatal(err)
	}

	if _, err = token.Verify(verifyOps); err == nil {
		t.Fatal("Verification should fail for token with exp in the future outside leeway")
	}
}

func writeTempRootCerts(rootKeys []key) (filename string, err error) {
	rootCerts, err := makeRootCerts(rootKeys)
	if err != nil {
		return "", err
	}

	tempFile, err := os.CreateTemp("", "rootCertBundle")
	if err != nil {
		return "", err
	}
	defer tempFile.Close()

	for _, cert := range rootCerts {
		if err = pem.Encode(tempFile, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}); err != nil {
			os.Remove(tempFile.Name())
			return "", err
		}
	}

	return tempFile.Name(), nil
}

// TestAccessController tests complete integration of the token auth package.
// It starts by mocking the options for a token auth accessController which
// it creates. It then tries a few mock requests:
//   - don't supply a token; should error with challenge
//   - supply an invalid token; should error with challenge
//   - supply a token with insufficient access; should error with challenge
//   - supply a valid token; should not error
func TestAccessController(t *testing.T) {
	// Make 2 keys; only the first is to be a trusted root key.
	rootKeys, err := makeRootKeys(2)
	if err != nil {
		t.Fatal(err)
	}

	rootCertBundleFilename, err := writeTempRootCerts(rootKeys[:1])
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(rootCertBundleFilename)

	realm := "https://auth.example.com/token/"
	issuer := "test-issuer.example.com"
	service := "test-service.example.com"

	options := map[string]interface{}{
		"realm":          realm,
		"issuer":         issuer,
		"service":        service,
		"rootcertbundle": rootCertBundleFilename,
		"autoredirect":   false,
	}

	accessController, err := newAccessController(options)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Make a mock http.Request with no token.
	req, err := http.NewRequest(http.MethodGet, "http://example.com/foo", nil)
	if err != nil {
		t.Fatal(err)
	}

	testAccess := auth.Access{
		Resource: auth.Resource{
			Type: "foo",
			Name: "bar",
		},
		Action: "baz",
	}

	ctx := context.WithRequest(context.Background(), req)
	authCtx, err := accessController.Authorized(ctx, testAccess)
	challenge, ok := err.(auth.Challenge)
	if !ok {
		t.Fatal("accessController did not return a challenge")
	}

	if challenge.Error() != ErrTokenRequired.Error() {
		t.Fatalf("accessControler did not get expected error - got %s - expected %s", challenge, ErrTokenRequired)
	}

	if authCtx != nil {
		t.Fatalf("expected nil auth context but got %s", authCtx)
	}

	// 2. Supply an invalid token.
	token, err := makeTestToken(
		issuer, service,
		[]*ResourceActions{{
			Type:    testAccess.Type,
			Name:    testAccess.Name,
			Actions: []string{testAccess.Action},
		}},
		rootKeys[1], 1, time.Now(), time.Now().Add(5*time.Minute), // Everything is valid except the key which signed it.
	)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.Raw))

	authCtx, err = accessController.Authorized(ctx, testAccess)
	challenge, ok = err.(auth.Challenge)
	if !ok {
		t.Fatal("accessController did not return a challenge")
	}

	if challenge.Error() != ErrInvalidToken.Error() {
		t.Fatalf("accessControler did not get expected error - got %s - expected %s", challenge, ErrTokenRequired)
	}

	if authCtx != nil {
		t.Fatalf("expected nil auth context but got %s", authCtx)
	}

	// 3. Supply a token with insufficient access.
	token, err = makeTestToken(
		issuer, service,
		[]*ResourceActions{}, // No access specified.
		rootKeys[0], 1, time.Now(), time.Now().Add(5*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.Raw))

	authCtx, err = accessController.Authorized(ctx, testAccess)
	challenge, ok = err.(auth.Challenge)
	if !ok {
		t.Fatal("accessController did not return a challenge")
	}

	if challenge.Error() != ErrInsufficientScope.Error() {
		t.Fatalf("accessControler did not get expected error - got %s - expected %s", challenge, ErrInsufficientScope)
	}

	if authCtx != nil {
		t.Fatalf("expected nil auth context but got %s", authCtx)
	}

	// 4. Supply the token we need, or deserve, or whatever.
	token, err = makeTestToken(
		issuer, service,
		[]*ResourceActions{{
			Type:    testAccess.Type,
			Name:    testAccess.Name,
			Actions: []string{testAccess.Action},
		}},
		rootKeys[0], 1, time.Now(), time.Now().Add(5*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.Raw))

	authCtx, err = accessController.Authorized(ctx, testAccess)
	if err != nil {
		t.Fatalf("accessController returned unexpected error: %s", err)
	}

	userInfo, ok := authCtx.Value(auth.UserKey).(auth.UserInfo)
	if !ok {
		t.Fatal("token accessController did not set auth.user context")
	}

	if userInfo.Name != "foo" {
		t.Fatalf("expected user name %q, got %q", "foo", userInfo.Name)
	}

	// 5. Supply a token with full admin rights, which is represented as "*".
	token, err = makeTestToken(
		issuer, service,
		[]*ResourceActions{{
			Type:    testAccess.Type,
			Name:    testAccess.Name,
			Actions: []string{"*"},
		}},
		rootKeys[0], 1, time.Now(), time.Now().Add(5*time.Minute),
	)
	if err != nil {
		t.Fatal(err)
	}

	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", token.Raw))

	_, err = accessController.Authorized(ctx, testAccess)
	if err != nil {
		t.Fatalf("accessController returned unexpected error: %s", err)
	}
}

// This tests that newAccessController can handle PEM blocks in the certificate
// file other than certificates, for example a private key.
func TestNewAccessControllerPemBlock(t *testing.T) {
	rootKeys, err := makeRootKeys(2)
	if err != nil {
		t.Fatal(err)
	}

	rootCertBundleFilename, err := writeTempRootCerts(rootKeys)
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(rootCertBundleFilename)

	// Add something other than a certificate to the rootcertbundle
	file, err := os.OpenFile(rootCertBundleFilename, os.O_WRONLY|os.O_APPEND, 0o666)
	if err != nil {
		t.Fatal(err)
	}
	keyBlock, err := rootKeys[0].PEMBlock()
	if err != nil {
		t.Fatal(err)
	}
	err = pem.Encode(file, keyBlock)
	if err != nil {
		t.Fatal(err)
	}
	err = file.Close()
	if err != nil {
		t.Fatal(err)
	}

	realm := "https://auth.example.com/token/"
	issuer := "test-issuer.example.com"
	service := "test-service.example.com"

	options := map[string]interface{}{
		"realm":          realm,
		"issuer":         issuer,
		"service":        service,
		"rootcertbundle": rootCertBundleFilename,
		"autoredirect":   false,
	}

	ac, err := newAccessController(options)
	if err != nil {
		t.Fatal(err)
	}

	if len(ac.(*accessController).rootCerts.Subjects()) != 2 { //nolint:staticcheck // FIXME(thaJeztah): ignore SA1019: ac.(*accessController).rootCerts.Subjects has been deprecated since Go 1.18: if s was returned by SystemCertPool, Subjects will not include the system roots. (staticcheck)
		t.Fatal("accessController has the wrong number of certificates")
	}
}
