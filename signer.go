package jwt

import (
	"crypto/rsa"
	"time"

	"github.com/pascaldekloe/jwt"
)

const (
	// RS256 RSASSA-PKCS1-v1_5 with SHA-256
	RS256 = jwt.RS256
	// RS384 RSASSA-PKCS1-v1_5 with SHA-348
	RS384 = jwt.RS384
	// RS512 RSASSA-PKCS1-v1_5 with SHA-512
	RS512 = jwt.RS512
)

// ErrAlgorithmUnknown signals an unsupported "alg" token (for the respective method).
var ErrAlgorithmUnknown = jwt.ErrAlgUnk

// Signer produces a token from a supplied subject and audience with notbefore and expiry times.
type Signer interface {
	SignClaims(claims ...Claim) ([]byte, error)
}

// RSASigner implements the `Signer` interface and creates a token signed with RSA public/private keys.
type RSASigner struct {
	PrivateKey *rsa.PrivateKey
	Issuer     string
	Algorithm  string
}

// NewRSASignerFromFile returns an `RSASigner` initialized with the RSA Private Key supplied.
func NewRSASignerFromFile(filename string) (Signer, error) {
	privateKey, err := ParsePKCS1PrivateKeyFromFile(filename)
	if err != nil {
		return nil, err
	}
	return &RSASigner{
		PrivateKey: privateKey,
		Algorithm:  jwt.RS256,
	}, nil
}

// SignClaims takes a list of claims and produces a signed token.
// Duplicate keys will we overridden in order of apearance!
// The issuer defaults to r.Issuer.
func (r *RSASigner) SignClaims(claims ...Claim) ([]byte, error) {

	tokenClaims, err := ConstructClaimsFromSlice(
		append(
			[]Claim{String("iss", r.Issuer)},
			claims...,
		)...,
	)
	if err != nil {
		return nil, err
	}
	token, err := tokenClaims.RSASign(r.Algorithm, r.PrivateKey)
	return token, err
}

// Sign takes a signer, subject, audience, online status, notBefore and expiry and produces a signed token
func Sign(signer Signer, subject, audience string, online bool, notBefore, expiry time.Time) ([]byte, error) {
	return signer.SignClaims(
		String(Subject, subject),
		String(Audience, audience),
		Bool("onl", online),
		Time(NotBefore, notBefore),
		Time(Expires, expiry),
	)
}

// SignFingerprint takes a signer, subject, audience, fingerprint, online status, notBefore and expiry and produces a signed token
func SignFingerprint(signer Signer, subject, audience, fingerprint string, online bool, notBefore, expiry time.Time) ([]byte, error) {
	return signer.SignClaims(
		String(Subject, subject),
		String(Audience, audience),
		Bool("onl", online),
		Time(NotBefore, notBefore),
		Time(Expires, expiry),
		String("fpt", fingerprint),
	)
}
