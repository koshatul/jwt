package jwt

import (
	"crypto/rsa"
	"errors"
	"strings"
	"time"

	"github.com/pascaldekloe/jwt"
)

// ErrTokenInvalidAudience is the error returned when an audience does not match the token.
var ErrTokenInvalidAudience = errors.New("invalid token audience")

// ErrTokenTimeNotValid is the general error returned when a token is outside the NotBefore or Expires times.
var ErrTokenTimeNotValid = errors.New("token time is not valid")

// // ErrTokenHasExpired is the error returned when a token has expired
// var ErrTokenHasExpired = errors.New("token has expired")

// // ErrTokenIsNotValidYet is the error returned when a token is not yet valid (this should be exceedingly rare, almost impossible without time skewing)
// var ErrTokenIsNotValidYet = errors.New("token is not yet valid")

// VerifyResult returns the information about the token verification.
type VerifyResult struct {
	ID          string
	IsOnline    bool
	Subject     string
	Audience    string
	Fingerprint string
	NotBefore   time.Time
	Expires     time.Time
	Claims      map[string]Claim
}

// Verifier takes a token and returns the subject if it is valid, or an error if it is not.
type Verifier interface {
	// Verify processes a supplied token
	Verify(token []byte) (VerifyResult, error)
}

// RSAVerifier implements the `Verifier` interface and tests a token signed with RSA public/private keys.
type RSAVerifier struct {
	PublicKey *rsa.PublicKey
	Issuer    string
	Audience  string
	// Algorithms []string
}

// NewRSAVerifierFromFile returns an `RSAVerifier` initialized with the RSA Public Key supplied and an audience for token verification.
func NewRSAVerifierFromFile(audience, filename string) (Verifier, error) {
	publicKey, err := ParsePKCS1PublicKeyFromFile(filename)
	if err != nil {
		return nil, err
	}
	return &RSAVerifier{
		Audience:  audience,
		PublicKey: publicKey,
		// Algorithms: []string{jwt.RS256, jwt.RS384, jwt.RS512},
	}, nil
}

func (v *RSAVerifier) getClaimMapFromClaims(claims *jwt.Claims) (map[string]Claim, error) {
	c := make(map[string]Claim)
	for k, v := range claims.Set {
		switch k {
		case NotBefore, Expires, Issued:
			if f, ok := claims.Number(k); ok {
				t := time.Unix(0, int64(f*float64(time.Second)))
				c[k] = Time(k, t)
			} else {
				return c, ErrInvalidClaimType
			}
		default:
			c[k] = Any(k, v)
		}
	}
	return c, nil
}

// Verify takes the token and checks it's signature against the RSA public key, and the audience, notbefore and expires validity.
func (v *RSAVerifier) Verify(token []byte) (VerifyResult, error) {
	checkTime := time.Now()
	result := VerifyResult{}
	claims, err := jwt.RSACheck(token, v.PublicKey)
	if err != nil {
		return result, err
	}
	// // Not a great use-case.
	// if v.Audience != "" && !strings.EqualFold(v.Audience, claims.Audience) {
	// 	return result, ErrTokenInvalidAudience
	// }
	if !strings.EqualFold(v.Audience, claims.Audience) {
		return result, ErrTokenInvalidAudience
	}
	if !claims.Valid(checkTime) {
		return result, ErrTokenTimeNotValid
	}
	online := false
	if val, ok := claims.Set["onl"]; ok {
		online = val.(bool)
	}
	fingerprint := ""
	if val, ok := claims.Set["fpt"]; ok {
		fingerprint = val.(string)
	}
	result = VerifyResult{
		Subject:     claims.Subject,
		IsOnline:    online,
		ID:          claims.ID,
		Audience:    claims.Audience,
		Fingerprint: fingerprint,
		NotBefore:   time.Time{},
		Expires:     time.Time{},
	}
	if claims.NotBefore != nil {
		result.NotBefore = claims.NotBefore.Time()
	}
	if claims.Expires != nil {
		result.Expires = claims.Expires.Time()
	}
	result.Claims, err = v.getClaimMapFromClaims(claims)
	return result, err
}
