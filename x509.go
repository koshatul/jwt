package jwt

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/spf13/afero"
)

// ParsePKCS1PublicKeyFromFile parses a PKCS1 Public Certificate from a PEM file.
func ParsePKCS1PublicKeyFromFile(filename string) (*rsa.PublicKey, error) {
	return ParsePKCS1PublicKeyFromFileAFS(afero.NewOsFs(), filename)
}

// ParsePKCS1PublicKeyFromFileAFS parses a PKCS1 Public Certificate from a PEM file with a supplied `afero.Fs`.
func ParsePKCS1PublicKeyFromFileAFS(afs afero.Fs, filename string) (*rsa.PublicKey, error) {
	data, err := afero.ReadFile(afs, filename)
	if err != nil {
		return nil, err
	}

	return ParsePKCS1PublicKey(data)
}

// ParsePKCS1PublicKey parses a PKCS1 Public Certificate from a byte slice containing a PEM certificate.
func ParsePKCS1PublicKey(data []byte) (*rsa.PublicKey, error) {
	publicPem, _ := pem.Decode(data)

	publicCert, err := x509.ParseCertificate(publicPem.Bytes)
	if err != nil {
		return nil, err
	}

	if publicKey, ok := publicCert.PublicKey.(*rsa.PublicKey); ok {
		return publicKey, nil
	}

	return nil, errors.New("unable to parse public key from certificate")
}

// ParsePKCS1PrivateKeyFromFile parses a PKCS1 Private Key from a PEM file.
func ParsePKCS1PrivateKeyFromFile(filename string) (*rsa.PrivateKey, error) {
	return ParsePKCS1PrivateKeyFromFileAFS(afero.NewOsFs(), filename)
}

// ParsePKCS1PrivateKeyFromFileAFS parses a PKCS1 Private Key from a PEM file with a supplied `afero.Fs`.
func ParsePKCS1PrivateKeyFromFileAFS(afs afero.Fs, filename string) (*rsa.PrivateKey, error) {
	data, err := afero.ReadFile(afs, filename)
	if err != nil {
		return nil, err
	}

	return ParsePKCS1PrivateKey(data)
}

// ParsePKCS1PrivateKey parses a PKCS1 Private Key from a byte slice containing an RSA key in PEM format.
func ParsePKCS1PrivateKey(data []byte) (*rsa.PrivateKey, error) {
	privatePem, _ := pem.Decode(data)
	privateKey, err := x509.ParsePKCS1PrivateKey(privatePem.Bytes)

	return privateKey, err
}
