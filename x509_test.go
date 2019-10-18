package jwt_test

import (
	"crypto/rsa"
	"encoding/asn1"
	"os"

	"github.com/koshatul/jwt/v2"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("x509 File Operations", func() {

	It("should succeed, public key from afs", func() {
		publicKey, err := jwt.ParsePKCS1PublicKeyFromFileAFS(afs, "cert.pem")
		Expect(err).NotTo(HaveOccurred())
		Expect(publicKey).To(BeAssignableToTypeOf(&rsa.PublicKey{}))
	})

	It("should succeed, private key from afs", func() {
		privateKey, err := jwt.ParsePKCS1PrivateKeyFromFileAFS(afs, "key.pem")
		Expect(err).NotTo(HaveOccurred())
		Expect(privateKey).To(BeAssignableToTypeOf(&rsa.PrivateKey{}))
	})

	It("should fail, public key from afs, invalid file", func() {
		publicKey, err := jwt.ParsePKCS1PublicKeyFromFileAFS(afs, "cert2.pem")
		Expect(err).To(BeAssignableToTypeOf(&os.PathError{}))
		Expect(publicKey).To(BeNil())
	})

	It("should fail, private key from afs, invalid file", func() {
		privateKey, err := jwt.ParsePKCS1PrivateKeyFromFileAFS(afs, "key2.pem")
		Expect(err).To(BeAssignableToTypeOf(&os.PathError{}))
		Expect(privateKey).To(BeNil())
	})

	It("should fail, public key from afs, loading wrong type", func() {
		publicKey, err := jwt.ParsePKCS1PublicKeyFromFileAFS(afs, "key.pem")
		Expect(err).To(BeAssignableToTypeOf(asn1.StructuralError{}))
		Expect(publicKey).To(BeNil())
	})

	It("should fail, private key from afs, loading wrong type", func() {
		privateKey, err := jwt.ParsePKCS1PrivateKeyFromFileAFS(afs, "cert.pem")
		Expect(err).To(BeAssignableToTypeOf(asn1.StructuralError{}))
		Expect(privateKey).To(BeNil())
	})

})
