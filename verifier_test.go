package jwt_test

import (
	"time"

	"github.com/koshatul/jwt/v2"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/ginkgo/extensions/table"
	. "github.com/onsi/gomega"
)

var _ = Describe("JWT Verifier", func() {

	var signer jwt.Signer
	var verifier jwt.Verifier

	BeforeEach(func() {
		signer = createSigner()
		verifier = createVerifier()
	})

	DescribeTable("should succeed",
		func(subject, audience string, online bool, nbf, exp time.Time) {
			token, err := jwt.Sign(signer, subject, audience, online, nbf, exp)
			Expect(err).NotTo(HaveOccurred())
			Expect(token).NotTo(BeEmpty())

			result, err := verifier.Verify(token)
			Expect(err).NotTo(HaveOccurred())
			Expect(result.ID).NotTo(BeEmpty())
			Expect(result.Fingerprint).To(BeEmpty())
			Expect(result.Subject).To(Equal(subject))
			Expect(result.Audiences).To(ContainElement(audience))
			Expect(result.IsOnline).To(Equal(online))
			Expect(result.NotBefore).To(BeTemporally("~", nbf, time.Microsecond))
			Expect(result.Expires).To(BeTemporally("~", exp, time.Microsecond))

			Expect(result.Claims[jwt.Subject]).To(ContainElement(jwt.String(jwt.Subject, subject)))
			Expect(result.Claims["onl"]).To(ContainElement(jwt.Bool("onl", online)))
			Expect(result.Claims[jwt.Audience]).To(ContainElement(jwt.String(jwt.Audience, audience)))
		},
		Entry(
			"standard token",
			"subject", "audience", false, time.Now().Add(-1*time.Minute).UTC(), time.Now().Add(time.Hour).UTC(),
		),
		Entry(
			"offline with array of claims",
			"subject", "audience", false, time.Now().Add(-1*time.Minute).UTC(), time.Now().Add(time.Hour).UTC(),
		),
		Entry(
			"online with array of claims",
			"subject", "audience", true, time.Now().Add(-1*time.Minute).UTC(), time.Now().Add(time.Hour).UTC(),
		),
	)

	It("should succeed, with multiple audiences, returning matched audience", func() {
		issued, err := time.Parse(time.RFC3339, "2006-01-02T15:04:05Z")
		Expect(err).NotTo(HaveOccurred())

		token, err := signer.SignClaims(
			jwt.String(jwt.Subject, "multi-audience-test"),
			jwt.String(jwt.Audience, "audience2"),
			jwt.String(jwt.Audience, "audience"),
			jwt.String(jwt.Audience, "audience3"),
			jwt.Any("custom", issued),
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Audiences).To(ContainElement("audience"))
	})

	It("should succeed, with array of claims", func() {
		notBefore := time.Now().UTC()
		expiry := time.Now().Add(time.Hour).UTC()
		token, err := jwt.Sign(signer, "subject", "audience", false, notBefore, expiry)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.IsOnline).To(BeFalse())
		Expect(result.Subject).To(Equal("subject"))
		Expect(result.ID).NotTo(BeEmpty())
		Expect(result.Audiences).To(ContainElement("audience"))
		Expect(result.Fingerprint).To(BeEmpty())
		Expect(result.NotBefore).To(BeTemporally("~", notBefore, time.Microsecond))
		Expect(result.Expires).To(BeTemporally("~", expiry, time.Microsecond))

		Expect(result.Claims[jwt.Subject]).To(ContainElement(jwt.String(jwt.Subject, "subject")))
		Expect(result.Claims["onl"]).To(ContainElement(jwt.Bool("onl", false)))
		Expect(result.Claims[jwt.Audience]).To(ContainElement(jwt.String(jwt.Audience, "audience")))

		nbf := result.Claims[jwt.NotBefore][0]
		nbfTime, nbfErr := nbf.Time()
		Expect(nbfErr).NotTo(HaveOccurred())
		Expect(nbfTime).To(BeTemporally("~", notBefore, time.Microsecond))
	})

	It("should succeed, claim:Issued", func() {
		issued, err := time.Parse(time.RFC3339, "2006-01-02T15:04:05Z")
		Expect(err).NotTo(HaveOccurred())

		token, err := signer.SignClaims(
			jwt.String(jwt.Subject, "subject"),
			jwt.String(jwt.Audience, "audience"),
			jwt.Time(jwt.Issued, issued),
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Subject).To(Equal("subject"))
		Expect(result.ID).NotTo(BeEmpty())
		Expect(result.Audiences).To(ContainElement("audience"))
		Expect(result.Fingerprint).To(BeEmpty())

		Expect(result.Claims[jwt.Issued]).To(ContainElement(jwt.Time(jwt.Issued, issued)))
	})

	It("should succeed, claim:Issuer", func() {
		token, err := signer.SignClaims(
			jwt.String(jwt.Subject, "subject"),
			jwt.String(jwt.Audience, "audience"),
			jwt.String(jwt.Issuer, "Acme-Widgets"),
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Subject).To(Equal("subject"))
		Expect(result.ID).NotTo(BeEmpty())
		Expect(result.Audiences).To(ContainElement("audience"))
		Expect(result.Fingerprint).To(BeEmpty())

		Expect(result.Claims[jwt.Issuer]).To(ContainElement(jwt.String(jwt.Issuer, "Acme-Widgets")))
	})

	It("should succeed, claim:custom(time type)", func() {
		issued, err := time.Parse(time.RFC3339, "2006-01-02T15:04:05Z")
		Expect(err).NotTo(HaveOccurred())

		token, err := signer.SignClaims(
			jwt.String(jwt.Subject, "subject"),
			jwt.String(jwt.Audience, "audience"),
			jwt.Any("custom", issued),
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.ID).NotTo(BeEmpty())
		Expect(result.Subject).To(Equal("subject"))
		Expect(result.Audiences).To(ContainElement("audience"))

		Expect(result.Claims["custom"][0].Time()).To(BeTemporally("~", issued, time.Second))
	})

	It("should succeed, claim:custom(string type)", func() {
		token, err := signer.SignClaims(
			jwt.String(jwt.Subject, "subject"),
			jwt.String(jwt.Audience, "audience"),
			jwt.Any("custom", "foobar"),
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Claims["custom"]).To(ContainElement(jwt.String("custom", "foobar")))
	})

	It("should succeed, claim:custom(int type)", func() {
		intVal := 99
		token, err := signer.SignClaims(
			jwt.String(jwt.Subject, "subject"),
			jwt.String(jwt.Audience, "audience"),
			jwt.Any("custom", intVal),
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Claims["custom"]).To(ContainElement(jwt.Int("custom", int64(intVal))))
	})

	It("should succeed, Includes Fingerprint", func() {
		notBefore := time.Now().UTC()
		expiry := time.Now().Add(time.Hour).UTC()
		token, err := jwt.SignFingerprint(signer, "subject", "audience", "fingerprint", false, notBefore, expiry)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.IsOnline).To(BeFalse())
		Expect(result.Fingerprint).To(Equal("fingerprint"))
	})

	It("should succeed, online token, includes fingerprint", func() {
		notBefore := time.Now().UTC()
		expiry := time.Now().Add(time.Hour).UTC()
		token, err := jwt.SignFingerprint(signer, "subject", "audience", "fingerprint", true, notBefore, expiry)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.IsOnline).To(BeTrue())
		Expect(result.Fingerprint).To(Equal("fingerprint"))
		Expect(result.Claims["fpt"]).To(ContainElement(jwt.String("fpt", "fingerprint")))
	})

	It("should succeed, Algorithm RS256", func() {
		privateKey, err := jwt.ParsePKCS1PrivateKeyFromFileAFS(createAfs(), "key.pem")
		Expect(err).NotTo(HaveOccurred())
		algSigner := &jwt.RSASigner{
			Algorithm:  jwt.RS256,
			PrivateKey: privateKey,
		}
		token, err := jwt.Sign(algSigner, "subject", "audience", false, time.Now(), time.Now().Add(time.Hour))
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.IsOnline).To(BeFalse())
		Expect(result.Subject).To(Equal("subject"))
	})

	It("should succeed, Algorithm RS384", func() {
		privateKey, err := jwt.ParsePKCS1PrivateKeyFromFileAFS(createAfs(), "key.pem")
		Expect(err).NotTo(HaveOccurred())
		algSigner := &jwt.RSASigner{
			Algorithm:  jwt.RS384,
			PrivateKey: privateKey,
		}
		token, err := jwt.Sign(algSigner, "subject", "audience", false, time.Now(), time.Now().Add(time.Hour))
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.IsOnline).To(BeFalse())
		Expect(result.Subject).To(Equal("subject"))
	})

	It("should succeed, Algorithm RS512", func() {
		privateKey, err := jwt.ParsePKCS1PrivateKeyFromFileAFS(createAfs(), "key.pem")
		Expect(err).NotTo(HaveOccurred())
		algSigner := &jwt.RSASigner{
			Algorithm:  jwt.RS512,
			PrivateKey: privateKey,
		}
		token, err := jwt.Sign(algSigner, "subject", "audience", false, time.Now(), time.Now().Add(time.Hour))
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.IsOnline).To(BeFalse())
		Expect(result.Subject).To(Equal("subject"))
	})

	It("should fail, invalid algorithm HS256", func() {
		privateKey, err := jwt.ParsePKCS1PrivateKeyFromFileAFS(createAfs(), "key.pem")
		Expect(err).NotTo(HaveOccurred())
		algSigner := &jwt.RSASigner{
			Algorithm:  "HS256",
			PrivateKey: privateKey,
		}
		token, err := jwt.Sign(algSigner, "subject", "audience", false, time.Now(), time.Now().Add(time.Hour))
		Expect(err.Error()).To(Equal("jwt: algorithm \"HS256\" not in use"))
		Expect(token).To(BeEmpty())
	})

	It("offline token", func() {
		token, err := jwt.Sign(signer, "subject", "audience", false, time.Now(), time.Now().Add(time.Hour))
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Subject).To(Equal("subject"))
		Expect(result.Audiences).To(ContainElement("audience"))

	})

	It("online token", func() {
		token, err := jwt.Sign(signer, "subject", "audience", true, time.Now(), time.Now().Add(time.Hour))
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.IsOnline).To(BeTrue())
		Expect(result.Subject).To(Equal("subject"))
	})

	It("audience should fail", func() {
		token, err := jwt.Sign(signer, "subject", "not-audience", false, time.Now(), time.Now().Add(time.Hour))
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).To(Equal(jwt.ErrTokenInvalidAudience))
		Expect(result.IsOnline).To(BeFalse())
		Expect(result.Subject).NotTo(Equal("subject"))
	})

	It("token not valid yet", func() {
		token, err := jwt.Sign(
			signer,
			"subject",
			"audience",
			false,
			time.Now().Add(time.Minute),
			time.Now().Add(time.Hour),
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).To(Equal(jwt.ErrTokenTimeNotValid))
		Expect(result.IsOnline).To(BeFalse())
		Expect(result.Subject).NotTo(Equal("subject"))
	})

	It("token expired", func() {
		token, err := jwt.Sign(
			signer,
			"subject",
			"audience",
			false,
			time.Now().Add(-1*time.Hour),
			time.Now().Add(-1*time.Minute),
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).To(Equal(jwt.ErrTokenTimeNotValid))
		Expect(result.IsOnline).To(BeFalse())
		Expect(result.Subject).NotTo(Equal("subject"))
	})

	It("garbage token", func() {
		result, err := verifier.Verify([]byte("garbage"))
		Expect(err).To(HaveOccurred())
		Expect(result.IsOnline).To(BeFalse())
		Expect(result.Subject).NotTo(Equal("subject"))
	})

	It("valid jwt structure, garbage token", func() {
		result, err := verifier.Verify([]byte("Z2FyYmFnZQ==.Z2FyYmFnZQ==.Z2FyYmFnZQ=="))
		Expect(err).To(HaveOccurred())
		Expect(result.IsOnline).To(BeFalse())
		Expect(result.Subject).NotTo(Equal("subject"))
	})

	It("valid jwt structure, valid json, garbage token", func() {
		result, err := verifier.Verify([]byte("e30=.e30=.e30="))
		Expect(err).To(HaveOccurred())
		Expect(result.IsOnline).To(BeFalse())
		Expect(result.Subject).NotTo(Equal("subject"))
	})

	It("valid jwt, invalid signing", func() {
		result, err := verifier.Verify(
			[]byte("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" +
				".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG" +
				"4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ." +
				"SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
			))
		Expect(err).To(HaveOccurred())
		Expect(result.IsOnline).To(BeFalse())
		Expect(result.Subject).NotTo(Equal("subject"))
	})

	It("should reject not-yet-valid token", func() {
		notBefore := time.Now().Add(time.Minute)
		expires := time.Now().Add(time.Hour)
		issued := time.Now()
		token, err := signer.SignClaims(
			jwt.String(jwt.Subject, "subject"),
			jwt.String(jwt.Audience, "audience"),
			jwt.Time(jwt.Issued, issued),
			jwt.Time(jwt.NotBefore, notBefore),
			jwt.Time(jwt.Expires, expires),
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).To(HaveOccurred())
		Expect(result.Subject).To(BeEmpty())
		Expect(result.IsOnline).To(BeFalse())
		Expect(result.Fingerprint).To(BeEmpty())
		Expect(result.NotBefore).To(Equal(time.Time{}))
		Expect(result.Expires).To(Equal(time.Time{}))
		// Expect(result.Claims).To(ContainElement(jwt.Time(jwt.Issued, issued)))
		// Expect(result.NotBefore).To(BeTemporally("~", notBefore, time.Millisecond))
		// Expect(result.Expires).To(BeTemporally("~", expires, time.Millisecond))
	})

	It("should reject invalid expiry/notbefore order", func() {
		notBefore := time.Now().Add(time.Minute)
		expires := time.Now().Add(-1 * time.Hour)
		issued := time.Now()
		token, err := signer.SignClaims(
			jwt.String(jwt.Subject, "subject"),
			jwt.String(jwt.Audience, "audience"),
			jwt.Time(jwt.Issued, issued),
			jwt.Time(jwt.NotBefore, notBefore),
			jwt.Time(jwt.Expires, expires),
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).To(HaveOccurred())
		Expect(result.Subject).To(BeEmpty())
		Expect(result.IsOnline).To(BeFalse())
		Expect(result.Fingerprint).To(BeEmpty())
		Expect(result.NotBefore).To(Equal(time.Time{}))
		Expect(result.Expires).To(Equal(time.Time{}))
	})

	It("should have valid issued date", func() {
		notBefore := time.Now().Add(-1 * time.Minute)
		expires := time.Now().Add(time.Hour)
		issued := time.Now()
		token, err := signer.SignClaims(
			jwt.String(jwt.Subject, "subject"),
			jwt.String(jwt.Audience, "audience"),
			jwt.Time(jwt.Issued, issued),
			jwt.Time(jwt.NotBefore, notBefore),
			jwt.Time(jwt.Expires, expires),
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Subject).To(Equal("subject"))
		Expect(result.Audiences).To(ContainElement("audience"))
		Expect(result.NotBefore).To(BeTemporally("~", notBefore, time.Millisecond))
		Expect(result.Expires).To(BeTemporally("~", expires, time.Millisecond))

		issuedAt, err := result.Claims[jwt.Issued][0].Time()
		Expect(err).NotTo(HaveOccurred())
		Expect(issuedAt).To(BeTemporally("~", issued, time.Millisecond))

	})
})
