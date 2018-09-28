package jwt_test

import (
	"time"

	"github.com/koshatul/jwt/src/jwt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("JWT Signer", func() {

	It("should succeed", func() {
		nbfTime := time.Now().UTC()
		expTime := time.Now().Add(time.Hour).UTC()

		subject := jwt.String(jwt.Subject, "subject")
		audience := jwt.String(jwt.Audience, "audience")
		notBefore := jwt.Time(jwt.NotBefore, nbfTime)
		expiry := jwt.Time(jwt.Expires, expTime)

		token, err := signer.SignClaims(subject, audience, expiry, notBefore)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.IsOnline).To(BeFalse())
		Expect(result.Subject).To(Equal("subject"))
		Expect(result.ID).NotTo(BeEmpty())
		Expect(result.Audience).To(Equal("audience"))
		Expect(result.Fingerprint).To(BeEmpty())
		Expect(result.NotBefore).To(BeTemporally("~", nbfTime, time.Microsecond))
		Expect(result.Expires).To(BeTemporally("~", expTime, time.Microsecond))
	})

	It("should return a result, even with no claims", func() {
		token, err := signer.SignClaims()
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).To(MatchError(jwt.ErrTokenInvalidAudience))
		Expect(result.Subject).To(BeEmpty())
		Expect(result.IsOnline).To(BeFalse())
		Expect(result.ID).To(BeEmpty())
		Expect(result.Audience).To(BeEmpty())
		Expect(result.Fingerprint).To(BeEmpty())
		Expect(result.NotBefore).To(Equal(time.Time{}))
		Expect(result.Expires).To(Equal(time.Time{}))
	})

	It("should return empty result on error on audience error", func() {
		token, err := signer.SignClaims(
			jwt.String(jwt.Subject, "subject"),
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).To(MatchError(jwt.ErrTokenInvalidAudience))
		Expect(result.Subject).To(BeEmpty())
	})

	It("should fail to verify with an invalid audience", func() {
		token, err := signer.SignClaims()
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).To(MatchError(jwt.ErrTokenInvalidAudience))
		Expect(result.Audience).To(BeEmpty())
	})

	It("should fail with an invalid expiry field type", func() {
		token, err := signer.SignClaims(
			jwt.String(jwt.Audience, "audience"),
			jwt.String(jwt.NotBefore, "I'm not a time"),
		)
		Expect(err).To(HaveOccurred())
		Expect(token).To(BeEmpty())
	})

	It("should succeed with a custom field (which is lost)", func() {
		nbfTime := time.Now().UTC()
		expTime := time.Now().Add(time.Hour).UTC()

		subject := jwt.String(jwt.Subject, "subject")
		audience := jwt.String(jwt.Audience, "audience")
		notBefore := jwt.Time(jwt.NotBefore, nbfTime)
		expiry := jwt.Time(jwt.Expires, expTime)
		custom := jwt.String("foo", "bar")

		token, err := signer.SignClaims(subject, audience, expiry, notBefore, custom)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Subject).To(Equal("subject"))
		Expect(result.ID).NotTo(BeEmpty())
		Expect(result.IsOnline).To(BeFalse())
		Expect(result.Audience).To(Equal("audience"))
		Expect(result.Fingerprint).To(BeEmpty())
		Expect(result.NotBefore).To(BeTemporally("~", nbfTime, time.Microsecond))
		Expect(result.Expires).To(BeTemporally("~", expTime, time.Microsecond))

		Expect(result.Claims).To(ContainElement(custom))
	})

	It("should succeed with an online field", func() {
		nbfTime := time.Now().UTC()
		expTime := time.Now().Add(time.Hour).UTC()

		subject := jwt.String(jwt.Subject, "subject")
		audience := jwt.String(jwt.Audience, "audience")
		notBefore := jwt.Time(jwt.NotBefore, nbfTime)
		expiry := jwt.Time(jwt.Expires, expTime)
		online := jwt.Bool("onl", true)

		token, err := signer.SignClaims(subject, audience, expiry, notBefore, online)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Subject).To(Equal("subject"))
		Expect(result.IsOnline).To(BeTrue())
		Expect(result.ID).NotTo(BeEmpty())
		Expect(result.Audience).To(Equal("audience"))
		Expect(result.Fingerprint).To(BeEmpty())
		Expect(result.NotBefore).To(BeTemporally("~", nbfTime, time.Microsecond))
		Expect(result.Expires).To(BeTemporally("~", expTime, time.Microsecond))

	})

	It("should succeed with an online field and fingerprint", func() {
		nbfTime := time.Now().UTC()
		expTime := time.Now().Add(time.Hour).UTC()

		subject := jwt.String(jwt.Subject, "subject")
		audience := jwt.String(jwt.Audience, "audience")
		notBefore := jwt.Time(jwt.NotBefore, nbfTime)
		expiry := jwt.Time(jwt.Expires, expTime)
		online := jwt.Bool("onl", true)
		fprint := jwt.String("fpt", "fingerpainting-is-fun")

		token, err := signer.SignClaims(subject, audience, expiry, notBefore, online, fprint)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Subject).To(Equal("subject"))
		Expect(result.IsOnline).To(BeTrue())
		Expect(result.ID).NotTo(BeEmpty())
		Expect(result.Audience).To(Equal("audience"))
		Expect(result.Fingerprint).To(Equal("fingerpainting-is-fun"))
		Expect(result.NotBefore).To(BeTemporally("~", nbfTime, time.Microsecond))
		Expect(result.Expires).To(BeTemporally("~", expTime, time.Microsecond))

	})

	It("should carry through custom ID", func() {
		id := jwt.String("jti", "ponies")
		audience := jwt.String(jwt.Audience, "audience")

		token, err := signer.SignClaims(id, audience)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.Subject).To(BeEmpty())
		Expect(result.IsOnline).To(BeFalse())
		Expect(result.ID).To(Equal("ponies"))
		Expect(result.Audience).To(Equal("audience"))
		Expect(result.Fingerprint).To(BeEmpty())
		Expect(result.NotBefore).To(Equal(time.Time{}))
		Expect(result.Expires).To(Equal(time.Time{}))
	})

	It("allows repeat keys, but uses last specified (overriding issuer should work for RSASigner)", func() {
		token, err := signer.SignClaims(
			jwt.String(jwt.Subject, "subject"),
			jwt.String(jwt.Audience, "audience"),
			jwt.String(jwt.Subject, "new-subject"),
		)
		Expect(err).NotTo(HaveOccurred())
		Expect(token).NotTo(BeEmpty())

		result, err := verifier.Verify(token)
		Expect(err).NotTo(HaveOccurred())
		Expect(result.IsOnline).To(BeFalse())
		Expect(result.Subject).To(Equal("new-subject"))
		Expect(result.ID).NotTo(BeEmpty())
		Expect(result.Audience).To(Equal("audience"))
		Expect(result.Fingerprint).To(BeEmpty())
		Expect(result.NotBefore).To(Equal(time.Time{}))
		Expect(result.Expires).To(Equal(time.Time{}))
	})

})
