package jwt_test

import (
	"github.com/koshatul/jwt"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
	"github.com/spf13/afero"
)

var (
	afs      afero.Fs
	verifier jwt.Verifier
	signer   jwt.Signer
)

var _ = BeforeSuite(func() {
	afs = afero.NewMemMapFs()
	afero.WriteFile(afs, "cert.pem", []byte(rsaPublicKey), 0755)
	afero.WriteFile(afs, "key.pem", []byte(rsaPrivateKey), 0755)

	publicKey, err := jwt.ParsePKCS1PublicKeyFromFileAFS(afs, "cert.pem")
	Expect(err).NotTo(HaveOccurred())
	verifier = &jwt.RSAVerifier{
		Audience:  "audience",
		PublicKey: publicKey,
	}

	privateKey, err := jwt.ParsePKCS1PrivateKeyFromFileAFS(afs, "key.pem")
	Expect(err).NotTo(HaveOccurred())
	signer = &jwt.RSASigner{
		Algorithm:  jwt.RS256,
		PrivateKey: privateKey,
	}
})

const rsaPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA1w0KHx3EpMnjHjEwEabM0fKbG5PvgJPSkEqYx7iex4hHDUgo
zpXDGilrFVAseNuLtCb2Hvhz7bJfteD4P/wsV6brUI8W/W4gP+Z9n7AQqxN9VWog
THUf2hFTaAf01zqGnORPAN7IVq03jvq6HXPEG4/BbpFYL4+2HU1irTveKjDagYN6
vD3nsghaRDmLJLfBiqJzpLvGVIbm7PhF7vK4aVkDpDGCItc6rvvS4/pwFIWXFlXG
ipCDmFSa+nvxLbjBJ7+v6TXlk9+cSIO7iYHMtoImG5CwHLhB5XaLD3GT+c6SVFWI
JQ/0k2yFhR7gF7jCfH4BhyWu1x35fw9LL5mpGwIDAQABAoIBAQCaUpsu1TfmYZKA
eh/aqu5Uw1qXocO/a1Uxgra8rDoVSjBi0aOnDEXkIlDcDJq9aB+K+mKouvbGXrjc
VkMP97ECfaBkQSroVv0BnjAMRlbPzb6lavEerPZckQ5fm0YSpccwE462OyldOhSi
oD6rIAZdGP5gkCDOkLzJrlzfoBTABNniYzBrFuWvs8+6iRHF0oUwa9Lv7R3m+5UG
OnfCQOV4haIBGixYzxt6bRDs2kvnaImepv0CoUaJmhpx4WYuixys4UpvNEoLDjaD
My0jsI5i5Vmx94IGM1OC2nhLrqNPm+fVdAdEs6BLVaZcYyO6IKQMFMkIk6IVjole
N/vldDUxAoGBAPQ3goDqB8PliJLwbRia1zSkxVD1bJ7V4S032P6DhEzabbrSD/eY
Z5limQfpObne2aux4QGSbgMduqEU2u4JQg76/WEng8L+QMVdOUxRJt92StzZN4pP
EnSx+TKjsQVHUXJANcJdefV2uACKe0y7l6NkFZjkjO8AEUhziSxxOrkNAoGBAOFt
SBrfHaxboP83tOikqCFSVUMxmb1hvv5LZ44+kFVoNgH3ZSZ/cYie78HKphnCStDS
jLjPmiagX+2d7iISX7Ulnhdn9seWG+WkHYv/8S8j0zDgcuJAzKsliz3NW2HXwhLY
CpVMHYe2esoC3zvjtb7MgGAG+qC4LrfgswQeLxDHAoGAIkKvUjqCwF6xHDwScgM2
8bGz5LmpdVb38goFrR7yLn3uKulRSCDfV8tXQJ7ddE/pJYcc08WhHVrMVdDBLeeq
lsNrTHfoqjBVEdsUMLqpw2uq8PSgMA0Lv8c/+HSyXtU0fdy4Lf5DH8Z55cmHpqoi
ic9+oCZgBx9xTUK4Gb4AyPkCgYBwn05Uzn9eqvCGUWh6ijjNXPrn9RHgAcOP/FAi
SrOFV+kTlmvcjfNE1FLoOLw/Rkhmh6pycpWLEriaWDqunwtdzwtqmjA6io4pbpKs
bRQr/vP2CUycKM+X+cvU9pHfEhINpA21hS+Dq/Ewl7q7iwoz5quETjhMr3f3ubT2
K7ZL5QKBgCOe+QMrJAiObibroekVQXiwOxsiE71rXeFyxBYMCje9mcmuWEtxulwm
4qrrDgk5CFeWphnvinqaMUhi3WeZx8I9Um2LGR0U9+fGI04Kpy/afLk0cniq/XF7
SVe7Ua9eV3cPWRG1g1/lbr3skCCyoNqNKeKduFPl3M8ePQ1U9Sdb
-----END RSA PRIVATE KEY-----`

const rsaPublicKey = `-----BEGIN CERTIFICATE-----
MIICqDCCAZACCQCwNFZCAsuFjzANBgkqhkiG9w0BAQsFADAWMRQwEgYDVQQDDAtU
ZXN0IFNpZ25lcjAeFw0xODA5MjgwMDU4NDRaFw0yODA5MjUwMDU4NDRaMBYxFDAS
BgNVBAMMC1Rlc3QgU2lnbmVyMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKC
AQEA1w0KHx3EpMnjHjEwEabM0fKbG5PvgJPSkEqYx7iex4hHDUgozpXDGilrFVAs
eNuLtCb2Hvhz7bJfteD4P/wsV6brUI8W/W4gP+Z9n7AQqxN9VWogTHUf2hFTaAf0
1zqGnORPAN7IVq03jvq6HXPEG4/BbpFYL4+2HU1irTveKjDagYN6vD3nsghaRDmL
JLfBiqJzpLvGVIbm7PhF7vK4aVkDpDGCItc6rvvS4/pwFIWXFlXGipCDmFSa+nvx
LbjBJ7+v6TXlk9+cSIO7iYHMtoImG5CwHLhB5XaLD3GT+c6SVFWIJQ/0k2yFhR7g
F7jCfH4BhyWu1x35fw9LL5mpGwIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQDGEg/R
r1csZEEpMHxIoWBSfyUX9Aw0CmZ7WhnDztbICxF/IS8AOifnU3mHa2SJlko9UaKv
wdq8iODpz1SLnRaLqTLWI1G3KuLnM2ETJkfWDNAA8A2zkAlrppluCMYYZXGhCpqm
uQDPsO6Fy1JGI5n9IbHYjly41PFIj6z3XL62OkAAVe59J9OCT37dTPy/YMoOYJJx
E05tdUGLlThdxzSlv67Aaynxo9GmVQYHRxzmzpcQkyFwEsZ8vwwDWhIsQLHushQ0
7i+Sjc+wOYOP2tBUKgLo7z99ezGQ27jjTStdc3fYvwXPHsqWG4qdDKx/HpSZTP0y
yMeinS43IJabbje8
-----END CERTIFICATE-----`
