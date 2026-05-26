//go:build security_review

package grpc

import (
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"net/url"
	"testing"
	"time"

	core "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/require"
)

func TestSecurityReviewRejectsEmptyExpectedChainID(t *testing.T) {
	pv := core.NewMockPV()
	val := pv.ExtractIntoValidator(1)
	ip := net.ParseIP("127.0.0.1")
	cert := endorsedCertificate(t, "celestia", val, ip, pv)

	require.Error(t, verifyPeerCertificates([]*x509.Certificate{cert}, val, testEndpoint(ip), ""))
}

func TestSecurityReviewRejectsLongLivedEndorsement(t *testing.T) {
	pv := core.NewMockPV()
	val := pv.ExtractIntoValidator(1)
	ip := net.ParseIP("127.0.0.1")
	source := &serverTLSCertificateSource{
		chainID:          "celestia",
		validatorAddress: val.Address.String(),
		endpoint:         testEndpoint(ip),
		signer:           pv,
		validity:         365 * 24 * time.Hour,
		now:              time.Now,
	}
	cert, err := source.currentCertificate()
	require.NoError(t, err)
	require.NotNil(t, cert.Leaf)

	require.Error(t, verifyPeerCertificates([]*x509.Certificate{cert.Leaf}, val, testEndpoint(ip), "celestia"))
}

func TestSecurityReviewClientCredentialsRejectMismatchedValidatorAddress(t *testing.T) {
	pv := core.NewMockPV()
	pubKey, err := pv.GetPubKey()
	require.NoError(t, err)
	otherVal := core.NewMockPV().ExtractIntoValidator(1)
	inconsistentVal := &core.Validator{
		Address: otherVal.Address,
		PubKey:  pubKey,
	}

	_, err = ClientTransportCredentials(inconsistentVal, testEndpoint(net.ParseIP("127.0.0.1")), "celestia")
	require.Error(t, err)
}

func TestSecurityReviewServerCredentialsRejectMismatchedSignerAddress(t *testing.T) {
	pv := core.NewMockPV()
	otherVal := core.NewMockPV().ExtractIntoValidator(1)

	_, err := ServerTransportCredentials("celestia", otherVal.Address.String(), testEndpoint(net.ParseIP("127.0.0.1")), pv)
	require.Error(t, err)
}

func TestSecurityReviewReusesStillValidCertificateWhenRefreshSigningFails(t *testing.T) {
	baseTime := time.Now()
	pv := &securityReviewSigner{PrivValidator: core.NewMockPV()}
	pubKey, err := pv.GetPubKey()
	require.NoError(t, err)
	val := &core.Validator{
		Address: pubKey.Address(),
		PubKey:  pubKey,
	}
	source := &serverTLSCertificateSource{
		chainID:          "celestia",
		validatorAddress: val.Address.String(),
		endpoint:         testEndpoint(net.ParseIP("127.0.0.1")),
		signer:           pv,
		validity:         defaultCertValidity,
		now: func() time.Time {
			return baseTime
		},
	}
	first, err := source.currentCertificate()
	require.NoError(t, err)
	require.NotNil(t, first.Leaf)

	pv.failSignRawBytes = true
	baseTime = first.Leaf.NotAfter.Add(-certRefreshBefore).Add(time.Second)

	second, err := source.currentCertificate()
	require.NoError(t, err)
	require.Same(t, first, second)
}

func TestSecurityReviewRejectsCertificateWithoutServerAuthUsage(t *testing.T) {
	pv := core.NewMockPV()
	val := pv.ExtractIntoValidator(1)
	ip := net.ParseIP("127.0.0.1")
	cert := endorsedTLSCertificate(t, "celestia", val, ip, pv, time.Hour)

	rewritten := rewriteCertificateForSecurityReview(t, cert, ip, func(template *x509.Certificate) {
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
	})

	require.Error(t, verifyPeerCertificates([]*x509.Certificate{rewritten}, val, testEndpoint(ip), "celestia"))
}

func TestSecurityReviewRejectsCertificateValidityDifferentFromEndorsement(t *testing.T) {
	pv := core.NewMockPV()
	val := pv.ExtractIntoValidator(1)
	ip := net.ParseIP("127.0.0.1")
	cert := endorsedTLSCertificate(t, "celestia", val, ip, pv, time.Hour)

	rewritten := rewriteCertificateForSecurityReview(t, cert, ip, func(template *x509.Certificate) {
		template.NotAfter = template.NotAfter.Add(-time.Minute)
	})

	require.Error(t, verifyPeerCertificates([]*x509.Certificate{rewritten}, val, testEndpoint(ip), "celestia"))
}

func TestSecurityReviewRejectsUnexpectedURISAN(t *testing.T) {
	pv := core.NewMockPV()
	val := pv.ExtractIntoValidator(1)
	ip := net.ParseIP("127.0.0.1")
	cert := endorsedTLSCertificate(t, "celestia", val, ip, pv, time.Hour)

	rewritten := rewriteCertificateForSecurityReview(t, cert, ip, func(template *x509.Certificate) {
		extra, err := url.Parse("spiffe://validator.example.com/fibre")
		require.NoError(t, err)
		template.URIs = append(template.URIs, extra)
	})

	require.Error(t, verifyPeerCertificates([]*x509.Certificate{rewritten}, val, testEndpoint(ip), "celestia"))
}

func TestSecurityReviewRejectsCACertificate(t *testing.T) {
	pv := core.NewMockPV()
	val := pv.ExtractIntoValidator(1)
	ip := net.ParseIP("127.0.0.1")
	cert := endorsedTLSCertificate(t, "celestia", val, ip, pv, time.Hour)

	rewritten := rewriteCertificateForSecurityReview(t, cert, ip, func(template *x509.Certificate) {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
	})

	require.Error(t, verifyPeerCertificates([]*x509.Certificate{rewritten}, val, testEndpoint(ip), "celestia"))
}

func endorsedTLSCertificate(t *testing.T, chainID string, val *core.Validator, ip net.IP, signer core.PrivValidator, validity time.Duration) *tls.Certificate {
	t.Helper()

	source := &serverTLSCertificateSource{
		chainID:          chainID,
		validatorAddress: val.Address.String(),
		endpoint:         testEndpoint(ip),
		signer:           signer,
		validity:         validity,
		now:              time.Now,
	}
	cert, err := source.currentCertificate()
	require.NoError(t, err)
	require.NotNil(t, cert.Leaf)
	return cert
}

func rewriteCertificateForSecurityReview(t *testing.T, cert *tls.Certificate, ip net.IP, mutate func(*x509.Certificate)) *x509.Certificate {
	t.Helper()

	leaf := cert.Leaf
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               leaf.Subject,
		NotBefore:             leaf.NotBefore,
		NotAfter:              leaf.NotAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:           []net.IP{ip},
		URIs:                  []*url.URL{endorsementURI(t, leaf)},
		BasicConstraintsValid: true,
	}
	mutate(template)

	der, err := x509.CreateCertificate(rand.Reader, template, template, leaf.PublicKey, cert.PrivateKey)
	require.NoError(t, err)
	rewritten, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return rewritten
}

func endorsementURI(t *testing.T, cert *x509.Certificate) *url.URL {
	t.Helper()

	raw := tlsEndorsementURIValue(cert)
	if raw == "" {
		t.Fatal("missing TLS endorsement URI SAN")
	}
	uri, err := url.Parse(raw)
	require.NoError(t, err)
	return uri
}

type securityReviewSigner struct {
	core.PrivValidator
	failSignRawBytes bool
}

func (s *securityReviewSigner) SignRawBytes(chainID, uniqueID string, rawBytes []byte) ([]byte, error) {
	if s.failSignRawBytes {
		return nil, errors.New("signing disabled")
	}
	return s.PrivValidator.SignRawBytes(chainID, uniqueID, rawBytes)
}
