package grpc

import (
	"crypto/x509"
	"net"
	"net/url"
	"strings"
	"testing"
	"time"

	valtypes "github.com/celestiaorg/celestia-app/v9/x/valaddr/types"
	core "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A forged endorsement that claims a victim validator's address but is signed
// by a different key must be rejected at the signature check, even though the
// address-equality check passes. This is the core "impersonate another
// validator" threat and exercises the (otherwise untested) signature branch.
func TestVerify_ForgedEndorsementWrongSignerRejected(t *testing.T) {
	attacker := core.NewMockPV()
	victim := core.NewMockPV()
	victimVal := victim.ExtractIntoValidator(1)
	ip := net.ParseIP("127.0.0.1")

	source := &serverTLSCertificateSource{
		chainID:          "celestia",
		validatorAddress: victimVal.Address.String(), // claim to be the victim
		endpoint:         testEndpoint(ip),
		signer:           attacker, // but sign with the attacker's key
		validity:         time.Hour,
		now:              time.Now,
	}
	cert, err := source.currentCertificate()
	require.NoError(t, err)

	err = verifyPeerCertificates([]*x509.Certificate{cert.Leaf}, victimVal, testEndpoint(ip), "celestia")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid TLS endorsement signature")
}

// An expired certificate/endorsement must be rejected.
func TestVerify_ExpiredCertificateRejected(t *testing.T) {
	pv := core.NewMockPV()
	val := pv.ExtractIntoValidator(1)
	ip := net.ParseIP("127.0.0.1")

	past := time.Now().Add(-48 * time.Hour)
	source := &serverTLSCertificateSource{
		chainID:          "celestia",
		validatorAddress: val.Address.String(),
		endpoint:         testEndpoint(ip),
		signer:           pv,
		validity:         time.Hour,
		now:              func() time.Time { return past },
	}
	cert, err := source.currentCertificate()
	require.NoError(t, err)

	err = verifyPeerCertificates([]*x509.Certificate{cert.Leaf}, val, testEndpoint(ip), "celestia")
	require.ErrorContains(t, err, "peer certificate is not valid")
}

// Tampering the embedded endorsement (without re-signing) must be rejected.
func TestVerify_TamperedEndorsementRejected(t *testing.T) {
	pv := core.NewMockPV()
	val := pv.ExtractIntoValidator(1)
	ip := net.ParseIP("127.0.0.1")
	cert := endorsedCertificate(t, "celestia", val, ip, pv)

	require.NoError(t, verifyPeerCertificates([]*x509.Certificate{cert}, val, testEndpoint(ip), "celestia"))

	for i := range cert.URIs {
		if cert.URIs[i] != nil && strings.HasPrefix(cert.URIs[i].String(), tlsEndorsementURIPrefix) {
			tampered := cert.URIs[i].String()
			cert.URIs[i], _ = url.Parse(tampered[:len(tampered)-1] + "!")
		}
	}
	require.Error(t, verifyPeerCertificates([]*x509.Certificate{cert}, val, testEndpoint(ip), "celestia"))
}

func TestVerify_EmptyChainIDRejectsForeignChain(t *testing.T) {
	pv := core.NewMockPV()
	val := pv.ExtractIntoValidator(1)
	ip := net.ParseIP("127.0.0.1")

	cert := endorsedCertificate(t, "mocha", val, ip, pv)

	require.Error(t, verifyPeerCertificates([]*x509.Certificate{cert}, val, testEndpoint(ip), "celestia"))
	require.Error(t, verifyPeerCertificates([]*x509.Certificate{cert}, val, testEndpoint(ip), ""))
}

func TestVerify_DNSHostSupported(t *testing.T) {
	const dnsHost = "validator.example.com:7980"

	require.NoError(t, valtypes.ValidateHost(dnsHost), "chain ValidateHost accepts DNS")

	endpoint, err := TargetAddressFromString(dnsHost)
	require.NoError(t, err)
	require.Equal(t, "validator.example.com", endpoint.Host)
	require.Nil(t, endpoint.IP)
}

// IPv4 and IPv4-mapped-IPv6 representations of the same address are treated
// consistently end to end (server SAN vs client expectation).
func TestVerify_IPv4MappedConsistent(t *testing.T) {
	pv := core.NewMockPV()
	val := pv.ExtractIntoValidator(1)
	serverIP := net.ParseIP("::ffff:127.0.0.1")
	clientIP := net.ParseIP("127.0.0.1")

	cert := endorsedCertificate(t, "celestia", val, serverIP, pv)
	require.NoError(t, verifyPeerCertificates([]*x509.Certificate{cert}, val, testEndpoint(clientIP), "celestia"))
}

func TestSource_RefreshFailureReusesStillValidCert(t *testing.T) {
	pv := core.NewMockPV()
	val := pv.ExtractIntoValidator(1)
	ip := net.ParseIP("127.0.0.1")

	signer := &flakyRefreshSigner{MockPV: pv, failAfter: 1}

	start := time.Now()
	clock := start
	source := &serverTLSCertificateSource{
		chainID:          "celestia",
		validatorAddress: val.Address.String(),
		endpoint:         testEndpoint(ip),
		signer:           signer,
		validity:         2 * time.Hour, // certRefreshBefore = 1h
		now:              func() time.Time { return clock },
	}

	c1, err := source.currentCertificate()
	require.NoError(t, err)
	require.NotNil(t, c1)
	require.True(t, time.Now().Before(c1.Leaf.NotAfter), "cached cert is still valid in real time")

	clock = start.Add(90 * time.Minute) // inside the refresh window
	c2, err := source.currentCertificate()
	require.NoError(t, err)
	require.Same(t, c1, c2)
}

type flakyRefreshSigner struct {
	core.MockPV
	calls     int
	failAfter int
}

func (f *flakyRefreshSigner) SignRawBytes(chainID, uniqueID string, raw []byte) ([]byte, error) {
	f.calls++
	if f.calls > f.failAfter {
		return nil, errFlakySignerUnavailable
	}
	return f.MockPV.SignRawBytes(chainID, uniqueID, raw)
}

type errFlaky string

func (e errFlaky) Error() string { return string(e) }

var errFlakySignerUnavailable = errFlaky("signer unavailable")
