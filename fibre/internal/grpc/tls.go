package grpc

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	core "github.com/cometbft/cometbft/types"
	"google.golang.org/grpc/credentials"
)

const (
	tlsEndorsementVersion   = 1
	tlsEndorsementUniqueID  = "FIBRE::GRPC_TLS_CERTIFICATE::V1"
	defaultCertValidity     = 24 * time.Hour
	certRefreshBefore       = time.Hour
	maxCertValidity         = 24*time.Hour + 5*time.Minute
	tlsEndorsementURIPrefix = "urn:celestia:fibre:grpc-tls:v1:"
)

type tlsEndorsementPayload struct {
	Version              int    `json:"version"`
	ChainID              string `json:"chain_id"`
	ValidatorAddress     string `json:"validator_address"`
	EndpointHost         string `json:"endpoint_host"`
	EndpointPort         string `json:"endpoint_port"`
	CertPublicKeySHA256  string `json:"cert_public_key_sha256"`
	NotBeforeUnixSeconds int64  `json:"not_before_unix_seconds"`
	NotAfterUnixSeconds  int64  `json:"not_after_unix_seconds"`
}

type tlsEndorsement struct {
	Payload   []byte `json:"payload"`
	Signature []byte `json:"signature"`
}

type TargetAddress struct {
	Host string
	IP   net.IP
	Port string
}

func (t TargetAddress) Validate() error {
	host := t.tlsHost()
	if host == "" {
		return fmt.Errorf("validator host is required")
	}
	if ip := t.tlsIP(); ip != nil {
		if ip.IsUnspecified() {
			return fmt.Errorf("validator host must not be an unspecified IP")
		}
	} else if !validDNSName(host) {
		return fmt.Errorf("validator host %q must be an IP literal or DNS name", host)
	}
	if t.Port == "" {
		return fmt.Errorf("validator port is required")
	}
	port, err := strconv.Atoi(t.Port)
	if err != nil {
		return fmt.Errorf("validator port must be numeric: %w", err)
	}
	if port < 1 || port > 65535 {
		return fmt.Errorf("validator port %d out of range [1, 65535]", port)
	}
	return nil
}

func (t TargetAddress) tlsHost() string {
	if t.IP != nil {
		return t.IP.String()
	}
	return strings.ToLower(t.Host)
}

func (t TargetAddress) tlsIP() net.IP {
	if t.IP != nil {
		return t.IP
	}
	return net.ParseIP(t.tlsHost())
}

type serverTLSCertificateSource struct {
	chainID          string
	validatorAddress string
	endpoint         TargetAddress
	signer           core.PrivValidator
	validity         time.Duration
	now              func() time.Time

	mu   sync.Mutex
	cert *tls.Certificate
}

// ServerTransportCredentials creates TLS credentials whose certificates are
// endorsed by the validator private key. The endorsement is carried in a URI SAN
// and verified by [ClientTransportCredentials].
func ServerTransportCredentials(chainID string, validatorAddress string, endpoint TargetAddress, signer core.PrivValidator) (credentials.TransportCredentials, error) {
	if chainID == "" {
		return nil, fmt.Errorf("chain ID is required")
	}
	if validatorAddress == "" {
		return nil, fmt.Errorf("validator address is required")
	}
	if err := endpoint.Validate(); err != nil {
		return nil, err
	}
	if signer == nil {
		return nil, fmt.Errorf("validator signer is required")
	}
	pubKey, err := signer.GetPubKey()
	if err != nil {
		return nil, fmt.Errorf("get validator public key: %w", err)
	}
	if pubKey.Address().String() != validatorAddress {
		return nil, fmt.Errorf("validator address %s does not match signer public key address %s", validatorAddress, pubKey.Address())
	}

	source := &serverTLSCertificateSource{
		chainID:          chainID,
		validatorAddress: validatorAddress,
		endpoint:         endpoint,
		signer:           signer,
		validity:         defaultCertValidity,
		now:              time.Now,
	}

	if _, err := source.currentCertificate(); err != nil {
		return nil, err
	}

	return credentials.NewTLS(&tls.Config{
		MinVersion:     tls.VersionTLS13,
		GetCertificate: source.GetCertificate,
	}), nil
}

func (s *serverTLSCertificateSource) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return s.currentCertificate()
}

func (s *serverTLSCertificateSource) currentCertificate() (*tls.Certificate, error) {
	now := s.now()

	s.mu.Lock()
	if s.cert != nil && s.cert.Leaf != nil && now.Before(s.cert.Leaf.NotAfter.Add(-certRefreshBefore)) {
		cert := s.cert
		s.mu.Unlock()
		return cert, nil
	}
	s.mu.Unlock()

	cert, err := s.newCertificate(now)
	if err != nil {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.cert != nil && s.cert.Leaf != nil && now.Before(s.cert.Leaf.NotAfter) {
			return s.cert, nil
		}
		return nil, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cert != nil && s.cert.Leaf != nil && now.Before(s.cert.Leaf.NotAfter.Add(-certRefreshBefore)) {
		return s.cert, nil
	}
	s.cert = cert
	return cert, nil
}

func (s *serverTLSCertificateSource) newCertificate(now time.Time) (*tls.Certificate, error) {
	if err := s.endpoint.Validate(); err != nil {
		return nil, err
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate ephemeral TLS key: %w", err)
	}

	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal TLS public key: %w", err)
	}
	publicKeyHash := sha256.Sum256(publicKeyDER)

	notBefore := now.Add(-time.Minute).UTC().Truncate(time.Second)
	notAfter := now.Add(s.validity).UTC().Truncate(time.Second)
	endpointHost := s.endpoint.tlsHost()
	payload := tlsEndorsementPayload{
		Version:              tlsEndorsementVersion,
		ChainID:              s.chainID,
		ValidatorAddress:     s.validatorAddress,
		EndpointHost:         endpointHost,
		EndpointPort:         s.endpoint.Port,
		CertPublicKeySHA256:  hex.EncodeToString(publicKeyHash[:]),
		NotBeforeUnixSeconds: notBefore.Unix(),
		NotAfterUnixSeconds:  notAfter.Unix(),
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal TLS endorsement payload: %w", err)
	}

	signature, err := s.signer.SignRawBytes(s.chainID, tlsEndorsementUniqueID, payloadBytes)
	if err != nil {
		return nil, fmt.Errorf("sign TLS endorsement: %w", err)
	}

	endorsementBytes, err := json.Marshal(tlsEndorsement{
		Payload:   payloadBytes,
		Signature: signature,
	})
	if err != nil {
		return nil, fmt.Errorf("marshal TLS endorsement: %w", err)
	}
	endorsementURI, err := url.Parse(tlsEndorsementURIPrefix + base64.RawURLEncoding.EncodeToString(endorsementBytes))
	if err != nil {
		return nil, fmt.Errorf("build TLS endorsement URI: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate certificate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: "fibre-" + s.validatorAddress,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		URIs:                  []*url.URL{endorsementURI},
	}
	if ip := s.endpoint.tlsIP(); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{endpointHost}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, publicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("create TLS certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse generated TLS certificate: %w", err)
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privateKey,
		Leaf:        leaf,
	}, nil
}

// ClientTransportCredentials creates TLS credentials that verify the peer is
// endorsed by val and that the certificate is valid for expectedEndpoint.
func ClientTransportCredentials(val *core.Validator, expectedEndpoint TargetAddress, expectedChainID string) (credentials.TransportCredentials, error) {
	if val == nil {
		return nil, fmt.Errorf("validator is required")
	}
	if val.PubKey == nil {
		return nil, fmt.Errorf("validator public key is required")
	}
	if val.PubKey.Address().String() != val.Address.String() {
		return nil, fmt.Errorf("validator address %s does not match public key address %s", val.Address.String(), val.PubKey.Address())
	}
	if err := expectedEndpoint.Validate(); err != nil {
		return nil, err
	}
	if expectedChainID == "" {
		return nil, fmt.Errorf("expected chain ID is required")
	}

	serverName := expectedEndpoint.tlsHost()
	return credentials.NewTLS(&tls.Config{
		MinVersion:         tls.VersionTLS13,
		ServerName:         serverName,
		InsecureSkipVerify: true, //nolint:gosec // verified by VerifyConnection below.
		VerifyConnection: func(state tls.ConnectionState) error {
			return verifyPeerCertificates(state.PeerCertificates, val, expectedEndpoint, expectedChainID)
		},
	}), nil
}

func verifyPeerCertificates(certs []*x509.Certificate, val *core.Validator, expectedEndpoint TargetAddress, expectedChainID string) error {
	if len(certs) == 0 {
		return fmt.Errorf("missing peer certificate")
	}
	if val == nil || val.PubKey == nil {
		return fmt.Errorf("validator and validator public key are required")
	}
	if val.PubKey.Address().String() != val.Address.String() {
		return fmt.Errorf("validator address %s does not match public key address %s", val.Address.String(), val.PubKey.Address())
	}
	if err := expectedEndpoint.Validate(); err != nil {
		return err
	}
	if expectedChainID == "" {
		return fmt.Errorf("expected chain ID is required")
	}

	cert := certs[0]
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return fmt.Errorf("peer certificate is not valid at %s", now.UTC().Format(time.RFC3339))
	}
	if cert.NotAfter.Sub(cert.NotBefore) > maxCertValidity {
		return fmt.Errorf("peer certificate lifetime %s exceeds maximum %s", cert.NotAfter.Sub(cert.NotBefore), maxCertValidity)
	}
	if !hasServerAuthEKU(cert) {
		return fmt.Errorf("peer certificate is missing server-auth extended key usage")
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		return fmt.Errorf("peer certificate is missing digital-signature key usage")
	}
	if !cert.BasicConstraintsValid || cert.IsCA {
		return fmt.Errorf("peer certificate has invalid basic constraints")
	}
	expectedHost := expectedEndpoint.tlsHost()
	if expectedIP := expectedEndpoint.tlsIP(); expectedIP != nil {
		if len(cert.IPAddresses) != 1 || !cert.IPAddresses[0].Equal(expectedIP) {
			return fmt.Errorf("peer certificate IP SANs do not exactly match validator host %s", expectedHost)
		}
		if len(cert.DNSNames) != 0 {
			return fmt.Errorf("peer certificate contains unexpected DNS subject alternative names")
		}
	} else {
		if len(cert.DNSNames) != 1 || !strings.EqualFold(cert.DNSNames[0], expectedHost) {
			return fmt.Errorf("peer certificate DNS SANs do not exactly match validator host %s", expectedHost)
		}
		if len(cert.IPAddresses) != 0 {
			return fmt.Errorf("peer certificate contains unexpected IP subject alternative names")
		}
	}
	if len(cert.EmailAddresses) != 0 {
		return fmt.Errorf("peer certificate contains unexpected email subject alternative names")
	}
	if err := cert.VerifyHostname(expectedHost); err != nil {
		return fmt.Errorf("peer certificate does not match validator host %s: %w", expectedHost, err)
	}

	endorsement, err := certificateEndorsement(cert)
	if err != nil {
		return err
	}

	var payload tlsEndorsementPayload
	if err := json.Unmarshal(endorsement.Payload, &payload); err != nil {
		return fmt.Errorf("decode TLS endorsement payload: %w", err)
	}

	if payload.Version != tlsEndorsementVersion {
		return fmt.Errorf("unsupported TLS endorsement version %d", payload.Version)
	}
	if payload.ChainID != expectedChainID {
		return fmt.Errorf("TLS endorsement chain ID mismatch: expected %q, got %q", expectedChainID, payload.ChainID)
	}
	if payload.ValidatorAddress != val.Address.String() {
		return fmt.Errorf("TLS endorsement validator mismatch: expected %s, got %s", val.Address.String(), payload.ValidatorAddress)
	}
	if !strings.EqualFold(payload.EndpointHost, expectedHost) {
		return fmt.Errorf("TLS endorsement host mismatch: expected %s, got %s", expectedHost, payload.EndpointHost)
	}
	if payload.EndpointPort != expectedEndpoint.Port {
		return fmt.Errorf("TLS endorsement port mismatch: expected %s, got %s", expectedEndpoint.Port, payload.EndpointPort)
	}

	publicKeyHash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	if payload.CertPublicKeySHA256 != hex.EncodeToString(publicKeyHash[:]) {
		return fmt.Errorf("TLS endorsement does not match certificate public key")
	}

	endorsedNotBefore := time.Unix(payload.NotBeforeUnixSeconds, 0).UTC()
	endorsedNotAfter := time.Unix(payload.NotAfterUnixSeconds, 0).UTC()
	if now.Before(endorsedNotBefore) || now.After(endorsedNotAfter) {
		return fmt.Errorf("TLS endorsement is not valid at %s", now.UTC().Format(time.RFC3339))
	}
	if !cert.NotBefore.Equal(endorsedNotBefore) || !cert.NotAfter.Equal(endorsedNotAfter) {
		return fmt.Errorf("peer certificate validity does not match TLS endorsement")
	}
	if endorsedNotAfter.Sub(endorsedNotBefore) > maxCertValidity {
		return fmt.Errorf("TLS endorsement lifetime %s exceeds maximum %s", endorsedNotAfter.Sub(endorsedNotBefore), maxCertValidity)
	}

	signBytes, err := core.RawBytesMessageSignBytes(expectedChainID, tlsEndorsementUniqueID, endorsement.Payload)
	if err != nil {
		return fmt.Errorf("create TLS endorsement sign bytes: %w", err)
	}
	if !val.PubKey.VerifySignature(signBytes, endorsement.Signature) {
		return fmt.Errorf("invalid TLS endorsement signature from validator %s", val.Address.String())
	}

	return nil
}

func certificateEndorsement(cert *x509.Certificate) (tlsEndorsement, error) {
	var encoded string
	for _, uri := range cert.URIs {
		if uri == nil {
			continue
		}
		raw := uri.String()
		if !strings.HasPrefix(raw, tlsEndorsementURIPrefix) {
			return tlsEndorsement{}, fmt.Errorf("unexpected TLS URI SAN")
		}
		if strings.HasPrefix(raw, tlsEndorsementURIPrefix) {
			if encoded != "" {
				return tlsEndorsement{}, fmt.Errorf("multiple TLS endorsement URI SANs")
			}
			encoded = strings.TrimPrefix(raw, tlsEndorsementURIPrefix)
		}
	}
	if encoded == "" {
		return tlsEndorsement{}, fmt.Errorf("missing TLS endorsement URI SAN")
	}
	endorsementBytes, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return tlsEndorsement{}, fmt.Errorf("decode TLS endorsement URI: %w", err)
	}
	var endorsement tlsEndorsement
	if err := json.Unmarshal(endorsementBytes, &endorsement); err != nil {
		return tlsEndorsement{}, fmt.Errorf("decode TLS endorsement: %w", err)
	}
	if len(endorsement.Payload) == 0 {
		return tlsEndorsement{}, fmt.Errorf("TLS endorsement payload is empty")
	}
	if len(endorsement.Signature) == 0 {
		return tlsEndorsement{}, fmt.Errorf("TLS endorsement signature is empty")
	}
	return endorsement, nil
}

// TargetAddressFromString extracts the host and port clients are expected to
// verify from a gRPC target or host registry value.
func TargetAddressFromString(target string) (TargetAddress, error) {
	endpoint, err := targetEndpoint(target)
	if err != nil {
		return TargetAddress{}, err
	}

	host, port, err := net.SplitHostPort(endpoint)
	if err != nil {
		return TargetAddress{}, fmt.Errorf("parse host %q: %w", target, err)
	}
	addr, err := newTargetAddress(host, port)
	if err != nil {
		return TargetAddress{}, fmt.Errorf("host %q is not usable for Fibre TLS verification: %w", endpoint, err)
	}
	if err := addr.Validate(); err != nil {
		return TargetAddress{}, fmt.Errorf("host %q is not usable for Fibre TLS verification: %w", endpoint, err)
	}
	return addr, nil
}

func newTargetAddress(host, port string) (TargetAddress, error) {
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	if host == "" {
		return TargetAddress{}, fmt.Errorf("validator host is required")
	}
	if ip := net.ParseIP(host); ip != nil {
		addr := TargetAddress{Host: ip.String(), IP: ip, Port: port}
		if err := addr.Validate(); err != nil {
			return TargetAddress{}, err
		}
		return addr, nil
	}
	host = strings.ToLower(host)
	addr := TargetAddress{Host: host, Port: port}
	if err := addr.Validate(); err != nil {
		return TargetAddress{}, err
	}
	return addr, nil
}

// TargetIP extracts the IP address clients are expected to verify from a gRPC
// target or host registry value. It is kept for IP-only callers; DNS targets
// should use [TargetAddressFromString].
func TargetIP(target string) (net.IP, error) {
	endpoint, err := TargetAddressFromString(target)
	if err != nil {
		return nil, err
	}
	if ip := endpoint.tlsIP(); ip != nil {
		return ip, nil
	}
	return nil, fmt.Errorf("host %q is not an IP address", target)
}

func targetEndpoint(target string) (string, error) {
	target = strings.TrimSpace(target)
	if target == "" {
		return "", fmt.Errorf("target is empty")
	}

	if !strings.Contains(target, "://") {
		return target, nil
	}

	parsed, err := url.Parse(target)
	if err != nil {
		return "", fmt.Errorf("parse target %q: %w", target, err)
	}

	endpoint := parsed.Host
	if endpoint == "" {
		endpoint = strings.TrimLeft(parsed.Path, "/")
	}
	if endpoint == "" {
		endpoint = parsed.Opaque
	}
	if endpoint == "" {
		return "", fmt.Errorf("target %q does not contain an endpoint", target)
	}
	return endpoint, nil
}

func hasServerAuthEKU(cert *x509.Certificate) bool {
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			return true
		}
	}
	return false
}

func validDNSName(host string) bool {
	if host == "" || len(host) > 253 || strings.HasSuffix(host, ".") {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' {
				continue
			}
			return false
		}
	}
	return true
}

func tlsEndorsementURIValue(cert *x509.Certificate) string {
	for _, uri := range cert.URIs {
		if uri != nil && strings.HasPrefix(uri.String(), tlsEndorsementURIPrefix) {
			return uri.String()
		}
	}
	return ""
}
