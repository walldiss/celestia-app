package grpc

import (
	"context"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"github.com/celestiaorg/celestia-app/v9/x/fibre/types"
	core "github.com/cometbft/cometbft/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

func TestTargetAddressFromString(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		wantHost string
		wantPort string
		wantIP   string
		wantErr  string
	}{
		{
			name:     "host port IPv4",
			target:   "127.0.0.1:7980",
			wantHost: "127.0.0.1",
			wantPort: "7980",
			wantIP:   "127.0.0.1",
		},
		{
			name:     "gRPC dns target IPv4",
			target:   "dns:///127.0.0.1:7980",
			wantHost: "127.0.0.1",
			wantPort: "7980",
			wantIP:   "127.0.0.1",
		},
		{
			name:     "host port IPv6",
			target:   "[::1]:7980",
			wantHost: "::1",
			wantPort: "7980",
			wantIP:   "::1",
		},
		{
			name:     "hostname accepted",
			target:   "validator.example.com:7980",
			wantHost: "validator.example.com",
			wantPort: "7980",
		},
		{
			name:    "unspecified IPv4 rejected",
			target:  "0.0.0.0:7980",
			wantErr: "unspecified IP",
		},
		{
			name:    "missing port rejected",
			target:  "127.0.0.1",
			wantErr: "parse host",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			endpoint, err := TargetAddressFromString(tt.target)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.wantHost, endpoint.Host)
			assert.Equal(t, tt.wantPort, endpoint.Port)
			if tt.wantIP != "" {
				require.NotNil(t, endpoint.IP)
				assert.Equal(t, tt.wantIP, endpoint.IP.String())
			} else {
				assert.Nil(t, endpoint.IP)
			}
		})
	}
}

func TestValidatorEndorsedTLSHandshake(t *testing.T) {
	pv := core.NewMockPV()
	val := pv.ExtractIntoValidator(1)
	ip := net.ParseIP("127.0.0.1")
	endpoint := testEndpoint(ip)

	serverCreds, err := ServerTransportCredentials("celestia", val.Address.String(), endpoint, pv)
	require.NoError(t, err)
	clientCreds, err := ClientTransportCredentials(val, endpoint, "celestia")
	require.NoError(t, err)

	require.NoError(t, handshake(serverCreds, clientCreds))
}

func TestValidatorEndorsedTLSHandshakeDNS(t *testing.T) {
	pv := core.NewMockPV()
	val := pv.ExtractIntoValidator(1)
	endpoint := TargetAddress{Host: "validator.example.com", Port: "7980"}

	serverCreds, err := ServerTransportCredentials("celestia", val.Address.String(), endpoint, pv)
	require.NoError(t, err)
	clientCreds, err := ClientTransportCredentials(val, endpoint, "celestia")
	require.NoError(t, err)

	require.NoError(t, handshake(serverCreds, clientCreds))
}

func TestValidatorEndorsedTLSVerification(t *testing.T) {
	pv := core.NewMockPV()
	val := pv.ExtractIntoValidator(1)
	ip := net.ParseIP("127.0.0.1")
	cert := endorsedCertificate(t, "celestia", val, ip, pv)

	require.NoError(t, verifyPeerCertificates([]*x509.Certificate{cert}, val, testEndpoint(ip), "celestia"))
}

func TestValidatorEndorsedTLSVerificationDNS(t *testing.T) {
	pv := core.NewMockPV()
	val := pv.ExtractIntoValidator(1)
	endpoint := TargetAddress{Host: "validator.example.com", Port: "7980"}
	cert := endorsedCertificateForEndpoint(t, "celestia", val, endpoint, pv)

	require.NoError(t, verifyPeerCertificates([]*x509.Certificate{cert}, val, endpoint, "celestia"))
	require.ErrorContains(t,
		verifyPeerCertificates([]*x509.Certificate{cert}, val, TargetAddress{Host: "other.example.com", Port: "7980"}, "celestia"),
		"do not exactly match validator host",
	)
}

func TestValidatorEndorsedTLSVerificationRejectsWrongValidator(t *testing.T) {
	serverPV := core.NewMockPV()
	serverVal := serverPV.ExtractIntoValidator(1)
	clientVal := core.NewMockPV().ExtractIntoValidator(1)
	ip := net.ParseIP("127.0.0.1")
	cert := endorsedCertificate(t, "celestia", serverVal, ip, serverPV)

	require.ErrorContains(t, verifyPeerCertificates([]*x509.Certificate{cert}, clientVal, testEndpoint(ip), "celestia"), "TLS endorsement validator mismatch")
}

func TestValidatorEndorsedTLSVerificationRejectsWrongIP(t *testing.T) {
	pv := core.NewMockPV()
	val := pv.ExtractIntoValidator(1)
	serverIP := net.ParseIP("127.0.0.1")
	clientIP := net.ParseIP("127.0.0.2")
	cert := endorsedCertificate(t, "celestia", val, serverIP, pv)

	require.ErrorContains(t, verifyPeerCertificates([]*x509.Certificate{cert}, val, testEndpoint(clientIP), "celestia"), "do not exactly match validator host")
}

func TestValidatorEndorsedTLSVerificationRejectsWrongChainID(t *testing.T) {
	pv := core.NewMockPV()
	val := pv.ExtractIntoValidator(1)
	ip := net.ParseIP("127.0.0.1")
	cert := endorsedCertificate(t, "celestia", val, ip, pv)

	require.ErrorContains(t, verifyPeerCertificates([]*x509.Certificate{cert}, val, testEndpoint(ip), "mocha"), "TLS endorsement chain ID mismatch")
}

func handshake(serverCreds, clientCreds credentials.TransportCredentials) error {
	listener := bufconn.Listen(1024 * 1024)
	server := grpclib.NewServer(grpclib.Creds(serverCreds))
	types.RegisterFibreServer(server, &types.UnimplementedFibreServer{})
	go func() {
		_ = server.Serve(listener)
	}()
	defer server.Stop()
	defer listener.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	conn, err := grpclib.DialContext(
		ctx,
		"passthrough:///bufnet",
		grpclib.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return listener.DialContext(ctx)
		}),
		grpclib.WithTransportCredentials(clientCreds),
		grpclib.WithBlock(),
	)
	if err != nil {
		return err
	}
	defer conn.Close()

	_, err = types.NewFibreClient(conn).DownloadShard(ctx, &types.DownloadShardRequest{})
	if status.Code(err) == codes.Unimplemented {
		return nil
	}
	return err
}

func endorsedCertificate(t *testing.T, chainID string, val *core.Validator, ip net.IP, signer core.PrivValidator) *x509.Certificate {
	t.Helper()
	return endorsedCertificateForEndpoint(t, chainID, val, testEndpoint(ip), signer)
}

func endorsedCertificateForEndpoint(t *testing.T, chainID string, val *core.Validator, endpoint TargetAddress, signer core.PrivValidator) *x509.Certificate {
	t.Helper()

	source := &serverTLSCertificateSource{
		chainID:          chainID,
		validatorAddress: val.Address.String(),
		endpoint:         endpoint,
		signer:           signer,
		validity:         time.Hour,
		now:              time.Now,
	}
	cert, err := source.currentCertificate()
	require.NoError(t, err)
	require.NotNil(t, cert.Leaf)
	return cert.Leaf
}

func testEndpoint(ip net.IP) TargetAddress {
	return TargetAddress{Host: ip.String(), IP: ip, Port: "7980"}
}
