package grpc

import (
	"context"
	"errors"
	"io"

	"github.com/celestiaorg/celestia-app/v9/fibre/validator"
	"github.com/celestiaorg/celestia-app/v9/x/fibre/types"
	core "github.com/cometbft/cometbft/types"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	grpclib "google.golang.org/grpc"
)

var (
	errMissingChainIDProvider = errors.New("chain ID provider is required")
	errEmptyChainID           = errors.New("chain ID is empty; state client must be started before dialing")
)

// Client combines [FibreClient] with [io.Closer] to manage the lifecycle
// of both the client and its underlying connection.
type Client interface {
	types.FibreClient
	io.Closer
}

// NewClientFn is a constructor function that creates a [Client]
// for a given validator. It should handle host resolution and connection establishment.
type NewClientFn func(ctx context.Context, val *core.Validator) (Client, error)

// fibreClientCloser wraps a [FibreClient] and [grpclib.ClientConn] to implement [Client].
type fibreClientCloser struct {
	types.FibreClient
	conn *grpclib.ClientConn
}

func (f *fibreClientCloser) Close() error {
	return f.conn.Close()
}

// DefaultNewClientFn returns the default [NewClientFn] that uses the provided
// [validator.HostRegistry] to resolve validator hosts and establishes TLS gRPC connections
// with OpenTelemetry instrumentation for distributed tracing. The peer certificate must
// be endorsed by the expected validator and match the validator host and port.
// The maxMsgSize parameter sets the maximum gRPC message size for send and receive operations.
func DefaultNewClientFn(hostReg validator.HostRegistry, chainID func() string, maxMsgSize int) NewClientFn {
	return func(ctx context.Context, val *core.Validator) (Client, error) {
		host, err := hostReg.GetHost(ctx, val)
		if err != nil {
			return nil, err
		}

		endpoint, err := TargetAddressFromString(host.String())
		if err != nil {
			return nil, err
		}
		if chainID == nil {
			return nil, errMissingChainIDProvider
		}
		cid := chainID()
		if cid == "" {
			return nil, errEmptyChainID
		}
		creds, err := ClientTransportCredentials(val, endpoint, cid)
		if err != nil {
			return nil, err
		}

		conn, err := grpclib.NewClient(host.String(),
			grpclib.WithTransportCredentials(creds),
			grpclib.WithStatsHandler(otelgrpc.NewClientHandler()),
			grpclib.WithDefaultCallOptions(
				grpclib.MaxCallRecvMsgSize(maxMsgSize),
				grpclib.MaxCallSendMsgSize(maxMsgSize),
			),
		)
		if err != nil {
			return nil, err
		}

		return &fibreClientCloser{
			FibreClient: types.NewFibreClient(conn),
			conn:        conn,
		}, nil
	}
}
