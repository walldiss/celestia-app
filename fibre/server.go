package fibre

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"

	fibregrpc "github.com/celestiaorg/celestia-app/v9/fibre/internal/grpc"
	"github.com/celestiaorg/celestia-app/v9/fibre/state"
	core "github.com/cometbft/cometbft/types"
	"go.opentelemetry.io/otel/trace"
	grpclib "google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// Server implements the Fibre gRPC service for validators.
// It handles upload and download requests from clients.
type Server struct {
	Config ServerConfig

	state  state.Client
	store  *Store
	grpc   *fibregrpc.Server
	signer core.PrivValidator

	log     *slog.Logger
	tracer  trace.Tracer
	metrics *serverMetrics

	pruneDone chan struct{}
	cancel    context.CancelFunc
}

// NewServer creates a new Fibre [Server]. The store backend is determined by
// [ServerConfig.StoreFn], which defaults to [NewPebbleStore].
func NewServer(cfg ServerConfig) (*Server, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	stateClient, err := cfg.StateClientFn()
	if err != nil {
		return nil, err
	}

	metrics, err := newServerMetrics(cfg.Meter)
	if err != nil {
		return nil, fmt.Errorf("creating metrics: %w", err)
	}

	server := &Server{
		Config:  cfg,
		state:   stateClient,
		log:     cfg.Log,
		tracer:  cfg.Tracer,
		metrics: metrics,
	}

	return server, nil
}

// ListenAddress returns the actual address the server is listening on.
func (s *Server) ListenAddress() string {
	if s.grpc == nil {
		return s.Config.ServerListenAddress
	}
	return s.grpc.ListenAddress()
}

// ChainID returns the chain ID detected from the connected app node.
func (s *Server) ChainID() string {
	return s.state.ChainID()
}

// Store returns the server's store.
func (s *Server) Store() *Store {
	return s.store
}

// Start connects to the celestia-app node, creates the signer,
// starts serving gRPC requests, and kicks off background pruning.
// NOTE: Order of operations is important. Start the state client first,
// then create the signer, and finally start the pruning loop followed by the gRPC server.
func (s *Server) Start(ctx context.Context) (err error) {
	if err := s.state.Start(ctx); err != nil {
		return err
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, s.Stop(context.Background()))
		}
	}()

	s.signer, err = s.Config.SignerFn(s.state.ChainID())
	if err != nil {
		return fmt.Errorf("creating signer: %w", err)
	}
	s.log.Info("signer ready")

	s.store, err = s.Config.StoreFn(s.Config.StoreConfig)
	if err != nil {
		return fmt.Errorf("opening store: %w", err)
	}

	s.grpc, err = fibregrpc.Listen(s.Config.ServerListenAddress)
	if err != nil {
		return fmt.Errorf("creating gRPC listener: %w", err)
	}

	creds, err := s.serverTransportCredentials(ctx, s.grpc.ListenAddress())
	if err != nil {
		return fmt.Errorf("creating TLS credentials: %w", err)
	}

	err = s.grpc.Register(
		s,
		grpclib.Creds(creds),
		grpclib.MaxRecvMsgSize(s.Config.MaxMessageSize),
		grpclib.MaxSendMsgSize(s.Config.MaxMessageSize),
	)
	if err != nil {
		return fmt.Errorf("registering gRPC server: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel

	s.pruneDone = make(chan struct{})
	go func() {
		defer close(s.pruneDone)
		s.startPruneLoop(ctx)
	}()

	serveErr := s.grpc.Serve()
	go func() {
		if err, ok := <-serveErr; ok && err != nil {
			s.log.Error("gRPC serve loop exited", "error", err)
		}
	}()
	s.log.Info("serving gRPC", "addr", s.grpc.ListenAddress())
	return nil
}

// Stop gracefully stops the gRPC server and background routines,
// then closes the underlying store and app connection.
// Cancelling the context forces an immediate stop without waiting for in-flight requests.
func (s *Server) Stop(ctx context.Context) (err error) {
	s.log.Info("stopping server")
	if s.cancel != nil {
		s.cancel()
	}
	if s.grpc != nil {
		s.grpc.Stop(ctx)
	}
	if s.pruneDone != nil {
		<-s.pruneDone
	}

	if closer, ok := s.signer.(io.Closer); ok {
		if closeErr := closer.Close(); closeErr != nil {
			s.log.Error("closing signer", "error", closeErr)
			err = errors.Join(err, closeErr)
		}
	}
	if s.store != nil {
		if closeErr := s.store.Close(); closeErr != nil {
			s.log.Error("closing store", "error", closeErr)
			err = errors.Join(err, closeErr)
		}
	}
	if s.state != nil {
		if closeErr := s.state.Stop(ctx); closeErr != nil {
			s.log.Error("closing state client", "error", closeErr)
			err = errors.Join(err, closeErr)
		}
	}
	return err
}

func (s *Server) serverTransportCredentials(ctx context.Context, fallbackAddress string) (credentials.TransportCredentials, error) {
	pubKey, err := s.signer.GetPubKey()
	if err != nil {
		return nil, fmt.Errorf("getting validator public key: %w", err)
	}

	val := &core.Validator{
		Address: pubKey.Address(),
		PubKey:  pubKey,
	}
	endpoint, err := s.tlsAdvertiseEndpoint(ctx, val, fallbackAddress)
	if err != nil {
		return nil, err
	}

	return fibregrpc.ServerTransportCredentials(s.state.ChainID(), val.Address.String(), endpoint, s.signer)
}

func (s *Server) tlsAdvertiseEndpoint(ctx context.Context, val *core.Validator, fallbackAddress string) (fibregrpc.TargetAddress, error) {
	host, err := s.state.GetHost(ctx, val)
	if err == nil && host.String() != "" {
		endpoint, parseErr := fibregrpc.TargetAddressFromString(host.String())
		if parseErr != nil {
			return fibregrpc.TargetAddress{}, fmt.Errorf("registered fibre host %q cannot be used for TLS: %w", host.String(), parseErr)
		}
		if s.Config.TLSAdvertiseAddress != "" {
			configured, cfgErr := fibregrpc.TargetAddressFromString(s.Config.TLSAdvertiseAddress)
			if cfgErr != nil {
				return fibregrpc.TargetAddress{}, fmt.Errorf("tls_advertise_address %q cannot be used for TLS: %w", s.Config.TLSAdvertiseAddress, cfgErr)
			}
			if configured.Host != endpoint.Host || configured.Port != endpoint.Port {
				return fibregrpc.TargetAddress{}, fmt.Errorf("tls_advertise_address %q does not match registered fibre host %q", s.Config.TLSAdvertiseAddress, host.String())
			}
		}
		return endpoint, nil
	}
	if err != nil {
		s.log.DebugContext(ctx, "could not use registered fibre host for TLS", "error", err)
	}

	if s.Config.TLSAdvertiseAddress != "" {
		endpoint, err := fibregrpc.TargetAddressFromString(s.Config.TLSAdvertiseAddress)
		if err != nil {
			return fibregrpc.TargetAddress{}, fmt.Errorf("tls_advertise_address %q cannot be used for TLS: %w", s.Config.TLSAdvertiseAddress, err)
		}
		return endpoint, nil
	}

	endpoint, err := fibregrpc.TargetAddressFromString(fallbackAddress)
	if err != nil {
		return fibregrpc.TargetAddress{}, fmt.Errorf("could not determine Fibre TLS endpoint; set tls_advertise_address or register a usable fibre host: %w", err)
	}
	return endpoint, nil
}
