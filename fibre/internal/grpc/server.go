package grpc

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/celestiaorg/celestia-app/v9/x/fibre/types"
	"google.golang.org/grpc"
)

// Server wraps a [grpc.Server] with TCP listener and lifecycle management.
type Server struct {
	server   *grpc.Server
	listener net.Listener
	done     chan struct{}
	serveErr chan error
}

// NewServer creates a Fibre gRPC [Server] that listens on the given address
// and registers the provided [types.FibreServer] service.
func NewServer(listenAddr string, service types.FibreServer, opts ...grpc.ServerOption) (*Server, error) {
	server, err := Listen(listenAddr)
	if err != nil {
		return nil, err
	}
	if err := server.Register(service, opts...); err != nil {
		_ = server.listener.Close()
		return nil, err
	}
	return server, nil
}

// Listen creates a Fibre gRPC [Server] listener without registering the gRPC
// service yet. Callers that need the actual bound address for TLS identity can
// inspect [Server.ListenAddress] before calling [Server.Register].
func Listen(listenAddr string) (*Server, error) {
	listener, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", listenAddr, err)
	}
	return &Server{listener: listener}, nil
}

// Register creates the underlying gRPC server and registers service.
func (s *Server) Register(service types.FibreServer, opts ...grpc.ServerOption) error {
	if s.server != nil {
		return fmt.Errorf("gRPC server already registered")
	}
	if service == nil {
		return fmt.Errorf("fibre service is required")
	}
	server := grpc.NewServer(opts...)
	types.RegisterFibreServer(server, service)
	s.server = server
	return nil
}

// ListenAddress returns the actual address the server is listening on.
func (s *Server) ListenAddress() string {
	return s.listener.Addr().String()
}

// Serve starts serving gRPC requests in a background goroutine and returns a
// channel that receives unexpected serve-loop errors.
func (s *Server) Serve() <-chan error {
	if s.server == nil {
		errc := make(chan error, 1)
		errc <- fmt.Errorf("gRPC server is not registered")
		close(errc)
		return errc
	}
	s.done = make(chan struct{})
	s.serveErr = make(chan error, 1)
	go func() {
		defer close(s.done)
		defer close(s.serveErr)
		if err := s.server.Serve(s.listener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			s.serveErr <- err
		}
	}()
	return s.serveErr
}

// Stop gracefully stops the gRPC server.
// If the context is cancelled before draining completes, it forces an immediate stop.
func (s *Server) Stop(ctx context.Context) {
	if s.done == nil {
		if s.listener != nil {
			_ = s.listener.Close()
		}
		if s.server != nil {
			s.server.Stop()
		}
		return
	}

	done := make(chan struct{})
	go func() {
		s.server.GracefulStop()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
		s.server.Stop()
	}

	<-s.done
}
