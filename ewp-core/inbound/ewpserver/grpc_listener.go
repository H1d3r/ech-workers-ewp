package ewpserver

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"ewp-core/log"
	pb "ewp-core/proto"
	"ewp-core/transport"
	grpctransport "ewp-core/transport/grpc"
)

// NewGRPCListener returns a Listener for inbound EWP-over-gRPC tunnels.
//
// tlsCfg is required for any internet-facing deployment; for tests
// you may pass nil to run in plaintext.
func NewGRPCListener(listen string, tlsCfg *tls.Config) Listener {
	return &grpcListenerAdapter{
		listen: listen,
		tlsCfg: tlsCfg,
		conns:  make(chan transport.TunnelConn, 32),
	}
}

type grpcListenerAdapter struct {
	listen string
	tlsCfg *tls.Config
	conns  chan transport.TunnelConn

	mu     sync.Mutex
	srv    *grpc.Server
	netLn  net.Listener
	closed bool
}

// run is invoked once by ewpserver.Inbound.Start (we satisfy the
// optional Runner interface).
func (g *grpcListenerAdapter) run(ctx context.Context) {
	go func() {
		ln, err := net.Listen("tcp", g.listen)
		if err != nil {
			log.Printf("[ewpserver/grpc] listen %s: %v", g.listen, err)
			close(g.conns)
			return
		}
		g.mu.Lock()
		if g.closed {
			g.mu.Unlock()
			_ = ln.Close()
			close(g.conns)
			return
		}
		g.netLn = ln

		var opts []grpc.ServerOption
		if g.tlsCfg != nil {
			opts = append(opts, grpc.Creds(credentials.NewTLS(g.tlsCfg)))
		}
		srv := grpc.NewServer(opts...)
		pb.RegisterProxyServiceServer(srv, &grpcServerHandler{conns: g.conns})
		g.srv = srv
		g.mu.Unlock()

		go func() {
			<-ctx.Done()
			g.Close()
		}()

		log.Printf("[ewpserver/grpc] listening on %s (TLS=%v)", g.listen, g.tlsCfg != nil)
		err = srv.Serve(ln)
		if err != nil {
			log.V("[ewpserver/grpc] serve: %v", err)
		}
		close(g.conns)
	}()
}

func (g *grpcListenerAdapter) Accept() (transport.TunnelConn, error) {
	c, ok := <-g.conns
	if !ok {
		return nil, errors.New("grpc listener closed")
	}
	return c, nil
}

func (g *grpcListenerAdapter) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.closed {
		return nil
	}
	g.closed = true
	if g.srv != nil {
		go g.srv.GracefulStop()
	}
	if g.netLn != nil {
		_ = g.netLn.Close()
	}
	return nil
}

func (g *grpcListenerAdapter) Addr() string {
	if g.tlsCfg != nil {
		return "grpc+tls://" + g.listen
	}
	return "grpc://" + g.listen
}

// grpcServerHandler turns each Tunnel RPC stream into a TunnelConn
// and pushes it onto the listener's accept channel. It blocks the
// gRPC handler goroutine until the engine releases the connection,
// because returning would terminate the underlying stream.
type grpcServerHandler struct {
	pb.UnimplementedProxyServiceServer
	conns chan<- transport.TunnelConn
}

type grpcTunnelConn struct {
	*grpctransport.ServerAdapter
	done chan struct{}
}

func (c *grpcTunnelConn) Close() error {
	select {
	case <-c.done:
	default:
		close(c.done)
	}
	return c.ServerAdapter.Close()
}

func (h *grpcServerHandler) Tunnel(stream pb.ProxyService_TunnelServer) error {
	adapter := grpctransport.NewServerAdapter(stream)
	conn := &grpcTunnelConn{ServerAdapter: adapter, done: make(chan struct{})}
	select {
	case h.conns <- conn:
	case <-stream.Context().Done():
		return stream.Context().Err()
	}
	// Block until the engine closes the connection or the client
	// disconnects. Returning here would terminate the stream.
	select {
	case <-conn.done:
	case <-stream.Context().Done():
	}
	return nil
}
