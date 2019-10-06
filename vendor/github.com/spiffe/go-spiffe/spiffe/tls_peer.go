package spiffe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/spiffe/go-spiffe/workload"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type TLSPeerOption func(*TLSPeer) error

// WithWorkloadAPIAddr overrides the address used to reach the SPIFFE Workload
// API. By default, the SPIFFE_ENDPOINT_SOCKET environment variable is used
// to convey the address.
func WithWorkloadAPIAddr(addr string) func(*TLSPeer) error {
	return func(p *TLSPeer) error {
		p.addr = addr
		return nil
	}
}

// WithLogger provides a logger to the TLSPeer
func WithLogger(log Logger) func(*TLSPeer) error {
	return func(p *TLSPeer) error {
		p.log = log
		return nil
	}
}

// TLSPeer connects to the workload API and provides up-to-date identity and
// trusted roots for TLS dialing and listening.
type TLSPeer struct {
	log    Logger
	addr   string
	client *workload.X509SVIDClient

	readyOnce sync.Once
	ready     chan struct{}

	mu    sync.RWMutex
	cert  *tls.Certificate
	roots map[string]*x509.CertPool
}

// NewTLSPeer creates a new TLSPeer using the provided options.
func NewTLSPeer(opts ...TLSPeerOption) (*TLSPeer, error) {
	p := &TLSPeer{
		ready: make(chan struct{}),
	}

	for _, opt := range opts {
		if err := opt(p); err != nil {
			return nil, err
		}
	}

	if p.log == nil {
		p.log = nullLogger{}
	}

	var dialOpts []workload.DialOption
	if p.addr != "" {
		dialOpts = append(dialOpts, workload.WithAddr(p.addr))
	}

	client, err := workload.NewX509SVIDClient(&tlsPeerWatcher{p: p}, dialOpts...)
	if err != nil {
		return nil, err
	}
	client.Start()

	p.client = client
	return p, nil
}

// Close closes the TLSPeer. It stops listening to Workload API updates. Any
// configuration obtained from the TLSPeer (directly or indirectly) is still
// valid but will no longer stay up-to-date.
func (p *TLSPeer) Close() error {
	return p.client.Stop()
}

// WaitUntilReady blocks until the peer has retrieved its first update from
// the Workload API or the provided context is canceled.
func (p *TLSPeer) WaitUntilReady(ctx context.Context) error {
	select {
	case <-p.ready:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// GetCertificate returns the TLS certificate returned from the Workload API.
// It fails if no certificate has been obtained. Call WaitUntilReady() first to
// ensure this call will succeed.
func (p *TLSPeer) GetCertificate() (*tls.Certificate, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.cert == nil {
		return nil, errors.New("workload does not have a certificate yet")
	}
	return p.cert, nil
}

// GetRoots returns a map from trust domain ID (i.e. spiffe://domain.test) to
// trusted roots pool returned from the Workload API.  It fails if no roots
// have been obtain. Call WaitUntilReady() first to ensure this call will
// succeed.
func (p *TLSPeer) GetRoots() (map[string]*x509.CertPool, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	if p.roots == nil {
		return nil, errors.New("workload does not have roots yet")
	}
	return p.roots, nil
}

// Dial dials to a remote peer using the network and address provided. It
// returns a TLS connection. If the remote peer does not have a SPIFFE ID
// allowable by the expectPeer callback, the TLS handshake will fail.
func (p *TLSPeer) Dial(ctx context.Context, network, address string, expectPeer ExpectPeerFunc) (net.Conn, error) {
	rawConn, err := new(net.Dialer).DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}

	config, err := p.GetConfig(ctx, expectPeer)
	if err != nil {
		rawConn.Close()
		return nil, err
	}

	// TODO: apply ctx timeouts to the handshake
	tlsConn := tls.Client(rawConn, config)
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, err
	}

	return tlsConn, nil
}

// Listen starts listening for remote peers using the network and address
// provided. It returns a listener, which should closed when finished to
// release resources.
func (p *TLSPeer) Listen(ctx context.Context, network, address string, expectPeer ExpectPeerFunc) (net.Listener, error) {
	inner, err := net.Listen(network, address)
	if err != nil {
		return nil, err
	}

	l, err := p.NewListener(ctx, inner, expectPeer)
	if err != nil {
		inner.Close()
		return nil, err
	}

	return l, nil
}

// NewListener wraps an existing listener in a TLS listener configured using
// credentials and roots returned from the Workload API.
func (p *TLSPeer) NewListener(ctx context.Context, inner net.Listener, expectPeer ExpectPeerFunc) (net.Listener, error) {
	config, err := p.GetConfig(ctx, expectPeer)
	if err != nil {
		return nil, err
	}
	return tls.NewListener(inner, config), nil
}

// GetConfig returns th peer TLS configuration that can be used to dial or
// listen for remote peers. The remote peer SPIFFE ID must be allowed by the
// provided expectPeer callback or the TLS handshake will fail. This function
// blocks until the peer is ready (see WaitUntilReady).
func (p *TLSPeer) GetConfig(ctx context.Context, expectPeer ExpectPeerFunc) (*tls.Config, error) {
	if expectPeer == nil {
		return nil, errors.New("authorize callback is required")
	}
	if err := p.WaitUntilReady(ctx); err != nil {
		return nil, err
	}
	return &tls.Config{
		ClientAuth:            tls.RequireAnyClientCert,
		InsecureSkipVerify:    true,
		GetCertificate:        AdaptGetCertificate(p),
		GetClientCertificate:  AdaptGetClientCertificate(p),
		VerifyPeerCertificate: AdaptVerifyPeerCertificate(p, expectPeer),
	}, nil
}

// DialGRPC dials the gRPC endpoint addr using the peer TLS configuration.
func (p *TLSPeer) DialGRPC(ctx context.Context, addr string, expectPeer ExpectPeerFunc, opts ...grpc.DialOption) (*grpc.ClientConn, error) {
	config, err := p.GetConfig(ctx, expectPeer)
	if err != nil {
		return nil, err
	}
	return grpc.DialContext(ctx, addr, append([]grpc.DialOption{
		grpc.WithTransportCredentials(credentials.NewTLS(config)),
	}, opts...)...)
}

func (p *TLSPeer) updateX509SVIDs(svids *workload.X509SVIDs) {
	p.log.Debugf("X509SVID workload API update received")

	// Use the default SVID for now
	// TODO: expand SVID selection options
	svid := svids.Default()
	_, trustDomainID, err := getIDsFromCertificate(svid.Certificates[0])
	if err != nil {
		p.onError(fmt.Errorf("unable to parse IDs from X509-SVID update: %v", err))
		return
	}

	cert := &tls.Certificate{
		Certificate: make([][]byte, 0, len(svid.Certificates)),
		PrivateKey:  svid.PrivateKey,
	}
	for _, svidCert := range svid.Certificates {
		cert.Certificate = append(cert.Certificate, svidCert.Raw)
	}

	roots := make(map[string]*x509.CertPool)
	for federatedDomainID, federatedDomainPool := range svid.FederatedTrustBundlePools {
		roots[federatedDomainID] = federatedDomainPool
	}
	roots[trustDomainID] = svid.TrustBundlePool

	p.mu.Lock()
	p.cert = cert
	p.roots = roots
	p.mu.Unlock()

	p.readyOnce.Do(func() {
		close(p.ready)
	})
}

func (p *TLSPeer) onError(err error) {
	p.log.Errorf("%v", err)
}

// AdaptGetCertificate is a convenience function used to adapt a TLSPeer to
// the tls.Config GetCertificate callback.
func AdaptGetCertificate(p *TLSPeer) func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return p.GetCertificate()
	}
}

// AdaptGetClientCertificate is a convenience function used to adapt a TLSPeer to
// the tls.Config GetClientCertificate callback.
func AdaptGetClientCertificate(p *TLSPeer) func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
		return p.GetCertificate()
	}
}

// AdaptVerifyPeerCertificate is a convenience function used to adapt a TLSPeer
// to the tls.Config VerifyPeerCertificate callback. It uses the
// VerifyPeerCertificate function from this package under the covers, using
// roots obtained from the TLS peer. The expectPeer callback is used to
// verify remote peer SPIFFE IDs.
func AdaptVerifyPeerCertificate(p *TLSPeer, expectPeer ExpectPeerFunc) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		var certs []*x509.Certificate
		for i, rawCert := range rawCerts {
			cert, err := x509.ParseCertificate(rawCert)
			if err != nil {
				p.log.Errorf("unable to parse certificate %d: %v", i, err)
				return err
			}
			certs = append(certs, cert)
		}

		roots, err := p.GetRoots()
		if err != nil {
			p.log.Errorf("unable to get roots: %v", err)
			return err
		}
		if _, err := VerifyPeerCertificate(certs, roots, expectPeer); err != nil {
			p.log.Errorf("unable to verify client peer chain: %v", err)
			return err
		}
		return nil
	}
}

// ListenTLS is a convenience wrapper for listening for remote peers using
// credentials obtained from the workload API. If more control is required it
// is recomended to use the TLSPeer instead.
func ListenTLS(ctx context.Context, network, addr string, expectPeer ExpectPeerFunc) (net.Listener, error) {
	tlsPeer, err := NewTLSPeer()
	if err != nil {
		return nil, err
	}

	listener, err := tlsPeer.Listen(ctx, network, addr, expectPeer)
	if err != nil {
		tlsPeer.Close()
		return nil, err
	}

	return &tlsListener{
		Listener: listener,
		tlsPeer:  tlsPeer,
	}, nil
}

// DialTLS is a convenience wrapper for dialing remote peers using credentials
// obtained from the workload API. If more control is required it is
// recommended to use the TLSPeer instead.
func DialTLS(ctx context.Context, network, addr string, expectPeer ExpectPeerFunc) (net.Conn, error) {
	tlsPeer, err := NewTLSPeer()
	if err != nil {
		return nil, err
	}
	defer tlsPeer.Close()
	return tlsPeer.Dial(ctx, network, addr, expectPeer)
}

type tlsPeerWatcher struct {
	p *TLSPeer
}

func (w *tlsPeerWatcher) UpdateX509SVIDs(svids *workload.X509SVIDs) {
	w.p.updateX509SVIDs(svids)
}

func (w *tlsPeerWatcher) OnError(err error) {
	w.p.onError(err)
}

type tlsListener struct {
	net.Listener
	tlsPeer *TLSPeer
}

func (l *tlsListener) Close() error {
	err1 := l.tlsPeer.Close()
	err2 := l.Listener.Close()
	if err1 != nil {
		return err1
	}
	return err2
}
