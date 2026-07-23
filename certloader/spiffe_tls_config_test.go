package certloader

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"testing"
	"time"

	spiffetest "github.com/ghostunnel/ghostunnel/certloader/internal/test"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/stretchr/testify/require"
)

func TestSPIFFELogger(t *testing.T) {
	logger := spiffeLogger{log: log.Default()}
	logger.Errorf("test")
	logger.Warnf("test")
	logger.Infof("test")
	logger.Debugf("test")
}

func TestWorkloadAPIClientDisableAuth(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	ca := spiffetest.NewCA(t, td)

	svid := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/foo"))

	workloadAPI := spiffetest.New(t)
	workloadAPI.SetX509SVIDResponse(
		&spiffetest.X509SVIDResponse{
			Bundle: ca.X509Bundle(),
			SVIDs:  []*x509svid.SVID{svid},
		})
	defer workloadAPI.Stop()

	log := log.Default()

	source, err := TLSConfigSourceFromWorkloadAPI(workloadAPI.Addr(), true, 10*time.Second, log)
	require.NoError(t, err)
	defer source.(*spiffeTLSConfigSource).Close()

	var clientVerifyCallCount int32
	clientBase := &tls.Config{
		VerifyPeerCertificate: countVerifyPeerCertificate(&clientVerifyCallCount),
	}
	clientConfig, err := source.GetClientConfig(clientBase)
	require.NoError(t, err)
	tlsConfig := clientConfig.GetClientConfig()
	require.Nil(t, tlsConfig.GetClientCertificate)
}

func TestWorkloadAPITLSConfigSource(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	ca := spiffetest.NewCA(t, td)

	svid := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/foo"))

	workloadAPI := spiffetest.New(t)
	workloadAPI.SetX509SVIDResponse(
		&spiffetest.X509SVIDResponse{
			Bundle: ca.X509Bundle(),
			SVIDs:  []*x509svid.SVID{svid},
		})
	defer workloadAPI.Stop()

	log := log.Default()

	source, err := TLSConfigSourceFromWorkloadAPI(workloadAPI.Addr(), false, 10*time.Second, log)
	require.NoError(t, err)
	defer source.(*spiffeTLSConfigSource).Close()

	// set up server configuration
	var serverVerifyCallCount int32
	serverBase := &tls.Config{
		VerifyPeerCertificate: countVerifyPeerCertificate(&serverVerifyCallCount),
	}
	serverConfig, err := source.GetServerConfig(serverBase)
	require.NoError(t, err)

	// set up client configuration
	var clientVerifyCallCount int32
	clientBase := &tls.Config{
		VerifyPeerCertificate: countVerifyPeerCertificate(&clientVerifyCallCount),
	}
	clientConfig, err := source.GetClientConfig(clientBase)
	require.NoError(t, err)

	// start up the server
	listener, err := tls.Listen("tcp", "localhost:0", serverConfig.GetServerConfig())
	require.NoError(t, err)
	defer listener.Close()
	go func() {
		t.Logf("ACCEPTING...")
		conn, err := listener.Accept()
		t.Logf("ACCEPTED: err=%v", err)
		if err == nil {
			defer conn.Close()
			_, err = fmt.Fprintln(conn, "PAYLOAD")
			t.Logf("WROTE RESPONSE: err=%v", err)
		}
	}()

	// dial the server
	t.Logf("DIALING...")
	conn, err := tls.Dial(listener.Addr().Network(), listener.Addr().String(), clientConfig.GetClientConfig())
	t.Logf("DIALED: err=%v", err)
	require.NoError(t, err)
	defer conn.Close()

	// read the response to assert the transport works
	t.Logf("READING RESPONSE...")
	_ = conn.SetReadDeadline(time.Now().Add(time.Second * 10))
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(conn)
	t.Logf("READ RESPONSE: response=%q err=%v", buf.String(), err)
	require.NoError(t, err)
	require.Equal(t, "PAYLOAD\n", buf.String())

	// assert base verification callback was called
	require.Equal(t, int32(1), atomic.LoadInt32(&clientVerifyCallCount))
	require.Equal(t, int32(1), atomic.LoadInt32(&serverVerifyCallCount))
}

func TestWorkloadAPISourceCreation(t *testing.T) {
	// SPIFFE client creation succeeds even with unreachable address (lazy connect).
	// This test exercises the TLSConfigSourceFromWorkloadAPI function to ensure
	// the source is created with correct settings.
	source, err := TLSConfigSourceFromWorkloadAPI("tcp://127.0.0.1:1", false, 10*time.Second, log.Default())
	require.NoError(t, err, "source creation should succeed (lazy connect)")
	defer source.(*spiffeTLSConfigSource).Close()

	require.NotNil(t, source, "source should not be nil")
	require.False(t, source.(*spiffeTLSConfigSource).clientDisableAuth, "clientDisableAuth should be false")
}

// TestWorkloadAPIUnreachableTimesOut verifies that when the Workload API is
// unreachable, building a config surfaces a bounded error (wrapping
// context.DeadlineExceeded) instead of hanging forever.
func TestWorkloadAPIUnreachableTimesOut(t *testing.T) {
	const initTimeout = 500 * time.Millisecond
	source, err := TLSConfigSourceFromWorkloadAPI("tcp://127.0.0.1:1", false, initTimeout, log.Default())
	require.NoError(t, err, "source creation should succeed (lazy connect)")
	defer source.(*spiffeTLSConfigSource).Close()

	done := make(chan error, 1)
	go func() {
		_, gerr := source.GetServerConfig(&tls.Config{})
		done <- gerr
	}()

	const guard = 5 * time.Second
	select {
	case gerr := <-done:
		require.Error(t, gerr, "expected an error from unreachable Workload API")
		require.ErrorIs(t, gerr, context.DeadlineExceeded, "want DeadlineExceeded, got: %v", gerr)
	case <-time.After(guard):
		t.Fatalf("GetServerConfig did not return within %s; newConfig is hanging (regression)", guard)
	}
}

func TestWorkloadAPISourceCreationDisableAuth(t *testing.T) {
	// Test source creation with clientDisableAuth=true
	source, err := TLSConfigSourceFromWorkloadAPI("tcp://127.0.0.1:1", true, 10*time.Second, log.Default())
	require.NoError(t, err, "source creation should succeed with auth disabled")
	defer source.(*spiffeTLSConfigSource).Close()

	spiffeSource := source.(*spiffeTLSConfigSource)
	require.True(t, spiffeSource.clientDisableAuth, "clientDisableAuth should be true")
}

func TestSpiffeTLSConfigSourceClose(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	ca := spiffetest.NewCA(t, td)

	svid := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/foo"))

	workloadAPI := spiffetest.New(t)
	workloadAPI.SetX509SVIDResponse(
		&spiffetest.X509SVIDResponse{
			Bundle: ca.X509Bundle(),
			SVIDs:  []*x509svid.SVID{svid},
		})
	defer workloadAPI.Stop()

	source, err := TLSConfigSourceFromWorkloadAPI(workloadAPI.Addr(), false, 10*time.Second, log.Default())
	require.NoError(t, err)

	// Explicitly test Close() method
	err = source.(*spiffeTLSConfigSource).Close()
	require.NoError(t, err, "Close should not return an error")
}

func TestWorkloadAPIServerConfigDisableAuth(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	ca := spiffetest.NewCA(t, td)

	svid := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/foo"))

	workloadAPI := spiffetest.New(t)
	workloadAPI.SetX509SVIDResponse(
		&spiffetest.X509SVIDResponse{
			Bundle: ca.X509Bundle(),
			SVIDs:  []*x509svid.SVID{svid},
		})
	defer workloadAPI.Stop()

	source, err := TLSConfigSourceFromWorkloadAPI(workloadAPI.Addr(), true, 10*time.Second, log.Default())
	require.NoError(t, err)
	defer source.(*spiffeTLSConfigSource).Close()

	serverBase := &tls.Config{}
	serverConfig, err := source.GetServerConfig(serverBase)
	require.NoError(t, err)

	tlsConfig := serverConfig.GetServerConfig()
	// When clientDisableAuth=true, ClientAuth should NOT be RequireAnyClientCert
	require.NotEqual(t, tls.RequireAnyClientCert, tlsConfig.ClientAuth,
		"ClientAuth should not require client certs when auth is disabled")
}

func countVerifyPeerCertificate(callCount *int32) func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) == 0 {
			return errors.New("raw certs were not passed through")
		}
		if len(verifiedChains) == 0 {
			return errors.New("verified chains were not passed through")
		}
		atomic.AddInt32(callCount, 1)
		return nil
	}
}

func TestSpiffeTLSConfigSourceReload(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	ca := spiffetest.NewCA(t, td)

	svid := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/foo"))

	workloadAPI := spiffetest.New(t)
	workloadAPI.SetX509SVIDResponse(
		&spiffetest.X509SVIDResponse{
			Bundle: ca.X509Bundle(),
			SVIDs:  []*x509svid.SVID{svid},
		})
	defer workloadAPI.Stop()

	source, err := TLSConfigSourceFromWorkloadAPI(workloadAPI.Addr(), false, 10*time.Second, log.Default())
	require.NoError(t, err)
	defer func() { _ = source.(*spiffeTLSConfigSource).Close() }()

	// Reload should be a no-op for SPIFFE (workload API maintains itself)
	err = source.Reload()
	require.NoError(t, err, "Reload should not return an error")
}

func TestTLSConfigSourceFromWorkloadAPIInvalidAddress(t *testing.T) {
	// Scheme is not "tcp" or "unix" -> setAddress returns ErrInvalidEndpointScheme
	// synchronously, so spiffeApi.New returns an error and TLSConfigSourceFromWorkloadAPI
	// exercises its `return nil, err` branch.
	source, err := TLSConfigSourceFromWorkloadAPI("invalid://malformed", false, 10*time.Second, log.Default())
	require.Error(t, err)
	require.Nil(t, source)
}

func TestNewConfigX509SourceErrorOnClosedClient(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	ca := spiffetest.NewCA(t, td)
	svid := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/foo"))

	api := spiffetest.New(t)
	api.SetX509SVIDResponse(&spiffetest.X509SVIDResponse{
		Bundle: ca.X509Bundle(),
		SVIDs:  []*x509svid.SVID{svid},
	})
	defer api.Stop()

	source, err := TLSConfigSourceFromWorkloadAPI(api.Addr(), false, 10*time.Second, log.Default())
	require.NoError(t, err)

	// Force the client into a failure state by closing the underlying gRPC ClientConn.
	// Subsequent calls reach newConfig, which calls spiffeApi.NewX509Source. The internal
	// watcher's WatchX509Context call fails on the closed connection and propagates
	// through errCh, exercising newConfig's `return nil, err` branch.
	require.NoError(t, source.(*spiffeTLSConfigSource).Close())

	_, err = source.GetClientConfig(&tls.Config{})
	require.Error(t, err)

	// Also exercise GetServerConfig — both call sites at spiffe_tls_config.go:60-66
	// route through newConfig, so this documents that both paths fail consistently.
	_, err = source.GetServerConfig(&tls.Config{})
	require.Error(t, err)
}

func TestSpiffeTLSConfigSourceCanServe(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	ca := spiffetest.NewCA(t, td)

	svid := ca.CreateX509SVID(spiffeid.RequireFromPath(td, "/foo"))

	workloadAPI := spiffetest.New(t)
	workloadAPI.SetX509SVIDResponse(
		&spiffetest.X509SVIDResponse{
			Bundle: ca.X509Bundle(),
			SVIDs:  []*x509svid.SVID{svid},
		})
	defer workloadAPI.Stop()

	source, err := TLSConfigSourceFromWorkloadAPI(workloadAPI.Addr(), false, 10*time.Second, log.Default())
	require.NoError(t, err)
	defer func() { _ = source.(*spiffeTLSConfigSource).Close() }()

	// CanServe should always return true for SPIFFE source
	require.True(t, source.CanServe(), "CanServe should return true")
}

// TestWorkloadAPISVIDRotation: when the Workload API streams a new X.509-SVID,
// subsequent TLS handshakes present the rotated certificate.
func TestWorkloadAPISVIDRotation(t *testing.T) {
	td := spiffeid.RequireTrustDomainFromString("example.org")
	ca := spiffetest.NewCA(t, td)

	id := spiffeid.RequireFromPath(td, "/foo")
	svid1 := ca.CreateX509SVID(id)

	workloadAPI := spiffetest.New(t)
	workloadAPI.SetX509SVIDResponse(&spiffetest.X509SVIDResponse{
		Bundle: ca.X509Bundle(),
		SVIDs:  []*x509svid.SVID{svid1},
	})
	defer workloadAPI.Stop()

	source, err := TLSConfigSourceFromWorkloadAPI(workloadAPI.Addr(), false, 10*time.Second, log.Default())
	require.NoError(t, err)
	defer func() { _ = source.(*spiffeTLSConfigSource).Close() }()

	serverConfig, err := source.GetServerConfig(&tls.Config{})
	require.NoError(t, err)

	listener, err := tls.Listen("tcp", "localhost:0", serverConfig.GetServerConfig())
	require.NoError(t, err)
	defer listener.Close()

	// Background accept loop, echoes "OK" so each handshake completes.
	// Exits when listener.Close() (deferred above) makes Accept return an error.
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = fmt.Fprintln(c, "OK")
			}(conn)
		}
	}()

	clientTLSConfig := &tls.Config{InsecureSkipVerify: true}

	dialAndGetServerCert := func() *x509.Certificate {
		t.Helper()
		conn, dialErr := tls.Dial(listener.Addr().Network(), listener.Addr().String(), clientTLSConfig)
		require.NoError(t, dialErr)
		defer conn.Close()
		require.NoError(t, conn.Handshake())
		_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := new(bytes.Buffer)
		_, _ = buf.ReadFrom(conn)
		state := conn.ConnectionState()
		require.NotEmpty(t, state.PeerCertificates, "server should present a certificate")
		return state.PeerCertificates[0]
	}

	cert1 := dialAndGetServerCert()
	require.Equal(t, svid1.Certificates[0].SerialNumber.String(), cert1.SerialNumber.String(),
		"server should present the initial SVID before rotation")

	svid2 := ca.CreateX509SVID(id)
	require.NotEqual(t, svid1.Certificates[0].SerialNumber.String(), svid2.Certificates[0].SerialNumber.String(),
		"sanity: rotated SVID must have a different serial")

	workloadAPI.SetX509SVIDResponse(&spiffetest.X509SVIDResponse{
		Bundle: ca.X509Bundle(),
		SVIDs:  []*x509svid.SVID{svid2},
	})

	// X509Source receives the new SVID asynchronously; poll until rotated.
	var cert2 *x509.Certificate
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		c := dialAndGetServerCert()
		if c.SerialNumber.String() == svid2.Certificates[0].SerialNumber.String() {
			cert2 = c
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	require.NotNil(t, cert2, "server did not rotate to the new SVID within deadline")
	require.NotEqual(t, cert1.SerialNumber.String(), cert2.SerialNumber.String(),
		"server certificate serial should change after SVID rotation")
	require.Equal(t, svid2.Certificates[0].SerialNumber.String(), cert2.SerialNumber.String(),
		"server should present the rotated SVID")
}
