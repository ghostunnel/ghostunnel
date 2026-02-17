package certloader

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
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

	source, err := TLSConfigSourceFromWorkloadAPI(workloadAPI.Addr(), true, log)
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

	source, err := TLSConfigSourceFromWorkloadAPI(workloadAPI.Addr(), false, log)
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
	source, err := TLSConfigSourceFromWorkloadAPI("tcp://127.0.0.1:1", false, log.Default())
	require.NoError(t, err, "source creation should succeed (lazy connect)")
	defer source.(*spiffeTLSConfigSource).Close()

	require.NotNil(t, source, "source should not be nil")
	require.False(t, source.(*spiffeTLSConfigSource).clientDisableAuth, "clientDisableAuth should be false")
}

func TestWorkloadAPISourceCreationDisableAuth(t *testing.T) {
	// Test source creation with clientDisableAuth=true
	source, err := TLSConfigSourceFromWorkloadAPI("tcp://127.0.0.1:1", true, log.Default())
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

	source, err := TLSConfigSourceFromWorkloadAPI(workloadAPI.Addr(), false, log.Default())
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

	source, err := TLSConfigSourceFromWorkloadAPI(workloadAPI.Addr(), true, log.Default())
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

	source, err := TLSConfigSourceFromWorkloadAPI(workloadAPI.Addr(), false, log.Default())
	require.NoError(t, err)
	defer func() { _ = source.(*spiffeTLSConfigSource).Close() }()

	// Reload should be a no-op for SPIFFE (workload API maintains itself)
	err = source.Reload()
	require.NoError(t, err, "Reload should not return an error")
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

	source, err := TLSConfigSourceFromWorkloadAPI(workloadAPI.Addr(), false, log.Default())
	require.NoError(t, err)
	defer func() { _ = source.(*spiffeTLSConfigSource).Close() }()

	// CanServe should always return true for SPIFFE source
	require.True(t, source.CanServe(), "CanServe should return true")
}
