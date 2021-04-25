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

	"github.com/spiffe/go-spiffe/spiffetest"
	"github.com/stretchr/testify/require"
)

func TestSPIFFELogger(t *testing.T) {
	logger := spiffeLogger{log: log.Default()}
	logger.Errorf("test")
	logger.Warnf("test")
	logger.Infof("test")
	logger.Debugf("test")
}

func TestWorkloadAPITLSConfigSource(t *testing.T) {
	ca := spiffetest.NewCA(t)

	cert, key := ca.CreateX509SVID("spiffe://domain.test/workload")

	workloadAPI := spiffetest.NewWorkloadAPI(t, &spiffetest.X509SVIDResponse{
		Bundle: ca.Roots(),
		SVIDs: []spiffetest.X509SVID{
			{
				CertChain: cert,
				Key:       key,
			},
		},
	})
	defer workloadAPI.Stop()

	log := log.Default()

	source, err := TLSConfigSourceFromWorkloadAPI(workloadAPI.Addr(), log)
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
	conn.SetReadDeadline(time.Now().Add(time.Second * 10))
	buf := new(bytes.Buffer)
	_, err = buf.ReadFrom(conn)
	t.Logf("READ RESPONSE: response=%q err=%v", buf.String(), err)
	require.NoError(t, err)
	require.Equal(t, "PAYLOAD\n", buf.String())

	// assert base verification callback was called
	require.Equal(t, int32(1), atomic.LoadInt32(&clientVerifyCallCount))
	require.Equal(t, int32(1), atomic.LoadInt32(&serverVerifyCallCount))
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
