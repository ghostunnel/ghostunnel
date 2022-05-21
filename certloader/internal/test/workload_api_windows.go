//go:build windows
// +build windows

package spiffetest

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/spiffe/go-spiffe/v2/proto/spiffe/workload"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
)

func NewWithNamedPipeListener(tb testing.TB) *WorkloadAPI {
	w := &WorkloadAPI{
		x509Chans:       make(map[chan *workload.X509SVIDResponse]struct{}),
		jwtBundlesChans: make(map[chan *workload.JWTBundlesResponse]struct{}),
	}

	listener, err := winio.ListenPipe(fmt.Sprintf(`\\.\pipe\go-spiffe-test-pipe-%x`, rand.Uint64()), nil)
	require.NoError(tb, err)

	server := grpc.NewServer()
	workload.RegisterSpiffeWorkloadAPIServer(server, &workloadAPIWrapper{w: w})

	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		_ = server.Serve(listener)
	}()

	w.addr = listener.Addr().String()
	tb.Logf("WorkloadAPI address: %s", w.addr)
	w.server = server
	return w
}

func init() {
	rand.Seed(time.Now().UnixNano())
}
