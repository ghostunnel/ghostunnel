package spiffetest

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"

	"github.com/gogo/protobuf/proto"
	"github.com/spiffe/go-spiffe/proto/spiffe/workload"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

type WorkloadAPI struct {
	tb     testing.TB
	wg     sync.WaitGroup
	addr   string
	server *grpc.Server

	mu    sync.Mutex
	chans map[chan *workload.X509SVIDResponse]struct{}
	resp  *workload.X509SVIDResponse
}

func NewWorkloadAPI(tb testing.TB, resp *X509SVIDResponse) *WorkloadAPI {
	w := &WorkloadAPI{
		chans: make(map[chan *workload.X509SVIDResponse]struct{}),
	}
	if resp != nil {
		w.resp = resp.ToProto(tb)
	}

	listener, err := net.Listen("tcp", "localhost:0")
	require.NoError(tb, err)

	server := grpc.NewServer()
	workload.RegisterSpiffeWorkloadAPIServer(server, &workloadAPIWrapper{w: w})

	w.wg.Add(1)
	go func() {
		defer w.wg.Done()
		server.Serve(listener)
	}()

	w.addr = fmt.Sprintf("%s://%s", listener.Addr().Network(), listener.Addr().String())
	w.server = server
	return w
}

func (w *WorkloadAPI) Stop() {
	w.server.Stop()
	w.wg.Wait()
}

func (w *WorkloadAPI) Addr() string {
	return w.addr
}

func (w *WorkloadAPI) SetX509SVIDResponse(r *X509SVIDResponse) {
	var resp *workload.X509SVIDResponse
	if r != nil {
		resp = r.ToProto(w.tb)
	}

	w.mu.Lock()
	w.resp = resp
	for ch := range w.chans {
		select {
		case ch <- resp:
		default:
			<-ch
			ch <- resp
		}
	}
	w.mu.Unlock()
}

func (w *WorkloadAPI) fetchX509SVID(req *workload.X509SVIDRequest, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	if err := checkHeader(stream.Context()); err != nil {
		return err
	}
	ch := make(chan *workload.X509SVIDResponse, 1)
	w.mu.Lock()
	w.chans[ch] = struct{}{}
	resp := w.resp
	w.mu.Unlock()

	defer func() {
		w.mu.Lock()
		delete(w.chans, ch)
		w.mu.Unlock()
	}()

	sendResp := func(resp *workload.X509SVIDResponse) error {
		if resp == nil {
			return status.Error(codes.PermissionDenied, "no SVID available")
		}
		return stream.Send(resp)
	}

	if err := sendResp(resp); err != nil {
		return err
	}
	for {
		select {
		case resp := <-ch:
			if err := sendResp(resp); err != nil {
				return err
			}
		case <-stream.Context().Done():
			return stream.Context().Err()
		}
	}
}

type workloadAPIWrapper struct {
	w *WorkloadAPI
}

func (w *workloadAPIWrapper) FetchJWTSVID(ctx context.Context, req *workload.JWTSVIDRequest) (*workload.JWTSVIDResponse, error) {
	return nil, errors.New("unimplemented")
}

func (w *workloadAPIWrapper) FetchJWTBundles(req *workload.JWTBundlesRequest, stream workload.SpiffeWorkloadAPI_FetchJWTBundlesServer) error {
	return errors.New("unimplemented")
}

func (w *workloadAPIWrapper) ValidateJWTSVID(ctx context.Context, req *workload.ValidateJWTSVIDRequest) (*workload.ValidateJWTSVIDResponse, error) {
	return nil, errors.New("unimplemented")
}

func (w *workloadAPIWrapper) FetchX509SVID(req *workload.X509SVIDRequest, stream workload.SpiffeWorkloadAPI_FetchX509SVIDServer) error {
	return w.w.fetchX509SVID(req, stream)
}

type X509SVID struct {
	CertChain []*x509.Certificate
	Key       crypto.Signer
}

type X509SVIDResponse struct {
	SVIDs            []X509SVID
	Bundle           []*x509.Certificate
	FederatedBundles map[string][]*x509.Certificate
}

func (r *X509SVIDResponse) ToProto(tb testing.TB) *workload.X509SVIDResponse {
	bundle := derBlobFromCerts(r.Bundle)

	pb := &workload.X509SVIDResponse{
		FederatedBundles: make(map[string][]byte),
	}
	for _, svid := range r.SVIDs {
		// The workload API should always respond with at one certificate and a
		// private key but making this optional here is needed for some test
		// flexibility.
		var spiffeID string
		if len(svid.CertChain) > 0 && len(svid.CertChain[0].URIs) > 0 {
			spiffeID = svid.CertChain[0].URIs[0].String()
		}
		var keyDER []byte
		if svid.Key != nil {
			var err error
			keyDER, err = x509.MarshalPKCS8PrivateKey(svid.Key)
			require.NoError(tb, err)
		}
		pb.Svids = append(pb.Svids, &workload.X509SVID{
			SpiffeId:    spiffeID,
			X509Svid:    derBlobFromCerts(svid.CertChain),
			X509SvidKey: keyDER,
			Bundle:      bundle,
		})
	}
	for k, v := range r.FederatedBundles {
		pb.FederatedBundles[k] = derBlobFromCerts(v)
	}

	return pb
}

func derBlobFromCerts(certs []*x509.Certificate) []byte {
	var der []byte
	for _, cert := range certs {
		der = append(der, cert.Raw...)
	}
	return der
}

func cloneX509SVIDResponse(pb *workload.X509SVIDResponse) *workload.X509SVIDResponse {
	return proto.Clone(pb).(*workload.X509SVIDResponse)
}

func checkHeader(ctx context.Context) error {
	return checkMetadata(ctx, "workload.spiffe.io", "true")
}

func checkMetadata(ctx context.Context, key, value string) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return errors.New("request does not contain metadata")
	}
	values := md.Get(key)
	if len(value) == 0 {
		return fmt.Errorf("request metadata does not contain %q value", key)
	}
	if values[0] != value {
		return fmt.Errorf("request metadata %q value is %q; expected %q", key, values[0], value)
	}
	return nil
}
