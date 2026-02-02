// Package connectproxy provides an HTTP CONNECT proxy dialer for use with
// golang.org/x/net/proxy. It allows establishing TCP connections through an
// HTTP CONNECT proxy.
package connectproxy

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"

	"golang.org/x/net/proxy"
)

// ConnectProxy is a proxy.Dialer factory for use with proxy.RegisterDialerType.
func ConnectProxy(proxyURL *url.URL, dialer proxy.Dialer) (proxy.Dialer, error) {
	port := proxyURL.Port()
	if port == "" {
		if proxyURL.Scheme == "https" {
			port = "443"
		} else {
			port = "8080"
		}
	}

	return &httpConnectDialer{
		parentDialer: dialer,
		proxyHost:    proxyURL.Hostname(),
		proxyPort:    port,
	}, nil
}

type httpConnectDialer struct {
	parentDialer proxy.Dialer
	proxyHost    string
	proxyPort    string
}

var _ proxy.Dialer = (*httpConnectDialer)(nil)
var _ proxy.ContextDialer = (*httpConnectDialer)(nil)

func (d *httpConnectDialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

func (d *httpConnectDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, fmt.Errorf("connectproxy: network type %q unsupported (only \"tcp\")", network)
	}

	var (
		conn net.Conn
		err  error
	)

	proxyAddr := net.JoinHostPort(d.proxyHost, d.proxyPort)
	if cd, ok := d.parentDialer.(proxy.ContextDialer); ok {
		conn, err = cd.DialContext(ctx, "tcp", proxyAddr)
	} else {
		conn, err = d.parentDialer.Dial("tcp", proxyAddr)
	}
	if err != nil {
		return nil, fmt.Errorf("connectproxy: failed dialing proxy: %w", err)
	}

	req := &http.Request{
		Method: "CONNECT",
		URL:    &url.URL{Opaque: address},
		Host:   address,
		Header: make(http.Header),
	}

	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}

	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("connectproxy: failed writing CONNECT request: %w", err)
	}

	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("connectproxy: failed reading response: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("connectproxy: proxy returned status %d: %s", resp.StatusCode, resp.Status)
	}

	conn.SetDeadline(time.Time{})

	return conn, nil
}
