[![Test](https://github.com/wrouesnel/go.connect-proxy-scheme/actions/workflows/test.yml/badge.svg)](https://github.com/wrouesnel/go.connect-proxy-scheme/actions/workflows/test.yml)
[![Quality](https://github.com/wrouesnel/go.connect-proxy-scheme/actions/workflows/quality.yml/badge.svg)](https://github.com/wrouesnel/go.connect-proxy-scheme/actions/workflows/quality.yml)
[![Coverage Status](https://coveralls.io/repos/github/wrouesnel/go.connect-proxy-scheme/badge.svg?branch=main)](https://coveralls.io/github/wrouesnel/go.connect-proxy-scheme?branch=main)

# HTTP Connect Scheme Support for golang.org/x/net/proxy

A [golang.org/x/net/proxy](https://pkg.go.dev/golang.org/x/net/proxy) compatible
scheme registration  that establishes the TCP connection over an [HTTP CONNECT Tunnel](https://en.wikipedia.org/wiki/HTTP_tunnel#HTTP_CONNECT_tunneling).

This is a refactor of https://github.com/mwitkow/go-http-dialer to make it compatible
with `golang.org/x/net/proxy`

## Features
 - [x] unencrypted connection to proxy (e.g. `http://proxy.example.com:3128`
 - [x] TLS connection to proxy (customizeable) (e.g. `https://proxy.example.com`)
 - [x] customizeable for `Proxy-Authenticate`, with challenge-response semantics
 - [x] out of the box support for `Basic` auth
 - [ ] appropriate `RemoteAddr` remapping
 

## Usage

### Simple

Just call `proxy.RegisterDialerType("http", connect_proxy_scheme.ConnectProxy)`
somewhere in your application to register the handler for HTTP.

Be aware that `HTTP_PROXY` and `HTTPS_PROXY` and related environment variables
are not picked up automatically by `golang.org/x/net/proxy` because it does
not have support for them (which this library adds). If you want to use
environment variable configuration you'll need to write it yourself.

### Worked Example

```go
package main
import (
	"fmt"
	"net/http"
	"net/url"
	"golang.org/x/net/proxy"
	"github.com/wrouesnel/go.connect-proxy-scheme"
)

func init() {
	proxy.RegisterDialerType("http", connect_proxy_scheme.ConnectProxy)
}

func main() {
	u, err := url.Parse("http://some-squid-proxy:3128")
	if err != nil {
		panic(err)
    }
	
	dialer, err := proxy.FromURL(u, proxy.Direct)
	if err != nil {
		panic(err)
    }

	tr := &http.Transport{
		DialContext: proxy.DialContext,
	}
	client := http.Client{Transport: tr}
	
	resp, err := client.Get("http://google.com")
	if err != nil {
		panic(err)
    }
	
	fmt.Println(resp)
}
```