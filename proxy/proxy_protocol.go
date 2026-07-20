/*-
 * Copyright 2026 Ghostunnel
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package proxy

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"net"

	proxyproto "github.com/pires/go-proxyproto"
)

// ProxyProtocolMode controls PROXY protocol v2 header generation.
type ProxyProtocolMode int

const (
	// ProxyProtocolOff disables PROXY protocol headers.
	ProxyProtocolOff ProxyProtocolMode = iota
	// ProxyProtocolConn sends connection info (src/dst IP+port) only, no TLVs.
	ProxyProtocolConn
	// ProxyProtocolTLS sends connection info + TLS metadata (version, ALPN, SNI) without client cert details.
	ProxyProtocolTLS
	// ProxyProtocolTLSFull sends connection info + all TLVs including client certificate.
	ProxyProtocolTLSFull
)

// PROXY protocol v2 client flag constants (from spec section 2.2.5).
const (
	pp2ClientSSL      = 0x01
	pp2ClientCertConn = 0x02
	pp2ClientCertSess = 0x04
)

func transportProtocol(c net.Conn) proxyproto.AddressFamilyAndProtocol {
	switch addr := c.RemoteAddr().(type) {
	case *net.TCPAddr:
		if addr.IP.To4() != nil {
			return proxyproto.TCPv4
		}
		return proxyproto.TCPv6
	case *net.UnixAddr:
		// Unix-domain listeners are valid PROXY protocol carriers; without
		// this case, go-proxyproto's formatVersion2 rejects the *net.UnixAddr
		// SourceAddr/DestinationAddr as ErrInvalidAddress and every connection
		// fails per-connection at WriteTo time.
		return proxyproto.UnixStream
	}
	return proxyproto.UNSPEC
}

func proxyProtoHeader(c net.Conn, tlsState *tls.ConnectionState, mode ProxyProtocolMode) (*proxyproto.Header, error) {
	h := &proxyproto.Header{
		Version:           2,
		Command:           proxyproto.PROXY,
		TransportProtocol: transportProtocol(c),
		SourceAddr:        c.RemoteAddr(),
		DestinationAddr:   c.LocalAddr(),
	}

	if tlsState != nil && mode >= ProxyProtocolTLS {
		tlvs, err := buildTLVs(tlsState, mode)
		if err != nil {
			return nil, fmt.Errorf("building PROXY protocol TLVs: %w", err)
		}
		if len(tlvs) > 0 {
			if err := h.SetTLVs(tlvs); err != nil {
				return nil, fmt.Errorf("setting PROXY protocol TLVs: %w", err)
			}
		}
	}

	return h, nil
}

// buildTLVs constructs the top-level TLV list from TLS connection state.
func buildTLVs(state *tls.ConnectionState, mode ProxyProtocolMode) ([]proxyproto.TLV, error) {
	var tlvs []proxyproto.TLV

	// PP2_TYPE_ALPN
	if state.NegotiatedProtocol != "" {
		tlvs = append(tlvs, proxyproto.TLV{
			Type:  proxyproto.PP2_TYPE_ALPN,
			Value: []byte(state.NegotiatedProtocol),
		})
	}

	// PP2_TYPE_AUTHORITY (SNI)
	if state.ServerName != "" {
		tlvs = append(tlvs, proxyproto.TLV{
			Type:  proxyproto.PP2_TYPE_AUTHORITY,
			Value: []byte(state.ServerName),
		})
	}

	// PP2_TYPE_SSL with nested sub-TLVs
	sslTLV, err := buildSSLTLV(state, mode)
	if err != nil {
		return nil, err
	}
	tlvs = append(tlvs, sslTLV)

	return tlvs, nil
}

// buildSSLTLV constructs the PP2_TYPE_SSL TLV with its 5-byte sub-header
// and nested sub-TLVs containing TLS connection metadata.
func buildSSLTLV(state *tls.ConnectionState, mode ProxyProtocolMode) (proxyproto.TLV, error) {
	var subTLVs []proxyproto.TLV

	// Always include TLS version
	subTLVs = append(subTLVs, proxyproto.TLV{
		Type:  proxyproto.PP2_SUBTYPE_SSL_VERSION,
		Value: []byte(tls.VersionName(state.Version)),
	})

	// Client certificate fields (only in TLSFull mode and if a cert was presented)
	if mode == ProxyProtocolTLSFull && len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]

		if cert.Subject.CommonName != "" {
			subTLVs = append(subTLVs, proxyproto.TLV{
				Type:  proxyproto.PP2_SUBTYPE_SSL_CN,
				Value: []byte(cert.Subject.CommonName),
			})
		}

		// Full DER-encoded client certificate (extension, not in HAProxy spec)
		subTLVs = append(subTLVs, proxyproto.TLV{
			Type:  proxyproto.PP2_SUBTYPE_SSL_CLIENT_CERT,
			Value: cert.Raw,
		})
	}

	// Build 5-byte sub-header: 1 byte flags + 4 bytes verify result
	var flags byte = pp2ClientSSL
	if mode == ProxyProtocolTLSFull && len(state.PeerCertificates) > 0 {
		// Set both flags: Ghostunnel doesn't distinguish connection-level vs
		// session-level (resumed) cert presentation — the cert was verified
		// on this connection either way.
		flags |= pp2ClientCertConn | pp2ClientCertSess
	}
	var header [5]byte
	header[0] = flags
	binary.BigEndian.PutUint32(header[1:5], 0) // verify=0, cert already verified by ghostunnel

	// Encode sub-TLVs and append after the 5-byte header
	subTLVBytes, err := proxyproto.JoinTLVs(subTLVs)
	if err != nil {
		return proxyproto.TLV{}, fmt.Errorf("encoding SSL sub-TLVs: %w", err)
	}

	value := make([]byte, len(header)+len(subTLVBytes))
	copy(value, header[:])
	copy(value[len(header):], subTLVBytes)

	return proxyproto.TLV{Type: proxyproto.PP2_TYPE_SSL, Value: value}, nil
}
