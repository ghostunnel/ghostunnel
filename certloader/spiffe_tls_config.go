/*-
 * Copyright 2019 Square Inc.
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

package certloader

import (
	"context"
	"crypto/tls"
	"crypto/x509"

	"github.com/spiffe/go-spiffe/spiffe"
)

type spiffeTLSConfigSource struct {
	peer *spiffe.TLSPeer
	log  Logger
}

type spiffeLogger struct {
	log Logger
}

func (l spiffeLogger) Debugf(format string, args ...interface{}) {
	l.log.Printf("(spiffe) [DEBUG]: "+format, args...)
}

func (l spiffeLogger) Infof(format string, args ...interface{}) {
	l.log.Printf("(spiffe) [INFO]: "+format, args...)
}

func (l spiffeLogger) Warnf(format string, args ...interface{}) {
	l.log.Printf("(spiffe) [WARN]: "+format, args...)
}

func (l spiffeLogger) Errorf(format string, args ...interface{}) {
	l.log.Printf("(spiffe) [ERROR]: "+format, args...)
}

func TLSConfigSourceFromWorkloadAPI(addr string, log Logger) (TLSConfigSource, error) {
	peer, err := spiffe.NewTLSPeer(
		spiffe.WithWorkloadAPIAddr(addr),
		spiffe.WithLogger(spiffeLogger{log: log}),
	)
	if err != nil {
		return nil, err
	}
	// TODO: provide a way to close the peer on graceful shutdown
	return &spiffeTLSConfigSource{
		peer: peer,
		log:  log,
	}, nil
}

func (s *spiffeTLSConfigSource) Reload() error {
	// The config returned by the workload TLSConfig maintains itself. Nothing
	// to do here.
	return nil
}

func (s *spiffeTLSConfigSource) CanServe() bool {
	return true
}

func (s *spiffeTLSConfigSource) GetClientConfig(base *tls.Config) (TLSClientConfig, error) {
	return s.newConfig(base)
}

func (s *spiffeTLSConfigSource) GetServerConfig(base *tls.Config) (TLSServerConfig, error) {
	return s.newConfig(base)
}

func (s *spiffeTLSConfigSource) Close() error {
	return s.peer.Close()
}

func (s *spiffeTLSConfigSource) newConfig(base *tls.Config) (*spiffeTLSConfig, error) {
	s.log.Printf("waiting for initial SPIFFE Workload API update...")
	if err := s.peer.WaitUntilReady(context.TODO()); err != nil {
		return nil, err
	}
	s.log.Printf("received SPIFFE Workload API update.")

	return &spiffeTLSConfig{
		base: base,
		peer: s.peer,
	}, nil
}

type spiffeTLSConfig struct {
	base *tls.Config
	peer *spiffe.TLSPeer
}

func (c *spiffeTLSConfig) GetClientConfig() *tls.Config {
	config := c.base.Clone()
	// Go TLS stack will do hostname validation with is not a part of SPIFFE
	// authentication. Unfortunately there is no way to just skip hostname
	// validation without having to turn off all verification. This is still
	// safe since Go will still invoke the VerifyPeerCertificate callback,
	// albeit with an empty set of verified chains. The VerifyPeerCertificate
	// callback provided by the SPIFFE library will perform SPIFFE
	// authentication against the raw certificates.
	config.InsecureSkipVerify = true
	config.VerifyPeerCertificate = c.chainVerifyPeerCertificate(config.VerifyPeerCertificate)
	config.GetClientCertificate = spiffe.AdaptGetClientCertificate(c.peer)
	return config
}

func (c *spiffeTLSConfig) GetServerConfig() *tls.Config {
	config := c.base.Clone()
	config.ClientAuth = tls.RequireAnyClientCert
	// Go TLS stack will do hostname validation with is not a part of SPIFFE
	// authentication. Unfortunately there is no way to just skip hostname
	// validation without having to turn off all verification. This is still
	// safe since Go will still invoke the VerifyPeerCertificate callback,
	// albeit with an empty set of verified chains. The VerifyPeerCertificate
	// callback provided by the SPIFFE library will perform SPIFFE
	// authentication against the raw certificates.
	config.InsecureSkipVerify = true
	config.VerifyPeerCertificate = c.chainVerifyPeerCertificate(config.VerifyPeerCertificate)
	config.GetCertificate = spiffe.AdaptGetCertificate(c.peer)
	return config
}

func (c *spiffeTLSConfig) chainVerifyPeerCertificate(orig func([][]byte, [][]*x509.Certificate) error) func([][]byte, [][]*x509.Certificate) error {
	return func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
		var certs []*x509.Certificate
		for _, rawCert := range rawCerts {
			cert, err := x509.ParseCertificate(rawCert)
			if err != nil {
				return err
			}
			certs = append(certs, cert)
		}

		// Grab the current set of roots.
		roots, err := c.peer.GetRoots()
		if err != nil {
			return err
		}

		// Verify the certificate chain. Allow the remote peer to have any SPIFFE ID as
		// the authorization check will happen via `orig`.
		verifiedChains, err := spiffe.VerifyPeerCertificate(certs, roots, spiffe.ExpectAnyPeer())
		if err != nil {
			return err
		}
		if orig != nil {
			return orig(rawCerts, verifiedChains)
		}
		return nil
	}
}
