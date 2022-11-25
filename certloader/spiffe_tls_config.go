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
	"log"

	spiffeConfig "github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	spiffeApi "github.com/spiffe/go-spiffe/v2/workloadapi"
)

type spiffeTLSConfigSource struct {
	client            *spiffeApi.Client
	clientDisableAuth bool
	logger            *log.Logger
}

func TLSConfigSourceFromWorkloadAPI(addr string, clientDisableAuth bool, logger *log.Logger) (TLSConfigSource, error) {
	client, err := spiffeApi.New(
		context.Background(),
		spiffeApi.WithAddr(addr),
		spiffeApi.WithLogger(spiffeLogger{log: logger}),
	)
	if err != nil {
		return nil, err
	}
	return &spiffeTLSConfigSource{
		client:            client,
		clientDisableAuth: clientDisableAuth,
		logger:            logger,
	}, nil
}

func (s *spiffeTLSConfigSource) Reload() error {
	// The config returned by the workload API maintains itself. Nothing to do here.
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
	return s.client.Close()
}

func (s *spiffeTLSConfigSource) newConfig(base *tls.Config) (*spiffeTLSConfig, error) {
	source, err := spiffeApi.NewX509Source(context.Background(), spiffeApi.WithClient(s.client))
	if err != nil {
		return nil, err
	}

	return &spiffeTLSConfig{
		base:              base,
		source:            source,
		clientDisableAuth: s.clientDisableAuth,
	}, nil
}

type spiffeTLSConfig struct {
	base              *tls.Config
	source            *spiffeApi.X509Source
	clientDisableAuth bool
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
	config.VerifyPeerCertificate = spiffeConfig.WrapVerifyPeerCertificate(config.VerifyPeerCertificate, c.source, spiffeConfig.AuthorizeAny())
	if !c.clientDisableAuth {
		// If auth is disabled on the client side we need to not set
		// the GetCertificate callback, because if we do it'll cause
		// the client to block forever if the SPIFFE Workload API
		// doesn't have a client certificate available for us.
		config.GetClientCertificate = spiffeConfig.GetClientCertificate(c.source)
	}
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
	config.VerifyPeerCertificate = spiffeConfig.WrapVerifyPeerCertificate(config.VerifyPeerCertificate, c.source, spiffeConfig.AuthorizeAny())
	config.GetCertificate = spiffeConfig.GetCertificate(c.source)
	return config
}
