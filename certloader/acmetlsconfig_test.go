/*-
 * Copyright 2025 Ghostunnel
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
	"crypto/tls"
	"testing"

	"github.com/caddyserver/certmagic"
	"github.com/mholt/acmez"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Note: Full ACME testing requires external ACME server interaction.
// These tests cover the code paths that can be tested without external dependencies.

func TestACMETLSConfigSourceGetClientConfigError(t *testing.T) {
	// GetClientConfig should always fail for ACME sources
	// (ACME is server-only feature)
	source := &acmeTLSConfigSource{
		magicConfig:  certmagic.NewDefault(),
		gtACMEConfig: &ACMEConfig{},
	}

	_, err := source.GetClientConfig(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not supported in client mode")
}

func TestACMETLSConfigSourceCanServe(t *testing.T) {
	source := &acmeTLSConfigSource{
		magicConfig:  certmagic.NewDefault(),
		gtACMEConfig: &ACMEConfig{},
	}

	// CanServe should always return true (certmagic manages validity)
	assert.True(t, source.CanServe())
}

func TestACMETLSConfigSourceReload(t *testing.T) {
	source := &acmeTLSConfigSource{
		magicConfig:  certmagic.NewDefault(),
		gtACMEConfig: &ACMEConfig{},
	}

	// Reload should be a no-op (certmagic auto-refreshes)
	err := source.Reload()
	assert.NoError(t, err)
}

func TestACMETLSConfigSourceGetServerConfigNilBase(t *testing.T) {
	source := &acmeTLSConfigSource{
		magicConfig:  certmagic.NewDefault(),
		gtACMEConfig: &ACMEConfig{},
	}

	// GetServerConfig should work with nil base config
	config, err := source.GetServerConfig(nil)
	require.NoError(t, err)
	require.NotNil(t, config)

	tlsConfig := config.GetServerConfig()
	require.NotNil(t, tlsConfig)
	assert.NotNil(t, tlsConfig.GetCertificate, "GetCertificate should be set")
	assert.Contains(t, tlsConfig.NextProtos, acmez.ACMETLS1Protocol, "ACME-TLS protocol should be in NextProtos")
}

func TestACMETLSConfigSourceGetServerConfigWithBase(t *testing.T) {
	source := &acmeTLSConfigSource{
		magicConfig:  certmagic.NewDefault(),
		gtACMEConfig: &ACMEConfig{},
	}

	// GetServerConfig should preserve base config settings
	base := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2", "http/1.1"},
	}

	config, err := source.GetServerConfig(base)
	require.NoError(t, err)
	require.NotNil(t, config)

	tlsConfig := config.GetServerConfig()
	require.NotNil(t, tlsConfig)
	assert.Equal(t, uint16(tls.VersionTLS13), tlsConfig.MinVersion, "MinVersion should be preserved from base")
	assert.Contains(t, tlsConfig.NextProtos, "h2", "base NextProtos should be preserved")
	assert.Contains(t, tlsConfig.NextProtos, "http/1.1", "base NextProtos should be preserved")
	assert.Contains(t, tlsConfig.NextProtos, acmez.ACMETLS1Protocol, "ACME-TLS protocol should be added")
}

func TestACMETLSConfigGetServerConfig(t *testing.T) {
	magicConfig := certmagic.NewDefault()
	base := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	acmeConfig := &acmeTLSConfig{
		magicConfig: magicConfig,
		base:        base,
	}

	tlsConfig := acmeConfig.GetServerConfig()
	require.NotNil(t, tlsConfig)

	// Verify it's a clone (not the same pointer)
	assert.NotSame(t, base, tlsConfig, "GetServerConfig should return a clone")

	// Verify GetCertificate is set
	assert.NotNil(t, tlsConfig.GetCertificate)

	// Verify ACME-TLS protocol is added
	assert.Contains(t, tlsConfig.NextProtos, acmez.ACMETLS1Protocol)
}
