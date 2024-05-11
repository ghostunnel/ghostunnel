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
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNoCertificate(t *testing.T) {
	cabundle, err := os.CreateTemp("", "ghostunnel-test")
	assert.Nil(t, err, "temp file error")
	defer os.Remove(cabundle.Name())

	_, err = cabundle.Write([]byte(testCertificate))
	assert.Nil(t, err, "temp file error")

	cert, err := NoCertificate(cabundle.Name())
	assert.Nil(t, err, "should read valid bundle")

	id := cert.GetIdentifier()
	assert.Equal(t, id, "", "no cert should have empty id")

	c, err := cert.GetCertificate(nil)
	assert.Nil(t, err, "should not error on GetCertificate")
	assert.NotNil(t, c, "should have non-nil server cert")

	c, err = cert.GetClientCertificate(nil)
	assert.Nil(t, err, "should not error on GetClientCertificate")
	assert.NotNil(t, c, "should have non-nil client cert")
}

func TestNoCertificateInvalid(t *testing.T) {
	cabundle, err := os.CreateTemp("", "ghostunnel-test")
	assert.Nil(t, err, "temp file error")
	defer os.Remove(cabundle.Name())

	_, err = cabundle.Write([]byte("invalid"))
	assert.Nil(t, err, "temp file error")

	_, err = NoCertificate(cabundle.Name())
	assert.NotNil(t, err, "should not read invalid bundle")
}
