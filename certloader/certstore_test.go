/*-
 * Copyright 2018 Square Inc.
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
	"log"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInvalidKeychainIdentity(t *testing.T) {
	logger := log.New(os.Stdout, "", log.LstdFlags|log.Lmicroseconds)
	ident, err := CertificateFromKeychainIdentity("!", "!", "!", false, logger)
	if ident != nil {
		t.Logf("loaded invalid identity: %v", ident)
	}
	assert.NotNil(t, err, "should not load invalid identity")
}

func TestSupportsKeychain(t *testing.T) {
	// Just verify this function doesn't panic and returns a bool
	result := SupportsKeychain()
	_ = result
}
