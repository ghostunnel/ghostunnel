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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTimeoutError(t *testing.T) {
	err := timeoutError{}
	assert.False(t, err.Error() == "", "Timeout error should have message")
	assert.True(t, err.Timeout(), "Timeout error should have Timeout() == true")
	assert.True(t, err.Temporary(), "Timeout error should have Temporary() == true")
}
