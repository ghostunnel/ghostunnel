/*-
 * Copyright 2022
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
)

type spiffeLogger struct {
	log *log.Logger
}

func (l spiffeLogger) Debugf(format string, args ...interface{}) {
	l.log.Printf("spiffe/debug: "+format, args...)
}

func (l spiffeLogger) Infof(format string, args ...interface{}) {
	l.log.Printf("spiffe/info: "+format, args...)
}

func (l spiffeLogger) Warnf(format string, args ...interface{}) {
	l.log.Printf("spiffe/warn: "+format, args...)
}

func (l spiffeLogger) Errorf(format string, args ...interface{}) {
	l.log.Printf("spiffe/error: "+format, args...)
}
