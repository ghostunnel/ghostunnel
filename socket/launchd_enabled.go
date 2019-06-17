// +build darwin

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

package socket

/*
#include <stdlib.h>
int launch_activate_socket(const char *name, int **fds, size_t *cnt);
*/
import "C"

import (
	"fmt"
	"net"
	"os"
	"unsafe"
)

func launchdSocket(address string) (net.Listener, error) {
	c_name := C.CString(address)
	var c_fds *C.int
	c_cnt := C.size_t(0)

	err := C.launch_activate_socket(c_name, &c_fds, &c_cnt)
	if err != 0 {
		return nil, fmt.Errorf("couldn't activate launchd socket: %v", err)
	}

	length := int(c_cnt)
	if length != 1 {
		return nil, fmt.Errorf("expected exactly one socket to be configured in launchd for '%s', found %d", address, length)
	}
	ptr := unsafe.Pointer(c_fds)
	defer C.free(ptr)

	fds := (*[1]C.int)(ptr)
	file := os.NewFile(uintptr(fds[0]), "")

	return net.FileListener(file)
}
