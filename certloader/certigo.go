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
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"os"

	certigo "github.com/square/certigo/lib"
)

func readPEM(path, password, format string) ([]*pem.Block, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	var pemBlocks []*pem.Block
	err = certigo.ReadAsPEMFromFiles(
		[]*os.File{file},
		format,
		func(prompt string) string { return password },
		func(block *pem.Block) { pemBlocks = append(pemBlocks, block) })
	if err != nil {
		return nil, fmt.Errorf("error reading file '%s': %s", path, err)
	}
	if len(pemBlocks) == 0 {
		return nil, fmt.Errorf("error reading file '%s', no certificates found", path)
	}

	return pemBlocks, nil
}

func readX509(path string) ([]*x509.Certificate, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	errs := []error{}
	out := []*x509.Certificate{}

	err = certigo.ReadAsX509FromFiles(
		[]*os.File{file}, "PEM", nil,
		func(cert *x509.Certificate, err error) {
			if err != nil {
				errs = append(errs, err)
				return
			}
			out = append(out, cert)
		})
	if err != nil || len(errs) > 0 {
		return nil, fmt.Errorf("error reading file '%s'", path)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no certificates found in file '%s'", path)
	}
	return out, nil
}

func LoadTrustStore(caBundlePath string) (*x509.CertPool, error) {
	if caBundlePath == "" {
		return x509.SystemCertPool()
	}

	caBundleBytes, err := ioutil.ReadFile(caBundlePath)
	if err != nil {
		return nil, err
	}

	bundle := x509.NewCertPool()
	ok := bundle.AppendCertsFromPEM(caBundleBytes)
	if !ok {
		return nil, errors.New("unable to read certificates from CA bundle")
	}

	return bundle, nil
}
