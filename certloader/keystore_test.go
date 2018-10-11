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
	"crypto/tls"
	"io/ioutil"
	"os"
	"runtime"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

const testCombinedCertificateAndKey = `
-----BEGIN CERTIFICATE-----
MIIC6DCCAdCgAwIBAgIJAK56Q73Kb2tfMA0GCSqGSIb3DQEBCwUAMA8xDTALBgNV
BAMMBHJvb3QwHhcNMTgwNTI0MTg0MjAwWhcNMzIwMTMxMTg0MjAwWjARMQ8wDQYD
VQQDDAZzZXJ2ZXIwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/bkEe
7lxh6H/XkGK/00GR+XNZHRgYagpbbATNnEt7zXJ3Ot6Fu2SJvUpjRhfJ2GCakjLq
2+YFlH8heN3DEYFFxuLOtnHrNzZW8TzyWlV9LWK+jO/YjEoH6wGwvZ/XiDwYTg/B
yzUphvuUdYMrWWdvV2PcLTspfjSNuUM8QjhKHchUJzddqaEWsTUM7tWIPpRZiDQH
BNmoEKklBrgwKyQZe/IJ/VL3Vntbdpp1eycHk6uh7hAWZ897Hidv8YwOP8Fusr0c
AMj2vEzS2HHED16ha8TAN+5lycAPPJ9b8bOeSv5K90w73Szjxf8fHkmgFmdI4Q3e
N9S2bVpUx3f+lNMvAgMBAAGjRTBDMBMGA1UdJQQMMAoGCCsGAQUFBwMBMCwGA1Ud
EQQlMCOHBH8AAAGHEAAAAAAAAAAAAAAAAAAAAAGCCWxvY2FsaG9zdDANBgkqhkiG
9w0BAQsFAAOCAQEAZq3KX0T8BvKwTTtCrzV7wkdruyfUFxNER2GAzynmm9rIHcTE
UiMoRZk/s5CcqJZFNS1N9ObqCXzNDzQreBOVcPk/YnCwiVviuzDfZxPPchrB3prp
1B9b813dhUknjy2nU40Bi/djx8Fp8H59EpGM+OWFt368zxb7NWxK8PFPKJDyHvbA
QDU7QP3y99EoYugQKPmjiav6gzDFegYilBt3bBKUwRqqMOv08wia4oycaCqZW+ay
qkfXo0Io2kEp2nkbQfPhAZASq1Il7x6ytr6NyIBCxsKvgPYF2YdDqfs2a/cwxU7A
zIo7sqovg5zVX3IUCJNbnC5g6wGYRoCUXzeExg==
-----END CERTIFICATE-----
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAv25BHu5cYeh/15Biv9NBkflzWR0YGGoKW2wEzZxLe81ydzre
hbtkib1KY0YXydhgmpIy6tvmBZR/IXjdwxGBRcbizrZx6zc2VvE88lpVfS1ivozv
2IxKB+sBsL2f14g8GE4Pwcs1KYb7lHWDK1lnb1dj3C07KX40jblDPEI4Sh3IVCc3
XamhFrE1DO7ViD6UWYg0BwTZqBCpJQa4MCskGXvyCf1S91Z7W3aadXsnB5Oroe4Q
FmfPex4nb/GMDj/BbrK9HADI9rxM0thxxA9eoWvEwDfuZcnADzyfW/Gznkr+SvdM
O90s48X/Hx5JoBZnSOEN3jfUtm1aVMd3/pTTLwIDAQABAoIBAAFkrwqnl3qK86tA
/McCpZ6HX0SNxqge1XZ24c4RTidXhnbBse7tPz0VaJ4yW2f3sDRPzhkRgqoVu5sl
ww9xaCx21x3EDC43F6koVlY5PBgOJYLXicNcugk2t6tupeQutKlEoC676OYlel1J
QawmGW+hBjQLDDwwE/fYGlos7TX04EzAfDDORZ5WQBnSFlGDXFNIV+pTXAwy5KHr
OQsbJEKoqF8KcXSS4yDZ0ZEKFJrC6pZUXAkDhUZd201UQtMIgOReGyBDmmGZZkNe
t1uBiZqwidYvMHFPT56S3R5nhL+4zeQ4SjvGluXei3c+uCkTtT7l7AKs84OC+DGg
NZDU4OECgYEA80nmBy0XmRR6CA6yg9Vy30s0Z/jIEk01USQmnHMOvIwOevi5TKiS
CgDZiHzM6b9PBTuux4/FA1vRIXJnSsMjamHIQbDHdjEi5ZuYF0SSGydEtNhCx/FF
eW5ZKKLBb/M+sfu06CN0Tts6OyKkQuWLSZ8RdjcYxwgrM1gDNktffNECgYEAyW67
DBNXTfzrRJG5Su+dGiULxlRlXd1Nv69gZaAH0FBKBw/BV+AGnYC/MbZSHsalmnXW
+FvwdlARoP5PrHkXA2V4cHyLFxdLHuMAokt8qu+cUHUXssyqay9jXEgkX/vKfjVm
pHZszJz4iIbXuqDaX1nBJqCznUO8I3KfH1SDT/8CgYBD6lI7mJvo0O2MCEZPRSvP
J9hWWf3IFiOXJiddL0Vi3xo/u+VGgBxcjIYtcuFlM1Gk3VdaQEk4Oc50rtIk7bqa
PPfBVs8nsGnUfQ4FGNBMojas4V4rILBLSMG89UpYrSfIWcLTtuoGBW8JCQ+f2SJ8
B9rBDHpvPVmJ+LzU0E+0sQKBgQCSAcFzL1HJJdsjCL3Wo3isys2OJP6U2yTQHL8y
6py/UnNWSwVKPQiOghQUZKOBy1ueamw3+eyC1ebxW2VFD0CvJY33e08WnbvF16VN
/omPHb+gUj+rSs78gozzBxfWuxw7/1k3POAAMIe17ofQr2eaVeS7qyCGjeKBj0Pn
4cqM4QKBgCxn5c5kskJcuSEKrCvuuSRYBbYY7FxBH2ksnFECl9VnsDl8pYMaTf0E
9kNvJK3/1WjJOaXy4cEPx/BMbHcrh01K/IM3Te2VCrp7tkA5H1V2YGQD4/aqmajA
plW93GyQzhwY+Cc1Of2ktdBwOHNn1xWyl3lgjAaW+da1nEhq6Anc
-----END RSA PRIVATE KEY-----`

func TestCertificateFromPEMFilesValid(t *testing.T) {
	file, err := ioutil.TempFile("", "ghostunnel-test")
	assert.Nil(t, err, "temp file error")
	defer os.Remove(file.Name())

	_, err = file.Write([]byte(testCombinedCertificateAndKey))
	assert.Nil(t, err, "temp file error")

	cert, err := CertificateFromPEMFiles(file.Name(), file.Name())
	assert.Nil(t, err, "should read PEM file with certificate & private key")

	c0, err := cert.GetCertificate(nil)
	assert.Nil(t, err, "should have a valid tls.Certificate on GetCertificate call")

	c1, err := cert.GetClientCertificate(nil)
	assert.Nil(t, err, "should have a valid tls.Certificate on GetCertificate call")

	assert.Equal(t, c0.Leaf.Subject.CommonName, "server", "should have the right cert")
	assert.Equal(t, c1.Leaf.Subject.CommonName, "server", "should have the right cert")
	assert.Nil(t, cert.Reload(), "should be able to reload")

	// Remove file & test reload failure
	if runtime.GOOS == "windows" {
		// Reloading not supported on Windows
		return
	}

	os.Remove(file.Name())
	assert.NotNil(t, cert.Reload(), "should not be able to reload")
}

func TestCertificateFromPEMFilesInvalid(t *testing.T) {
	file, err := ioutil.TempFile("", "ghostunnel-test")
	assert.Nil(t, err, "temp file error")
	defer os.Remove(file.Name())

	_, err = file.Write([]byte("invalid"))
	assert.Nil(t, err, "temp file error")

	cert, err := CertificateFromPEMFiles(file.Name(), file.Name())
	assert.Nil(t, cert, "should not return certificate on error")
	assert.NotNil(t, err, "should read PEM file with certificate & private key")
}

func TestGetCachedCertificateKeystore(t *testing.T) {
	tlscert := &tls.Certificate{}
	kscert := &keystoreCertificate{
		cached: unsafe.Pointer(tlscert),
	}

	c, err := kscert.GetCertificate(nil)
	assert.Nil(t, err, "should be able to read certificate")
	assert.Equal(t, tlscert, c)

	c, err = kscert.GetClientCertificate(nil)
	assert.Nil(t, err, "should be able to read certificate")
	assert.Equal(t, tlscert, c)
}
