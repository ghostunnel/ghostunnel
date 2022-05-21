# fakeca [![PkgGoDev](https://pkg.go.dev/badge/github.com/github/fakeca?tab=doc)](https://pkg.go.dev/github.com/github/fakeca?tab=doc) [![Report card](https://goreportcard.com/badge/github.com/github/fakeca)](https://goreportcard.com/report/github.com/github/fakeca) [![Actions CI](https://github.com/github/fakeca/workflows/Test/badge.svg)](https://github.com/github/fakeca/actions?query=workflow%3ATest)

This is a package for creating fake certificate authorities for test fixtures.

## Example

```go
package main

import (
	"crypto/x509/pkix"

	"github.com/github/fakeca"
)

func main() {
	// Change defaults for cert subjects.
	fakeca.DefaultProvince = []string{"CO"}
	fakeca.DefaultLocality = []string{"Denver"}

	// Create a root CA.
	root := fakeca.New(fakeca.IsCA, fakeca.Subject(pkix.Name{
		CommonName: "root.myorg.com",
	}))

	// Create an intermediate CA under the root.
	intermediate := root.Issue(fakeca.IsCA, fakeca.Subject(pkix.Name{
		CommonName: "intermediate.myorg.com",
	}))

	// Create a leaf certificate under the intermediate.
	leaf := intermediate.Issue(fakeca.Subject(pkix.Name{
		CommonName: "leaf.myorg.com",
	}))

	// Get PFX (PKCS12) blob containing certificate and encrypted private key.
	leafPFX := leaf.PFX("pa55w0rd")

	// Get an *x509.CertPool containing certificate chain from CA to leaf for use
	// with Go's TLS libraries.
	leafPool := leaf.ChainPool()
}

```
