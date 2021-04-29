package certstore

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"github.com/github/fakeca"
)

var (
	root = fakeca.New(fakeca.IsCA, fakeca.Subject(pkix.Name{
		Organization: []string{"certstore"},
		CommonName:   "root",
	}))

	intermediate = root.Issue(fakeca.IsCA, fakeca.Subject(pkix.Name{
		Organization: []string{"certstore"},
		CommonName:   "intermediate",
	}))

	leafKeyRSA, _ = rsa.GenerateKey(rand.Reader, 2048)
	leafRSA       = intermediate.Issue(fakeca.PrivateKey(leafKeyRSA), fakeca.Subject(pkix.Name{
		Organization: []string{"certstore"},
		CommonName:   "leaf-rsa",
	}))

	leafKeyEC, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafEC       = intermediate.Issue(fakeca.PrivateKey(leafKeyEC), fakeca.Subject(pkix.Name{
		Organization: []string{"certstore"},
		CommonName:   "leaf-ec",
	}))
)

func init() {
	// delete any fixtures from a previous test run.
	clearFixtures()
}

func withStore(t *testing.T, cb func(Store)) {
	store, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()

	cb(store)
}

func withIdentity(t *testing.T, i *fakeca.Identity, cb func(Identity)) {
	withStore(t, func(store Store) {
		// Import an identity
		if err := store.Import(i.PFX("asdf"), "asdf"); err != nil {
			t.Fatal(err)
		}

		// Look for our imported identity
		idents, err := store.Identities()
		if err != nil {
			t.Fatal(err)
		}
		for _, ident := range idents {
			defer ident.Close()
		}

		var found Identity
		for _, ident := range idents {
			crt, err := ident.Certificate()
			if err != nil {
				t.Fatal(err)
			}

			if i.Certificate.Equal(crt) {
				if found != nil {
					t.Fatal("duplicate identity imported")
				}
				found = ident
			}
		}
		if found == nil {
			t.Fatal("imported identity not found")
		}

		// Clean up after ourselves.
		defer func(f Identity) {
			if err := f.Delete(); err != nil {
				t.Fatal(err)
			}
		}(found)

		cb(found)
	})
}

func clearFixtures() {
	store, err := Open()
	if err != nil {
		panic(err)
	}
	defer store.Close()

	idents, err := store.Identities()
	if err != nil {
		panic(err)
	}
	for _, ident := range idents {
		defer ident.Close()
	}

	for _, ident := range idents {
		crt, err := ident.Certificate()
		if err != nil {
			panic(err)
		}

		if isFixture(crt) {
			if err := ident.Delete(); err != nil {
				panic(err)
			}
		}
	}
}

func isFixture(crt *x509.Certificate) bool {
	return len(crt.Subject.Organization) == 1 && crt.Subject.Organization[0] == "certstore"
}
