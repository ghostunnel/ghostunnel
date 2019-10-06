package spiffe

import (
	"crypto/x509"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

type idType int

const (
	anyId idType = iota
	trustDomainId
	workloadId
)

// ValidateID validates the SPIFFE ID according to the SPIFFE
// specification. The validation mode controls the type of validation.
func ValidateID(spiffeID string, mode ValidationMode) error {
	_, err := ParseID(spiffeID, mode)
	return err
}

// ValidateURI validates the SPIFFE ID according to the SPIFFE
// specification, namely:
// - spiffe id is not empty
// - spiffe id is a valid url
// - scheme is 'spiffe'
// - user info is not allowed
// - host is not empty
// - port is not allowed
// - query values are not allowed
// - fragment is not allowed
// In addition, the validation mode is used to control what kind of SPIFFE ID
// is expected.
// For more information:
// [https://github.com/spiffe/spiffe/blob/master/standards/SPIFFE-ID.md]
func ValidateURI(id *url.URL, mode ValidationMode) error {
	options := mode.validationOptions()

	validationError := func(format string, args ...interface{}) error {
		var kind string
		switch options.idType {
		case trustDomainId:
			kind = "trust domain "
		case workloadId:
			kind = "workload "
		}
		return fmt.Errorf("invalid %sSPIFFE ID %q: "+format,
			append([]interface{}{kind, id.String()}, args...)...)
	}

	if id == nil || *id == (url.URL{}) {
		return validationError("SPIFFE ID is empty")
	}

	// General validation
	switch {
	case strings.ToLower(id.Scheme) != "spiffe":
		return validationError("invalid scheme")
	case id.User != nil:
		return validationError("user info is not allowed")
	case id.Host == "":
		return validationError("trust domain is empty")
	case id.Port() != "":
		return validationError("port is not allowed")
	case id.Fragment != "":
		return validationError("fragment is not allowed")
	case id.RawQuery != "":
		return validationError("query is not allowed")
	}

	// trust domain validation
	if options.trustDomainRequired {
		if options.trustDomain == "" {
			return errors.New("trust domain to validate against cannot be empty")
		}
		if id.Host != options.trustDomain {
			return fmt.Errorf("%q does not belong to trust domain %q", id, options.trustDomain)
		}
	}

	// id type validation
	switch options.idType {
	case anyId:
	case trustDomainId:
		if id.Path != "" {
			return validationError("path is not empty")
		}
	case workloadId:
		if id.Path == "" {
			return validationError("path is empty")
		}
	default:
		return validationError("internal error: unhandled id type %v", options.idType)
	}

	return nil
}

// ParseID parses the SPIFFE ID and makes sure it is valid according to
// the specified validation mode.
func ParseID(spiffeID string, mode ValidationMode) (*url.URL, error) {
	u, err := url.Parse(spiffeID)
	if err != nil {
		return nil, fmt.Errorf("invalid SPIFFE ID: %v", err)
	}

	if err := ValidateURI(u, mode); err != nil {
		return nil, err
	}

	return normalizeURI(u), nil
}

// ValidationMode is used to control extra validation of the SPIFFE ID
// beyond the syntax checks done during parsing/validation.
type ValidationMode interface {
	validationOptions() validationOptions
}

type validationOptions struct {
	trustDomain         string
	trustDomainRequired bool
	idType              idType
}

type validationMode struct {
	options validationOptions
}

func (m validationMode) validationOptions() validationOptions {
	return m.options
}

// Allows any well-formed SPIFFE ID
func AllowAny() ValidationMode {
	return validationMode{}
}

// Allows a well-formed SPIFFE ID for the specific trust domain (e.g. spiffe://domain.test/workload)
func AllowTrustDomain(trustDomain string) ValidationMode {
	return validationMode{
		options: validationOptions{
			trustDomain:         trustDomain,
			trustDomainRequired: true,
			idType:              trustDomainId,
		},
	}
}

// Allows a well-formed SPIFFE ID for a workload belonging to a specific trust domain (e.g. spiffe://domain.test/workload)
func AllowTrustDomainWorkload(trustDomain string) ValidationMode {
	return validationMode{
		options: validationOptions{
			trustDomain:         trustDomain,
			trustDomainRequired: true,
			idType:              workloadId,
		},
	}
}

// Allows a well-formed SPIFFE ID for any trust domain (e.g. spiffe://domain.test).
func AllowAnyTrustDomain() ValidationMode {
	return validationMode{
		options: validationOptions{
			idType: trustDomainId,
		},
	}
}

// Allows a well-formed SPIFFE ID for a workload belonging to any trust domain (e.g. spiffe://domain.test).
func AllowAnyTrustDomainWorkload() ValidationMode {
	return validationMode{
		options: validationOptions{
			idType: workloadId,
		},
	}
}

// NormalizeID normalizes the SPIFFE ID so it can be directly compared for
// equality. Specifically, it lower cases the scheme and host portions of the
// URI.
func NormalizeID(id string, mode ValidationMode) (string, error) {
	u, err := ParseID(id, mode)
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

// NormalizeURI normalizes the SPIFFE ID URI so it can be directly compared for
// equality. Specifically, it lower cases the scheme and host portions of the
// URI.
func NormalizeURI(u *url.URL, mode ValidationMode) (*url.URL, error) {
	if err := ValidateURI(u, mode); err != nil {
		return nil, err
	}
	return normalizeURI(u), nil
}

func normalizeURI(u *url.URL) *url.URL {
	c := *u
	c.Scheme = strings.ToLower(c.Scheme)
	// SPIFFE ID's can't contain ports so don't bother handling that here.
	c.Host = strings.ToLower(u.Hostname())
	return &c
}

// TrustDomainID creates a trust domain SPIFFE ID given a trust domain.
func TrustDomainID(trustDomain string) string {
	return TrustDomainURI(trustDomain).String()
}

// TrustDomainURI creates a trust domain SPIFFE URI given a trust domain.
func TrustDomainURI(trustDomain string) *url.URL {
	return &url.URL{
		Scheme: "spiffe",
		Host:   trustDomain,
	}
}

// getIDsFromCertificate extracts the SPIFFE ID and Trust Domain ID from the
// URI SAN of the provided certificate. If the certificate has no URI SAN or
// the SPIFFE ID is malformed, it will return an error.
func getIDsFromCertificate(peer *x509.Certificate) (string, string, error) {
	switch {
	case len(peer.URIs) == 0:
		return "", "", errors.New("peer certificate contains no URI SAN")
	case len(peer.URIs) > 1:
		return "", "", errors.New("peer certificate contains more than one URI SAN")
	}

	id := peer.URIs[0]

	if err := ValidateURI(id, AllowAny()); err != nil {
		return "", "", err
	}

	return id.String(), TrustDomainID(id.Host), nil
}
