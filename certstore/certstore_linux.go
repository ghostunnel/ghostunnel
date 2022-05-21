package certstore

import "errors"

// Implement this function, just to silence other compiler errors.
func openStore() (Store, error) {
	return nil, errors.New("certstore only works on macOS and Windows")
}
