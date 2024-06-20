package certstore

import (
	"errors"
	"log"
)

// Implement this function, just to silence other compiler errors.
func openStore(logger *log.Logger) (Store, error) {
	return nil, errors.New("certstore only works on macOS and Windows")
}
