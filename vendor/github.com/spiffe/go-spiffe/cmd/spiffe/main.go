package main

import (
	"log"
	"os"

	spiffe "github.com/spiffe/go-spiffe"
)

func main() {
	// Make log not print out time information
	log.SetFlags(0)

	if len(os.Args) <= 1 {
		log.Fatalf("\033[31mexpecting path [paths...] e.g\033[00m\n\tspiffe /var/lib/letsencrypt/spiffe.pem $HOME/Desktop/certs/cert.pem\033[00m\n")
	}

	seenPaths := make(map[string]bool)
	args := os.Args[1:]
	for i, path := range args {
		if _, seen := seenPaths[path]; seen {
			continue
		}

		seenPaths[path] = true
		f, err := os.Open(path)
		if err != nil {
			log.Printf("\n#%d: err=%v\n", i, err)
			continue
		}

		uris, err := spiffe.FGetURINamesFromPEM(f)
		_ = f.Close()

		if err != nil {
			log.Printf("\n#%d: parseErr=%v\n", i, err)
			continue
		}
		if len(uris) == 0 {
			log.Printf("\n#%d: no uris could be parsed\n", i)
			continue
		}

		log.Printf("Path:: #%d: %q\n", i+1, path)
		for j, uri := range uris {
			log.Printf("\tURI #%d: %q\n", j+1, uri)
		}
	}
}
