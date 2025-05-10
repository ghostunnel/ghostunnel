package find

import (
	"os/exec"
	"strings"
)

// Stat is exported out of golang convention, rather than necessity
type Stat struct {
	Name string
	Path string
}

// Repo uses git via the console to locate the top level directory
func Repo() (Stat, error) {
	path, err := rootPath()
	if err != nil {
		return Stat{
			"Unknown",
			"./",
		}, err
	}

	gitRepo, err := exec.Command("basename", path).Output()
	if err != nil {
		return Stat{}, err
	}

	return Stat{
		strings.TrimSpace(string(gitRepo)),
		path,
	}, nil
}

func rootPath() (string, error) {
	path, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(path)), nil
}
