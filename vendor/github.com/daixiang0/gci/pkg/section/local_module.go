package section

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/mod/modfile"

	"github.com/daixiang0/gci/pkg/parse"
	"github.com/daixiang0/gci/pkg/specificity"
)

const LocalModuleType = "localmodule"

type LocalModule struct {
	Paths []string
}

func (m *LocalModule) MatchSpecificity(spec *parse.GciImports) specificity.MatchSpecificity {
	for _, path := range m.Paths {
		if spec.Path == path || strings.HasPrefix(spec.Path, path+"/") {
			return specificity.LocalModule{}
		}
	}
	return specificity.MisMatch{}
}

func (m *LocalModule) String() string {
	return LocalModuleType
}

func (m *LocalModule) Type() string {
	return LocalModuleType
}

func (m *LocalModule) Configure(path string) error {
	if path != "" {
		m.Paths = []string{path}
		return nil
	}

	modPaths, err := m.findLocalModules()
	if err != nil {
		return fmt.Errorf("unable to find local modules: %v", err)
	}

	if len(modPaths) == 0 {
		return errors.New("could not find module path for `localModule` configuration")
	}

	m.Paths = modPaths
	return nil
}

func (m *LocalModule) findLocalModules() ([]string, error) {
	modsPath, err := m.getModulesPathFromWorkspace()
	switch {
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return nil, err
	case err == nil:
		return modsPath, nil
	}

	modPath, err := m.getModulePathFromRootMod()
	switch {
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return nil, err
	case err == nil:
		return []string{modPath}, nil
	}

	return nil, nil
}

func (m *LocalModule) getModulePathFromRootMod() (string, error) {
	modFilePath := "go.mod"
	if v, exists := os.LookupEnv("GOMOD"); exists {
		modFilePath = v
	}

	modPath, err := m.getModulePath(modFilePath)
	if err != nil {
		return "", err
	}

	return modPath, nil
}

func (m *LocalModule) getModulesPathFromWorkspace() ([]string, error) {
	rawWorkFile, err := os.ReadFile("go.work")
	if err != nil {
		return nil, fmt.Errorf("unable to read go.work file: %w", err)
	}

	workFile, err := modfile.ParseWork("go.work", rawWorkFile, nil)
	if err != nil {
		return nil, fmt.Errorf("unable to parse go.work file: %v", err)
	}

	var modsPath []string

	for _, use := range workFile.Use {
		modFilePath := filepath.Join(use.Path, "go.mod")
		modPath, err := m.getModulePath(modFilePath)
		if err != nil {
			return nil, fmt.Errorf("unable to get mod file %s defined go.work: %v", modFilePath, err)
		}

		modsPath = append(modsPath, modPath)
	}

	return m.removeRedundantModulePaths(modsPath), nil
}

func (m *LocalModule) getModulePath(modFilePath string) (string, error) {
	rawModFile, err := os.ReadFile(modFilePath)
	if err != nil {
		return "", fmt.Errorf("unable to read %s mod file: %w", modFilePath, err)
	}

	modulePath := modfile.ModulePath(rawModFile)
	if modulePath == "" {
		return "", fmt.Errorf("no module path found in %s", modFilePath)
	}

	return modulePath, nil
}

func (m *LocalModule) removeRedundantModulePaths(modPaths []string) []string {
	var result []string

	modPaths = slices.Clone(modPaths)
	slices.SortFunc(modPaths, func(a, b string) int {
		return len(a) - len(b)
	})

	for _, path := range modPaths {
		isRedundant := false

		for _, existing := range result {
			if path == existing || strings.HasPrefix(path, existing+"/") {
				isRedundant = true
				break
			}
		}

		if !isRedundant {
			result = append(result, path)
		}
	}

	return result
}
