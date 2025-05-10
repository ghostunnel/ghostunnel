//go:build mage

// Self-contained go-project magefile.

//nolint:deadcode,gochecknoglobals,gochecknoinits,wrapcheck,varnamelen,gomnd,forcetypeassert,forbidigo,funlen,gocognit,cyclop,nolintlint
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/bits"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	archiver "github.com/mholt/archiver"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
	"github.com/magefile/mage/target"

	"github.com/integralist/go-findroot/find"
	"github.com/pkg/errors"
)

var (
	errAutogenMultipleScriptSections       = errors.New("found multiple managed script sections")
	errAutogenUnknownPreCommitScriptFormat = errors.New("unknown pre-commit script format")
	errPlatformNotSupported                = errors.New("current platform is not supported")
	errParallelBuildFailed                 = errors.New("parallel build failed")
	errLintBisect                          = errors.New("error during lint bisect")
)

var curDir = func() string {
	name, _ := os.Getwd()
	return name
}()

const (
	constCoverageDir = ".coverage"
	constToolBinDir  = ".bin"
	constGitHookDir  = "githooks"
	constBinDir      = "bin"
	constReleaseDir  = "release"
	constCmdDir      = "cmd"
	constCoverFile   = ".cover.out"
)

const (
	constManagedScriptSectionHead = "## ++ BUILD SYSTEM MANAGED - DO NOT EDIT ++ ##"
	constManagedScriptSectionFoot = "## -- BUILD SYSTEM MANAGED - DO NOT EDIT -- ##"
)

// normalizePath turns a path into an absolute path and removes symlinks.
func normalizePath(name string) string {
	absPath := must(filepath.Abs(name))
	return absPath
}

// binRootName is set to the name of the directory by default.
var binRootName = func() string {
	return must(find.Repo()).Path
}()

// dockerImageName is set to the name of the directory by default.
var dockerImageName = func() string {
	return binRootName
}()

var coverageDir = normalizePath(path.Join(curDir, constCoverageDir))
var toolsBinDir = normalizePath(path.Join(curDir, constToolBinDir))
var gitHookDir = normalizePath(path.Join(curDir, constGitHookDir))
var binDir = normalizePath(path.Join(curDir, constBinDir))
var releaseDir = normalizePath(path.Join(curDir, constReleaseDir))
var cmdDir = normalizePath(path.Join(curDir, constCmdDir))

var outputDirs = []string{binDir, releaseDir, coverageDir}

//nolint:unused,varcheck
var containerName = func() string {
	if name := os.Getenv("CONTAINER_NAME"); name != "" {
		return name
	}
	return dockerImageName
}()

type Platform struct {
	OS        string
	Arch      string
	BinSuffix string
}

func (p *Platform) String() string {
	return fmt.Sprintf("%s-%s", p.OS, p.Arch)
}

func (p *Platform) PlatformDir() string {
	platformDir := path.Join(binDir, fmt.Sprintf("%s_%s_%s", productName, versionShort, p.String()))
	return platformDir
}

func (p *Platform) PlatformBin(cmd string) string {
	platformBin := fmt.Sprintf("%s%s", cmd, p.BinSuffix)
	return path.Join(p.PlatformDir(), platformBin)
}

func (p *Platform) ArchiveDir() string {
	return fmt.Sprintf("%s_%s_%s", productName, versionShort, p.String())
}

func (p *Platform) ReleaseBase() string {
	return path.Join(releaseDir, fmt.Sprintf("%s_%s_%s", productName, versionShort, p.String()))
}

// platforms is the list of platforms we build for.
var platforms []Platform = []Platform{
	{"linux", "arm", ""},
	{"linux", "arm64", ""},
	{"linux", "amd64", ""},
	{"linux", "386", ""},
	{"darwin", "amd64", ""},
	{"darwin", "arm64", ""},
	{"windows", "amd64", ".exe"},
	{"windows", "386", ".exe"},
	{"freebsd", "amd64", ""},
}

// platformsLookup is the lookup map of the above list by <OS>/<Arch>.
var platformsLookup map[string]Platform = func() map[string]Platform {
	ret := make(map[string]Platform, len(platforms))
	for _, platform := range platforms {
		ret[platform.String()] = platform
	}
	return ret
}()

// productName can be overridden by environ product name.
var productName = func() string {
	if name := os.Getenv("PRODUCT_NAME"); name != "" {
		return name
	}
	name, _ := os.Getwd()
	return path.Base(name)
}()

// Source files.
var goSrc []string
var goDirs []string
var goPkgs []string
var goCmds []string

var version = func() string {
	if v := os.Getenv("VERSION"); v != "" {
		return v
	}
	out, _ := sh.Output("git", "describe", "--dirty")

	if out == "" {
		return "v0.0.0"
	}

	return out
}()

var versionShort = func() string {
	if v := os.Getenv("VERSION_SHORT"); v != "" {
		return v
	}
	out, _ := sh.Output("git", "describe", "--abbrev=0")

	if out == "" {
		return "v0.0.0"
	}

	return out
}()

var concurrency = func() int {
	if v := os.Getenv("CONCURRENCY"); v != "" {
		pv, err := strconv.ParseUint(v, 10, bits.UintSize)
		if err != nil {
			panic(err)
		}

		// Ensure we always have at least 1 process
		if int(pv) < 1 {
			return 1
		}

		return int(pv)
	}
	return runtime.NumCPU()
}()

var linterDeadline = func() time.Duration {
	if v := os.Getenv("LINTER_DEADLINE"); v != "" {
		d, _ := time.ParseDuration(v)
		if d != 0 {
			return d
		}
	}
	return time.Minute
}()

func Log(args ...interface{}) {
	if mg.Verbose() {
		fmt.Println(args...)
	}
}

var concurrencyQueue chan struct{}
var concurrencyWg *sync.WaitGroup

// concurrentRun calls a function while respecting concurrency limits, and
// returns a promise-like function which will resolve to the value.
func concurrentRun[T any](fn func() T) func() T {
	concurrencyQueue <- struct{}{} // Acquire a job
	concurrencyWg.Add(1)           // Ensure we can wait

	rCh := make(chan T)
	go func() {
		rCh <- fn()
		<-concurrencyQueue   // Release a job
		concurrencyWg.Done() // Mark job finished
	}()

	return func() T {
		return <-rCh
	}
}

// waitResults accepts a map of operations and waits for them all to complete.
func waitResults(m map[string]func() error) func() error {
	type dispatch struct {
		k string
		v error
	}

	resultQueue := make(chan dispatch, len(m))
	for k, fn := range m {
		go func(k string, fn func() error) {
			resultQueue <- dispatch{
				k: k,
				v: fn(),
			}
		}(k, fn)
	}

	return func() error {
		buildError := false

		for i := 0; i < len(m); i++ {
			result := <-resultQueue
			if result.v != nil {
				buildError = true
				fmt.Printf("Error: %s: %s\n", result.k, result.v)
			}
		}

		if buildError {
			return errParallelBuildFailed
		}
		return nil
	}
}

func init() {
	// Initialize concurrency queue
	concurrencyQueue = make(chan struct{}, concurrency)
	concurrencyWg = &sync.WaitGroup{}

	// Set environment
	os.Setenv("PATH", fmt.Sprintf("%s:%s", toolsBinDir, os.Getenv("PATH")))
	os.Setenv("GOBIN", toolsBinDir)
	Log("Build PATH: ", os.Getenv("PATH"))
	Log("Concurrency:", concurrency)
	goSrc = func() []string {
		results := new([]string)
		err := filepath.Walk(".", func(relpath string, info os.FileInfo, _ error) error {
			// Ensure absolute path so globs work
			path, err := filepath.Abs(relpath)
			if err != nil {
				panic(err)
			}

			// Look for files
			if info.IsDir() {
				return nil
			}

			// Exclusions
			for _, exclusion := range []string{toolsBinDir, binDir, releaseDir, coverageDir} {
				if strings.HasPrefix(path, exclusion) {
					if info.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
			}

			if strings.Contains(path, "/vendor/") {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			if strings.Contains(path, ".git") {
				if info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			if !strings.HasSuffix(path, ".go") {
				return nil
			}

			*results = append(*results, path)
			return nil
		})
		if err != nil {
			panic(err)
		}
		return *results
	}()
	goDirs = func() []string {
		resultMap := make(map[string]struct{})
		for _, path := range goSrc {
			absDir, err := filepath.Abs(filepath.Dir(path))
			if err != nil {
				panic(err)
			}
			resultMap[absDir] = struct{}{}
		}
		results := []string{}
		for k := range resultMap {
			results = append(results, k)
		}
		return results
	}()
	goPkgs = func() []string {
		results := []string{}
		out, err := sh.Output("go", "list", "./...")
		if err != nil {
			panic(err)
		}
		for _, line := range strings.Split(out, "\n") {
			if !strings.Contains(line, "/vendor/") {
				results = append(results, line)
			}
		}
		return results
	}()
	goCmds = func() []string {
		results := []string{}

		finfos, err := ioutil.ReadDir(cmdDir)
		if err != nil {
			return results
		}
		for _, finfo := range finfos {
			results = append(results, finfo.Name())
		}
		return results
	}()

	// Ensure output dirs exist
	for _, dir := range outputDirs {
		panicOnError(os.MkdirAll(dir, os.FileMode(0777)))
	}
}

// must consumes an error from a function.
func must[T any](result T, err error) T {
	if err != nil {
		panic(err)
	}
	return result
}

func panicOnError(err error) {
	if err != nil {
		panic(err)
	}
}

// concurrencyLimitedBuild executes a certain number of commands limited by concurrency.
func concurrencyLimitedBuild(buildCmds ...interface{}) error {
	resultsCh := make(chan error, len(buildCmds))
	concurrencyControl := make(chan struct{}, concurrency)
	for _, buildCmd := range buildCmds {
		go func(buildCmd interface{}) {
			concurrencyControl <- struct{}{}
			resultsCh <- buildCmd.(func() error)()
			<-concurrencyControl
		}(buildCmd)
	}
	// Doesn't work at the moment
	//	mg.Deps(buildCmds...)
	results := []error{}
	var resultErr error = nil
	for len(results) < len(buildCmds) {
		err := <-resultsCh
		results = append(results, err)
		if err != nil {
			fmt.Println(err)
			resultErr = errors.Wrap(errParallelBuildFailed, "concurrencyLimitedBuild command failure")
		}
		fmt.Printf("Finished %v of %v\n", len(results), len(buildCmds))
	}

	return resultErr
}

// Tools builds build tools of the project and is depended on by all other build targets.
func Tools() (err error) {
	// Catch panics and convert to errors
	defer func() {
		if perr := recover(); perr != nil {
			err = perr.(error)
		}
	}()

	toolBuild := func(toolType string, tools ...string) error {
		toolTargets := []interface{}{}
		for _, toolImport := range tools {
			localToolImport := toolImport
			f := func() error { return sh.Run("go", "install", "-v", localToolImport) }
			toolTargets = append(toolTargets, f)
		}

		Log("Build", toolType, "tools")
		if berr := concurrencyLimitedBuild(toolTargets...); berr != nil {
			return berr
		}
		return nil
	}

	// golangci-lint don't want to support if it's not a binary release, so
	// don't go-install.

	if berr := toolBuild("static", "github.com/golangci/golangci-lint/cmd/golangci-lint@v1.48.0", "github.com/wadey/gocovmerge@latest"); berr != nil {
		return berr
	}

	return nil
}

func lintArgs(args ...string) []string {
	returnedArgs := []string{"-j", fmt.Sprintf("%v", concurrency), fmt.Sprintf(
		"--deadline=%s", linterDeadline.String())}
	returnedArgs = append(returnedArgs, args...)
	return returnedArgs
}

// Lint runs gometalinter for code quality. CI will run this before accepting PRs.
func Lint() error {
	mg.Deps(Tools)
	extraArgs := lintArgs("run")
	extraArgs = append(extraArgs, goDirs...)
	return sh.RunV("golangci-lint", extraArgs...)
}

// LintBisect runs the linters one directory at a time.
// It is useful for finding problems where golangci-lint won't compile and
// doesn't emit an error message.
func LintBisect() error {
	errs := []error{}
	for _, goDir := range goDirs {
		fmt.Println("Linting:", goDir)
		err := sh.RunV("golangci-lint", lintArgs("run", goDir)...)
		if err != nil {
			fmt.Println("LINT ERROR IN:", goDir)
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errLintBisect
	}
	return nil
}

// listLinters gets the golangci-lint config
func listLinters() ([]string, error) {
	cmd := exec.Command("golangci-lint", "linters")
	output, err := cmd.Output()
	if err != nil {
		return []string{}, errors.Wrap(err, "golangci-lint linters failed to run")
	}
	bio := bufio.NewReader(bytes.NewBuffer(output))
	linters := []string{}
	for {
		line, _ := bio.ReadString('\n')
		line = strings.Trim(line, " \n\t")
		if line == "" {
			continue
		}
		if line == "Enabled by your configuration linters:" {
			continue
		}
		if line == "Disabled by your configuration linters:" {
			// Done
			break
		}
		linter := strings.Split(line, ":")[0]
		linter = strings.Split(linter, "(")[0]
		linter = strings.Trim(linter, " \n\t")
		linters = append(linters, linter)
	}
	return linters, nil
}

// LintersBisect runs all linters in golangci-lint one at a time.
// It is useful find broken linters.
func LintersBisect() error {
	linters, err := listLinters()
	if err != nil {
		return errors.Wrap(err, "LintersBisect: listLinters failed")
	}
	errs := map[string]error{}

	// Annoyingly, we have to override .golangci.yml to allow us to pick linters
	// one by one.
	golangCi := make(map[string]interface{})
	_ = yaml.Unmarshal(must(ioutil.ReadFile(".golangci.yml")), golangCi)
	delete(golangCi, "linters")
	tempConfig, err := ioutil.TempFile("", ".golangci.*.yml")
	if err != nil {
		return errors.Wrap(err, "LintersBisect: TempFile failed")
	}
	_ = must(tempConfig.Write(must(yaml.Marshal(golangCi))))
	defer os.Remove(tempConfig.Name())

	for _, linter := range linters {
		extraArgs := lintArgs("run",
			fmt.Sprintf("--config=%s", tempConfig.Name()),
			"--disable-all",
			fmt.Sprintf("--enable=%s", linter))
		extraArgs = append(extraArgs, goDirs...)
		err := sh.RunV("golangci-lint", extraArgs...)
		if err != nil {
			errs[linter] = err
		}
	}

	if len(errs) > 0 {
		for linter := range errs {
			fmt.Println("FAILED LINTER:", linter)
		}

		return errLintBisect
	}
	return nil
}

// fmt runs golangci-lint with the formatter options.
func formattingLinter(doFixes bool) error {
	mg.Deps(Tools)
	args := []string{"run", "--no-config", "--disable-all", "--enable=gofmt", "--enable=goimports", "--enable=godot"}
	if doFixes {
		args = append(args, "--fix")
	}
	return sh.RunV("golangci-lint", args...)
}

// Style checks formatting of the file. CI will run this before acceptiing PRs.
func Style() error {
	return formattingLinter(false)
}

// Fmt automatically formats all source code files.
func Fmt() error {
	return formattingLinter(true)
}

func listCoverageFiles() ([]string, error) {
	result := []string{}
	finfos, derr := ioutil.ReadDir(coverageDir)
	if derr != nil {
		return result, derr
	}
	for _, finfo := range finfos {
		result = append(result, path.Join(coverageDir, finfo.Name()))
	}
	return result, nil
}

// Test run test suite.
func Test() error {
	mg.Deps(Tools)

	// Ensure coverage directory exists
	if err := os.MkdirAll(coverageDir, os.FileMode(0777)); err != nil {
		return err
	}

	// Clean up coverage directory
	coverFiles, derr := listCoverageFiles()
	if derr != nil {
		return derr
	}
	for _, coverFile := range coverFiles {
		if err := sh.Rm(coverFile); err != nil {
			return err
		}
	}

	// Run tests
	//coverProfiles := []string{}
	for _, pkg := range goPkgs {
		coverProfile := path.Join(coverageDir,
			fmt.Sprintf("%s%s", strings.ReplaceAll(pkg, "/", "-"), ".out"))
		testErr := sh.Run("go", "test", "-v", "-covermode", "count", fmt.Sprintf("-coverprofile=%s", coverProfile),
			pkg)
		if testErr != nil {
			return testErr
		}
		//coverProfiles = append(coverProfiles, coverProfile)
	}

	return nil
}

// Coverage sums up the coverage profiles in .coverage. It does not clean up after itself or before.
func Coverage() error {
	// Clean up coverage directory
	coverFiles, derr := listCoverageFiles()
	if derr != nil {
		return derr
	}

	mergedCoverage, err := sh.Output("gocovmerge", coverFiles...)
	if err != nil {
		return err
	}
	return ioutil.WriteFile(constCoverFile, []byte(mergedCoverage), os.FileMode(0777))
}

// All runs a full suite suitable for CI
//
//nolint:unparam
func All() error {
	mg.SerialDeps(Style, Lint, Test, Coverage, Release)
	return nil
}

// GithubReleaseMatrix emits a line to setup build matrix jobs for release builds.
//
//nolint:unparam
func GithubReleaseMatrix() error {
	output := make([]string, 0, len(platforms))
	for _, platform := range platforms {
		output = append(output, platform.String())
	}
	jsonData := must(json.Marshal(output))
	fmt.Printf("::set-output name=release-matrix::%s\n", string(jsonData))
	return nil
}

func makeBuilder(cmd string, platform Platform) func() error {
	f := func() error {
		cmdSrc := fmt.Sprintf("./%s/%s", must(filepath.Rel(curDir, cmdDir)), cmd)

		Log("Make platform binary directory:", platform.PlatformDir())
		if err := os.MkdirAll(platform.PlatformDir(), os.FileMode(0777)); err != nil {
			return errors.Wrapf(err, "error making directory: cmd: %s", cmd)
		}

		Log("Checking for changes:", platform.PlatformBin(cmd))
		if changed, err := target.Path(platform.PlatformBin(cmd), goSrc...); !changed {
			if err != nil {
				if !os.IsNotExist(err) {
					return errors.Wrapf(err, "error while checking for changes: cmd: %s", cmd)
				}
			} else {
				return nil
			}
		}

		fmt.Println("Building", platform.PlatformBin(cmd))
		return sh.RunWith(map[string]string{"CGO_ENABLED": "0", "GOOS": platform.OS, "GOARCH": platform.Arch},
			"go", "build", "-a", "-ldflags", fmt.Sprintf("-buildid='' -extldflags '-static' -X main.Version=%s", version),
			"-trimpath", "-o", platform.PlatformBin(cmd), cmdSrc)
	}
	return f
}

func getCurrentPlatform() *Platform {
	var curPlatform *Platform
	for _, p := range platforms {
		if p.OS == runtime.GOOS && p.Arch == runtime.GOARCH {
			storedP := p
			curPlatform = &storedP
		}
	}
	Log("Determined current platform:", curPlatform)
	return curPlatform
}

// Binary build a binary for the current platform.
func Binary() error {
	curPlatform := getCurrentPlatform()
	if curPlatform == nil {
		return errPlatformNotSupported
	}

	if err := ReleaseBin(curPlatform.String()); err != nil {
		return err
	}

	buildResults := map[string]func() error{}

	for _, cmd := range goCmds {
		buildResults[cmd] = concurrentRun(func() error {
			// Make a root symlink to the build
			cmdPath := path.Join(curDir, cmd)
			os.Remove(cmdPath)
			if err := os.Symlink(curPlatform.PlatformBin(cmd), cmdPath); err != nil {
				return err
			}
			return nil
		})
	}

	return waitResults(buildResults)()
}

// doReleaseBin handles the deferred building of an actual release binary.
//
//nolint:gocritic
func doReleaseBin(OSArch string) func() error {
	platform, ok := platformsLookup[OSArch]
	if !ok {
		return func() error { return errors.Wrapf(errPlatformNotSupported, "ReleaseBin: %s", OSArch) }
	}

	buildResults := map[string]func() error{}

	for _, cmd := range goCmds {
		buildResults[cmd] = concurrentRun(makeBuilder(cmd, platform))
	}

	return waitResults(buildResults)
}

// ReleaseBin builds cross-platform release binaries under the bin/ directory.
//
//nolint:gocritic
func ReleaseBin(OSArch string) error {
	return doReleaseBin(OSArch)()
}

// ReleaseBinAll builds cross-platform release binaries under the bin/ directory.
func ReleaseBinAll() error {
	buildResults := map[string]func() error{}
	for OSArch := range platformsLookup {
		buildResults[fmt.Sprintf("build-%s", OSArch)] = doReleaseBin(OSArch)
	}

	return waitResults(buildResults)()
}

// Release builds release archives under the release/ directory.
//
//nolint:gocritic
func doRelease(OSArch string) func() error {
	platform, ok := platformsLookup[OSArch]
	if !ok {
		return func() error { return errors.Wrapf(errPlatformNotSupported, "ReleaseBin: %s", OSArch) }
	}

	return func() error {
		if err := ReleaseBin(OSArch); err != nil {
			return err
		}

		archiveCmds := map[string]func() error{}
		if platform.OS == "windows" {
			// build a zip binary as well
			archiveName := fmt.Sprintf("%s.zip", platform.ReleaseBase())
			archiveCmds[archiveName] = concurrentRun(func() error {
				if _, err := os.Stat(archiveName); err == nil {
					_ = os.Remove(archiveName)
				}
				archiveDir := path.Join(binDir, platform.ArchiveDir())
				fmt.Println("Archiving", archiveName)
				return archiver.NewZip().Archive([]string{archiveDir}, archiveName)
			})
		}

		// build tar gz
		archiveName := fmt.Sprintf("%s.tar.gz", platform.ReleaseBase())
		archiveCmds[archiveName] = concurrentRun(func() error {
			if _, err := os.Stat(archiveName); err == nil {
				_ = os.Remove(archiveName)
			}
			archiveDir := path.Join(binDir, platform.ArchiveDir())
			fmt.Println("Archiving", archiveName)
			return archiver.NewTarGz().Archive([]string{archiveDir}, archiveName)
		})

		return waitResults(archiveCmds)()
	}
}

// PlatformTargets prints the list of target platforms
func PlatformTargets() error {
	platforms := make([]string, 0, len(platformsLookup))
	for platform := range platformsLookup {
		platforms = append(platforms, platform)
	}
	sort.Strings(platforms)
	for _, platform := range platforms {
		fmt.Println(platform)
	}
	return nil
}

// Release a binary archive for a specific platform
//
//nolint:gocritic
func Release(OSArch string) error {
	return doRelease(OSArch)()
}

// Release builds release archives under the release/ directory.
func ReleaseAll() error {
	buildResults := map[string]func() error{}
	for OSArch := range platformsLookup {
		buildResults[fmt.Sprintf("release-%s", OSArch)] = doRelease(OSArch)
	}

	return waitResults(buildResults)()
}

// Clean deletes build output and cleans up the working directory.
func Clean() error {
	for _, name := range goCmds {
		if err := sh.Rm(path.Join(binDir, name)); err != nil {
			return err
		}
	}

	for _, name := range outputDirs {
		if err := sh.Rm(name); err != nil {
			return err
		}
	}
	return nil
}

// Debug prints the value of internal state variables
//
//nolint:unparam
func Debug() error {
	fmt.Println("Source Files:", goSrc)
	fmt.Println("Packages:", goPkgs)
	fmt.Println("Directories:", goDirs)
	fmt.Println("Command Paths:", goCmds)
	fmt.Println("Output Dirs:", outputDirs)
	fmt.Println("PATH:", os.Getenv("PATH"))
	return nil
}

// Autogen configure local git repository with commit hooks.
func Autogen() error {
	fmt.Println("Installing git hooks in local repository...")

	for _, fname := range must(ioutil.ReadDir(gitHookDir)) {
		hookName := fname.Name()
		if !fname.IsDir() {
			continue
		}

		gitHookPath := fmt.Sprintf(".git/hooks/%s", hookName)
		repoHookPath := path.Join(gitHookDir, fname.Name())

		scripts := []string{}
		for _, scriptName := range must(ioutil.ReadDir(repoHookPath)) {
			if scriptName.IsDir() {
				continue
			}
			fullHookPath := path.Join(gitHookDir, hookName, scriptName.Name())
			relHookPath := must(filepath.Rel(binRootName, fullHookPath))

			scripts = append(scripts, relHookPath)

			data, err := ioutil.ReadFile(gitHookPath)
			if err != nil {
				data = []byte("#!/bin/bash\n")
			}

			splitHook := strings.Split(string(data), "\n")
			if strings.TrimRight(splitHook[0], " \t") != "#!/bin/bash" {
				fmt.Printf("Don't know how to update your %s script.\n", hookName)
				return errAutogenUnknownPreCommitScriptFormat
			}

			headAt := -1
			tailAt := -1
			for idx, line := range splitHook {
				// Search until header.
				if strings.TrimPrefix(line, " ") == constManagedScriptSectionHead {
					if headAt != -1 {
						fmt.Println("Found multiple managed script sections in ", fname.Name(), "first was at line ", headAt, "second was at line ", idx)
						return errAutogenMultipleScriptSections
					}
					headAt = idx
					continue
				} else if strings.TrimPrefix(line, " ") == constManagedScriptSectionFoot {
					if tailAt != -1 {
						fmt.Println("Found multiple managed script sections in ", fname.Name(), "first was at line ", headAt, "second was at line ", idx)
						return errAutogenMultipleScriptSections
					}
					tailAt = idx + 1
					continue
				}
			}

			if headAt == -1 {
				headAt = 1
			}

			if tailAt == -1 {
				tailAt = len(splitHook)
			}

			scriptPackage := []string{constManagedScriptSectionHead}
			scriptPackage = append(scriptPackage, "# These lines were added by go run mage.go autogen.", "")
			for _, scriptPath := range scripts {
				scriptPackage = append(scriptPackage, fmt.Sprintf("\"./%s\" || exit $?", scriptPath))
			}
			scriptPackage = append(scriptPackage, "", constManagedScriptSectionFoot)

			updatedScript := splitHook[:headAt]
			updatedScript = append(updatedScript, scriptPackage...)
			updatedScript = append(updatedScript, splitHook[tailAt:]...)

			err = ioutil.WriteFile(gitHookPath, []byte(strings.Join(updatedScript, "\n")),
				os.FileMode(0755))
			if err != nil {
				return err
			}
		}
	}

	return nil
}
