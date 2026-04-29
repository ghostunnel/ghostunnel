//go:build mage

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

type Go mg.Namespace
type Apple mg.Namespace
type Git mg.Namespace
type Test mg.Namespace
type Docker mg.Namespace
type Website mg.Namespace

var Default = Go.Build

// runSilent executes a command without echoing it to stdout, to avoid
// leaking sensitive arguments (passwords, secrets) in CI logs.
func runSilent(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// printf prints the given format and args if verbose mode is enabled.
func printf(format string, args ...interface{}) {
	if mg.Verbose() {
		fmt.Printf(format, args...)
	}
}

// runCommands executes a list of commands, stopping on the first error.
// Checks the context for cancellation before running each command.
func runCommands(ctx context.Context, cmds [][]string) error {
	for _, cmd := range cmds {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("context cancelled: %w", err)
		}
		if err := sh.Run(cmd[0], cmd[1:]...); err != nil {
			return err
		}
	}
	return nil
}

// Builds builds the Ghostunnel binary.
func (Go) Build(ctx context.Context) error {
	version := os.Getenv("VERSION")
	if version == "" {
		version = getVersion()
	}

	return sh.Run("go", "build", "-ldflags", fmt.Sprintf("-X main.version=%s", version), "-o", "ghostunnel", ".")
}

// Lint runs golangci-lint on the codebase.
func (Go) Lint(ctx context.Context) error {
	cmd := exec.CommandContext(ctx, "go", "tool", "golangci-lint", "run")
	output, err := cmd.CombinedOutput()
	if err != nil {
		os.Stdout.Write(output)
		return err
	}
	return nil
}

// Man generates the Ghostunnel man page from the built binary.
// Also generates docs/reference/manpage-<os>.md from the man page using
// pandoc, with Hugo front matter prepended for the website.
func (Go) Man(ctx context.Context) error {
	mg.CtxDeps(ctx, Go.Build)

	output, err := sh.Output("./ghostunnel", "--help-custom-man")
	if err != nil {
		return fmt.Errorf("failed to generate man page: %w", err)
	}

	if err := os.WriteFile("ghostunnel.man", []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write ghostunnel.man: %w", err)
	}

	// Generate docs/reference/manpage-<os>.md from the man page using pandoc
	manpageMD := fmt.Sprintf("docs/reference/manpage-%s.md", runtime.GOOS)
	pandocOutput, err := sh.Output("pandoc", "-f", "man", "-t", "gfm", "ghostunnel.man")
	if err != nil {
		return fmt.Errorf("failed to convert man page to markdown: %w", err)
	}

	// Platform-specific titles, weights, and aliases for Hugo front matter
	manPageMeta := map[string]struct {
		title  string
		weight int
		alias  string
	}{
		"darwin": {title: "Man Page (macOS)", weight: 20, alias: "/docs/manpage-darwin/"},
		"linux":  {title: "Man Page (Linux)", weight: 10, alias: "/docs/manpage-linux/"},
	}

	meta, ok := manPageMeta[runtime.GOOS]
	if !ok {
		meta.title = fmt.Sprintf("Man Page (%s)", runtime.GOOS)
		meta.weight = 30
		meta.alias = fmt.Sprintf("/docs/manpage-%s/", runtime.GOOS)
	}

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "---\n")
	fmt.Fprintf(&buf, "title: %s\n", meta.title)
	fmt.Fprintf(&buf, "description: Complete command-line reference with all flags, modes, and examples.\n")
	fmt.Fprintf(&buf, "weight: %d\n", meta.weight)
	fmt.Fprintf(&buf, "aliases:\n")
	fmt.Fprintf(&buf, "  - %s\n", meta.alias)
	fmt.Fprintf(&buf, "---\n\n")
	fmt.Fprintf(&buf, "> This man page was generated from the %s binary. Some flags may differ on other platforms.\n\n", meta.title[len("Man Page ("):len(meta.title)-1])
	buf.WriteString(pandocOutput)

	if err := os.WriteFile(manpageMD, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %w", manpageMD, err)
	}

	return nil
}

// Codesign signs a macOS binary using the codesign tool. The binary argument
// specifies which file to sign. Requires macOS. If CODESIGN_CERTIFICATE is
// set, a temporary keychain is created, the certificate is imported, and the
// keychain is cleaned up after signing.
//
// Environment variables:
//   - CODESIGN_IDENTITY: Signing identity (required, e.g. "Developer ID Application: Name (TEAMID)")
//   - CODESIGN_CERTIFICATE: Base64-encoded .p12 certificate to import into a temporary keychain (optional, for CI)
//   - CODESIGN_CERTIFICATE_PASSWORD: Password for the .p12 certificate (required if CODESIGN_CERTIFICATE is set)
func (Apple) Codesign(ctx context.Context, binary string) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("codesigning is only supported on macOS")
	}

	identity := os.Getenv("CODESIGN_IDENTITY")
	if identity == "" {
		return fmt.Errorf("CODESIGN_IDENTITY must be set")
	}

	certData := os.Getenv("CODESIGN_CERTIFICATE")
	if certData != "" {
		cleanup, err := setupCodesignKeychain(certData)
		if err != nil {
			return err
		}
		defer cleanup()
	}

	printf("Signing binary %s with identity %s\n", binary, identity)

	if err := sh.Run("codesign", "--force", "--options", "runtime", "--sign", identity, binary); err != nil {
		return fmt.Errorf("codesign %s failed: %w", binary, err)
	}

	if err := sh.Run("codesign", "--verify", "--verbose", binary); err != nil {
		return fmt.Errorf("codesign verification of %s failed: %w", binary, err)
	}

	printf("Binary %s signed and verified successfully\n", binary)
	return nil
}

// Notarize submits a signed macOS binary to Apple's notary service. Requires
// macOS. If NOTARIZE_KEY is set, the .p8 key is written to a temp file and
// cleaned up after notarization.
//
// The binary is zipped for submission and the zip is removed afterward.
// Note: stapling only works for .app, .pkg, and .dmg — for bare binaries the
// notarization is registered with Apple but cannot be stapled. The staple step
// is attempted but a failure is not treated as an error.
//
// Environment variables:
//   - NOTARIZE_ISSUER_ID: App Store Connect API issuer ID (required)
//   - NOTARIZE_KEY_ID: App Store Connect API key ID (required)
//   - NOTARIZE_KEY: Base64-encoded .p8 private key (optional, for CI; if not set, key must already exist)
func (Apple) Notarize(ctx context.Context, binary string) error {
	if runtime.GOOS != "darwin" {
		return fmt.Errorf("notarization is only supported on macOS")
	}

	issuerID := os.Getenv("NOTARIZE_ISSUER_ID")
	keyID := os.Getenv("NOTARIZE_KEY_ID")
	if issuerID == "" || keyID == "" {
		return fmt.Errorf("NOTARIZE_ISSUER_ID and NOTARIZE_KEY_ID must be set")
	}

	// If NOTARIZE_KEY is set, write the .p8 key to a temp file for notarytool
	keyPath, err := setupNotarizeKey(keyID)
	if err != nil {
		return err
	}
	if keyPath != "" {
		defer os.Remove(keyPath)
	}

	// Create zip for submission
	zipPath := binary + ".zip"
	if err := sh.Run("ditto", "-c", "-k", "--sequesterRsrc", binary, zipPath); err != nil {
		return fmt.Errorf("failed to create zip for %s: %w", binary, err)
	}

	printf("Submitting %s for notarization...\n", binary)

	submitArgs := []string{"notarytool", "submit", zipPath,
		"--issuer", issuerID,
		"--key-id", keyID,
	}
	if keyPath != "" {
		submitArgs = append(submitArgs, "--key", keyPath)
	}
	submitArgs = append(submitArgs, "--wait")

	err = sh.Run("xcrun", submitArgs...)
	os.Remove(zipPath)
	if err != nil {
		return fmt.Errorf("notarization of %s failed: %w", binary, err)
	}

	// Attempt to staple — this only works for .app/.pkg/.dmg, not bare binaries
	if err := sh.Run("xcrun", "stapler", "staple", binary); err != nil {
		printf("Stapling skipped for %s (not supported for bare binaries): %v\n", binary, err)
	}

	printf("Notarization of %s completed successfully\n", binary)
	return nil
}

// setupCodesignKeychain creates a temporary keychain, imports the signing
// certificate, and configures the keychain search list. Returns a cleanup
// function that removes the temporary keychain and restores the original
// search list.
func setupCodesignKeychain(certBase64 string) (func(), error) {
	password := os.Getenv("CODESIGN_CERTIFICATE_PASSWORD")
	if password == "" {
		return nil, fmt.Errorf("CODESIGN_CERTIFICATE_PASSWORD must be set when CODESIGN_CERTIFICATE is set")
	}

	// Decode certificate
	certBytes, err := base64.StdEncoding.DecodeString(certBase64)
	if err != nil {
		return nil, fmt.Errorf("failed to decode CODESIGN_CERTIFICATE: %w", err)
	}

	// Write certificate to temp file
	certFile, err := os.CreateTemp("", "codesign-*.p12")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp file: %w", err)
	}
	if _, err := certFile.Write(certBytes); err != nil {
		os.Remove(certFile.Name())
		return nil, fmt.Errorf("failed to write certificate: %w", err)
	}
	certFile.Close()

	// Generate random keychain password
	keychainPassBytes := make([]byte, 32)
	if _, err := rand.Read(keychainPassBytes); err != nil {
		os.Remove(certFile.Name())
		return nil, fmt.Errorf("failed to generate keychain password: %w", err)
	}
	keychainPassword := base64.StdEncoding.EncodeToString(keychainPassBytes)

	keychainPath := "ghostunnel-signing.keychain-db"

	// Save original keychain search list
	originalKeychains, err := sh.Output("security", "list-keychains", "-d", "user")
	if err != nil {
		os.Remove(certFile.Name())
		return nil, fmt.Errorf("failed to list keychains: %w", err)
	}

	cleanup := func() {
		// Restore original keychain search list
		restoreArgs := []string{"list-keychains", "-d", "user", "-s"}
		restoreArgs = append(restoreArgs, parseKeychainPaths(originalKeychains)...)
		sh.Run("security", restoreArgs...)
		sh.Run("security", "delete-keychain", keychainPath)
		os.Remove(certFile.Name())
	}

	// Create temporary keychain (suppress command echo to avoid leaking keychain password)
	if err := runSilent("security", "create-keychain", "-p", keychainPassword, keychainPath); err != nil {
		cleanup()
		return nil, fmt.Errorf("failed to create keychain: %w", err)
	}

	// Set keychain settings (no auto-lock)
	if err := sh.Run("security", "set-keychain-settings", keychainPath); err != nil {
		cleanup()
		return nil, fmt.Errorf("failed to set keychain settings: %w", err)
	}

	// Unlock keychain (suppress command echo to avoid leaking keychain password)
	if err := runSilent("security", "unlock-keychain", "-p", keychainPassword, keychainPath); err != nil {
		cleanup()
		return nil, fmt.Errorf("failed to unlock keychain: %w", err)
	}

	// Import certificate into keychain (suppress command echo to avoid leaking certificate password)
	if err := runSilent("security", "import", certFile.Name(), "-k", keychainPath, "-f", "pkcs12", "-P", password, "-T", "/usr/bin/codesign"); err != nil {
		cleanup()
		return nil, fmt.Errorf("failed to import certificate: %w", err)
	}

	// Set key partition list to allow codesign access (suppress command echo to avoid leaking keychain password)
	if err := runSilent("security", "set-key-partition-list", "-S", "apple-tool:,apple:,codesign:", "-s", "-k", keychainPassword, keychainPath); err != nil {
		cleanup()
		return nil, fmt.Errorf("failed to set key partition list: %w", err)
	}

	// Add temporary keychain to search list (prepend to existing)
	keychainArgs := []string{"list-keychains", "-d", "user", "-s", keychainPath}
	keychainArgs = append(keychainArgs, parseKeychainPaths(originalKeychains)...)
	if err := sh.Run("security", keychainArgs...); err != nil {
		cleanup()
		return nil, fmt.Errorf("failed to update keychain search list: %w", err)
	}

	return cleanup, nil
}

// setupNotarizeKey writes the NOTARIZE_KEY env var (base64-encoded .p8) to a
// temp file and returns its path. Returns an empty path if NOTARIZE_KEY is not
// set (assumes the key file is already available locally).
func setupNotarizeKey(keyID string) (string, error) {
	keyData := os.Getenv("NOTARIZE_KEY")
	if keyData == "" {
		return "", nil
	}

	keyBytes, err := base64.StdEncoding.DecodeString(keyData)
	if err != nil {
		return "", fmt.Errorf("failed to decode NOTARIZE_KEY: %w", err)
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("failed to get home directory: %w", err)
	}

	keyDir := filepath.Join(homeDir, "private_keys")
	if err := os.MkdirAll(keyDir, 0700); err != nil {
		return "", fmt.Errorf("failed to create private_keys directory: %w", err)
	}

	keyPath := filepath.Join(keyDir, fmt.Sprintf("AuthKey_%s.p8", keyID))
	if err := os.WriteFile(keyPath, keyBytes, 0600); err != nil {
		return "", fmt.Errorf("failed to write API key: %w", err)
	}

	return keyPath, nil
}

// parseKeychainPaths parses the output of `security list-keychains` into
// a list of unquoted keychain paths.
func parseKeychainPaths(output string) []string {
	var paths []string
	for _, line := range strings.Split(output, "\n") {
		kc := strings.TrimSpace(strings.Trim(strings.TrimSpace(line), "\""))
		if kc != "" {
			paths = append(paths, kc)
		}
	}
	return paths
}

// Clean removes build artifacts.
func (Git) Clean(ctx context.Context) error {
	return sh.Run("git", "clean", "-Xdf")
}

// pythonCmd returns the Python interpreter command for the current platform.
// On Windows, Python is typically installed as "python" rather than "python3".
func pythonCmd() string {
	if runtime.GOOS == "windows" {
		return "python"
	}
	return "python3"
}

// coveredPackages is the list of packages to instrument for coverage.
// Used consistently across unit and integration tests so that coverage
// blocks are compatible when merged.
var coveredPackages = ".,./auth,./certloader,./certloader/jceks,./certstore,./policy,./proxy,./wildcard,./socket"

// cleanCoverage removes stale coverage data from previous runs and
// recreates the coverage subdirectories. Used as a mage dep so that mage's
// built-in deduplication ensures it runs exactly once per invocation,
// even when Unit and Integration are triggered in parallel by Test.All.
func cleanCoverage() error {
	if err := os.RemoveAll("coverage"); err != nil {
		return fmt.Errorf("failed to remove coverage directory: %w", err)
	}
	for _, sub := range []string{"unit", "integration"} {
		if err := os.MkdirAll(filepath.Join("coverage", sub), 0755); err != nil {
			return fmt.Errorf("failed to create coverage/%s: %w", sub, err)
		}
	}
	return nil
}

// build builds a coverage-instrumented binary using go build -cover.
// Unlike go test -c, this produces a normal binary that writes coverage
// data to GOCOVERDIR on exit (including signal-triggered exits).
func (Test) build() error {
	output := "ghostunnel.cover"
	if runtime.GOOS == "windows" {
		output += ".exe"
	}
	return sh.Run("go", "build", "-cover", "-covermode=count", "-coverpkg", coveredPackages, "-tags", "coverage", "-o", output, ".")
}

// All runs both unit and integration tests, then merges coverage.
func (Test) All(ctx context.Context) error {
	mg.CtxDeps(ctx, Test.Unit, Test.Integration)
	mg.CtxDeps(ctx, Test.Coverage)
	return nil
}

// Unit runs the unit tests.
func (Test) Unit(ctx context.Context) error {
	mg.Deps(cleanCoverage)
	printf("Running unit tests...\n")

	return sh.Run("go", "test", "-v", "-covermode=count", "-coverpkg", coveredPackages, "-coverprofile=coverage/unit.profile", "./...")
}

// Integration runs the integration tests in parallel.
// Set GHOSTUNNEL_TEST_PARALLEL to control concurrency (default: NumCPU, max 16).
func (Test) Integration(ctx context.Context) error {
	mg.CtxDeps(ctx, Test.build)
	mg.Deps(cleanCoverage)

	// Run integration tests
	testFiles, err := filepath.Glob("tests/test-*.py")
	if err != nil || len(testFiles) == 0 {
		return fmt.Errorf("failed to find test files: %w", err)
	}

	// Determine parallelism. On Windows, default to 1 because without
	// SO_REUSEPORT we can't keep port reservation sockets open, so parallel
	// tests risk ephemeral port collisions.
	parallel := runtime.NumCPU()
	if parallel > 16 {
		parallel = 16
	}
	if runtime.GOOS == "windows" {
		parallel = 1
	}
	if envVal := os.Getenv("GHOSTUNNEL_TEST_PARALLEL"); envVal != "" {
		if n, err := strconv.Atoi(envVal); err == nil && n > 0 {
			parallel = n
		}
	}

	printf("Running %d integration tests with parallelism=%d...\n", len(testFiles), parallel)

	type testResult struct {
		name     string
		stdout   []byte
		stderr   []byte
		err      error
		duration time.Duration
	}

	// Channel-based semaphore for limiting concurrency
	sem := make(chan struct{}, parallel)
	results := make(chan testResult, len(testFiles))

	// Launch all tests as goroutines
	for _, testFile := range testFiles {
		go func() {
			// Check for context cancellation before acquiring semaphore
			select {
			case <-ctx.Done():
				results <- testResult{
					name: strings.TrimSuffix(filepath.Base(testFile), ".py"),
					err:  ctx.Err(),
				}
				return
			case sem <- struct{}{}: // acquire
			}
			defer func() { <-sem }() // release

			testName := strings.TrimSuffix(filepath.Base(testFile), ".py")
			printf("=== RUN   %s\n", testName)

			start := time.Now()
			testFileName := filepath.Base(testFile)
			cmd := exec.CommandContext(ctx, pythonCmd(), testFileName)
			cmd.Dir = "tests"

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Run()
			duration := time.Since(start)

			results <- testResult{
				name:     testName,
				stdout:   stdout.Bytes(),
				stderr:   stderr.Bytes(),
				err:      err,
				duration: duration,
			}
		}()
	}

	// Collect results
	var failed []testResult
	for i := 0; i < len(testFiles); i++ {
		r := <-results
		if r.err == nil {
			printf("--- PASS: %s (%.2fs)\n", r.name, r.duration.Seconds())
		} else if exitErr, ok := r.err.(*exec.ExitError); ok && exitErr.ExitCode() == 2 {
			reason := strings.SplitN(strings.TrimSpace(string(r.stderr)), "\n", 2)[0]
			printf("--- SKIP: %s (%.2fs) (%s)\n", r.name, r.duration.Seconds(), reason)
		} else {
			fmt.Printf("--- FAIL: %s (%.2fs)\n", r.name, r.duration.Seconds())
			failed = append(failed, r)
		}
	}

	// Report failures
	if len(failed) > 0 {
		fmt.Printf("\n--- FAILURES ---\n")
		for _, r := range failed {
			fmt.Printf("\n--- FAIL: %s (%.2fs)\n", r.name, r.duration.Seconds())
			fmt.Printf("--- stdout ---\n")
			os.Stdout.Write(r.stdout)
			fmt.Printf("--- stderr ---\n")
			os.Stdout.Write(r.stderr)
		}
		return fmt.Errorf("%d integration test(s) failed", len(failed))
	}

	return nil
}

// Single runs a single integration test by name.
// The test name can be specified with or without the "test-" prefix and ".py" suffix.
// Examples:
//
//	mage test:single test-server-listen-port-conflict
//	mage test:single server-listen-port-conflict
//	mage test:single test-server-listen-port-conflict.py
func (Test) Single(ctx context.Context, name string) error {
	mg.CtxDeps(ctx, Test.build)
	mg.Deps(cleanCoverage)

	// Normalize the test name
	name = strings.TrimSuffix(name, ".py")
	if !strings.HasPrefix(name, "test-") {
		name = "test-" + name
	}

	// Check that the test file exists
	testPath := filepath.Join("tests", name+".py")
	if _, err := os.Stat(testPath); err != nil {
		return fmt.Errorf("integration test file not found: %s", testPath)
	}

	// Run the test
	printf("=== RUN   %s\n", name)
	start := time.Now()

	cmd := exec.CommandContext(ctx, pythonCmd(), name+".py")
	cmd.Dir = "tests"

	var stdout, stderr bytes.Buffer
	if mg.Verbose() {
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
	} else {
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr
	}

	err := cmd.Run()
	elapsed := time.Since(start).Seconds()

	if err == nil {
		printf("--- PASS: %s (%.2fs)\n", name, elapsed)
		return nil
	}

	// On failure, show captured output if not already streaming
	if !mg.Verbose() {
		fmt.Printf("--- stdout ---\n")
		os.Stdout.Write(stdout.Bytes())
		fmt.Printf("--- stderr ---\n")
		os.Stdout.Write(stderr.Bytes())
	}
	fmt.Printf("--- FAIL: %s (%.2fs)\n", name, elapsed)
	if exitError, ok := err.(*exec.ExitError); ok {
		return fmt.Errorf("integration test %s failed with exit code %d", name, exitError.ExitCode())
	}
	return fmt.Errorf("integration test %s failed: %w", name, err)
}

// Coverage merges coverage data from unit and integration tests into
// a single text profile. Integration tests use GOCOVERDIR (binary format),
// which is converted to text with go tool covdata. Unit tests produce a
// text profile directly. The two text profiles are then merged.
func (Test) Coverage(ctx context.Context) error {
	mg.CtxDeps(ctx, Test.Unit, Test.Integration)

	// Convert integration GOCOVERDIR binary data to a text profile.
	if err := sh.Run("go", "tool", "covdata", "textfmt",
		"-i=coverage/integration",
		"-o=coverage/integration.profile",
	); err != nil {
		return fmt.Errorf("failed to convert integration coverage to text: %w", err)
	}

	// Merge unit and integration text profiles.
	return mergeProfiles(
		[]string{"coverage/unit.profile", "coverage/integration.profile"},
		"coverage/all.profile",
	)
}

// coverageExcludedPatterns lists basename glob patterns whose blocks are
// dropped during coverage merging.
var coverageExcludedPatterns = []string{
	"test_helpers_*.go",
}

// isCoverageExcluded reports whether a coverage block key (e.g.
// "github.com/ghostunnel/ghostunnel/certstore/test_helpers_darwin.go:10.1,12.2")
// belongs to a file that should be excluded from coverage reports.
func isCoverageExcluded(key string) bool {
	colon := strings.LastIndex(key, ":")
	if colon < 0 {
		return false
	}
	base := filepath.Base(key[:colon])
	for _, pat := range coverageExcludedPatterns {
		if ok, _ := filepath.Match(pat, base); ok {
			return true
		}
	}
	return false
}

// mergeProfiles merges multiple Go coverage text profiles into one.
// For blocks that appear in multiple profiles, hit counts are summed.
// Blocks from files matching coverageExcluded are dropped — these are
// test-only helpers that have to live in non-_test.go files (cgo is not
// allowed in _test.go) and would otherwise skew package coverage.
func mergeProfiles(inputs []string, output string) error {
	type block struct {
		stmts int
		count int
	}

	mode := ""
	blocks := map[string]*block{} // key = "file:startline.col,endline.col"

	for _, input := range inputs {
		data, err := os.ReadFile(input)
		if err != nil {
			return fmt.Errorf("failed to read %s: %w", input, err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			if strings.HasPrefix(line, "mode:") {
				if mode == "" {
					mode = strings.TrimSpace(strings.TrimPrefix(line, "mode:"))
				}
				continue
			}
			// Format: "pkg/file.go:start,end stmts count"
			lastSpace := strings.LastIndex(line, " ")
			if lastSpace < 0 {
				continue
			}
			rest := line[:lastSpace]
			countStr := line[lastSpace+1:]

			secondLastSpace := strings.LastIndex(rest, " ")
			if secondLastSpace < 0 {
				continue
			}
			key := rest[:secondLastSpace]
			stmtsStr := rest[secondLastSpace+1:]

			if isCoverageExcluded(key) {
				continue
			}

			count, err := strconv.Atoi(countStr)
			if err != nil {
				continue
			}
			stmts, err := strconv.Atoi(stmtsStr)
			if err != nil {
				continue
			}

			if b, ok := blocks[key]; ok {
				b.count += count
			} else {
				blocks[key] = &block{stmts: stmts, count: count}
			}
		}
	}

	if mode == "" {
		mode = "count"
	}

	// Sort keys for deterministic output
	keys := make([]string, 0, len(blocks))
	for k := range blocks {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf bytes.Buffer
	fmt.Fprintf(&buf, "mode: %s\n", mode)
	for _, key := range keys {
		b := blocks[key]
		fmt.Fprintf(&buf, "%s %d %d\n", key, b.stmts, b.count)
	}

	return os.WriteFile(output, buf.Bytes(), 0644)
}

// Keys generates test certificates and keys for development/testing purposes.
// These should NOT be used in production. The keys are generated in the test-keys directory.
func (Test) Keys(ctx context.Context) error {
	// Create test-keys directory
	if err := os.MkdirAll("test-keys", 0755); err != nil {
		return err
	}

	// Write openssl.ext configuration file
	opensslExt := `[root]
keyUsage=critical, keyCertSign
basicConstraints=critical, CA:TRUE, pathlen:0
[server]
extendedKeyUsage = serverAuth
subjectAltName = IP:127.0.0.1,IP:::1,DNS:localhost,URI:spiffe://ghostunnel/server
[client]
extendedKeyUsage = clientAuth
subjectAltName = IP:127.0.0.1,IP:::1,DNS:localhost,URI:spiffe://ghostunnel/client
`
	if err := os.WriteFile("test-keys/openssl.ext", []byte(opensslExt), 0644); err != nil {
		return err
	}

	// Root CA generation commands
	rootCommands := [][]string{
		{"openssl", "genrsa", "-out", "test-keys/root-key.pem", "2048"},
		{"openssl", "req", "-new", "-key", "test-keys/root-key.pem", "-out", "test-keys/root-csr.pem", "-subj", "/CN=root"},
		{"openssl", "x509", "-req", "-sha256", "-in", "test-keys/root-csr.pem", "-signkey", "test-keys/root-key.pem", "-out", "test-keys/root-cert.pem", "-days", "5000", "-extfile", "test-keys/openssl.ext", "-extensions", "root"},
	}
	if err := runCommands(ctx, rootCommands); err != nil {
		return err
	}

	// Create root combined file and cacert.pem
	rootCert, rootCertErr := os.ReadFile("test-keys/root-cert.pem")
	rootKey, rootKeyErr := os.ReadFile("test-keys/root-key.pem")
	if rootCertErr != nil || rootKeyErr != nil {
		return fmt.Errorf("failed to read root certificate or key: %v / %v", rootCertErr, rootKeyErr)
	}
	rootCombined := append(rootCert, rootKey...)
	if err := os.WriteFile("test-keys/root-combined.pem", rootCombined, 0644); err != nil {
		return err
	}
	if err := os.WriteFile("test-keys/cacert.pem", rootCert, 0644); err != nil {
		return err
	}

	// Generate server and client keys
	for _, name := range []string{"server", "client"} {
		if err := generateEntityKeys(ctx, name); err != nil {
			return err
		}
	}

	printf("Test keys generated successfully in test-keys/ directory\n")
	return nil
}

// generateEntityKeys generates all keys and certificates for a given entity (server or client).
func generateEntityKeys(ctx context.Context, name string) error {
	commands := [][]string{
		{"openssl", "genrsa", "-out", fmt.Sprintf("test-keys/%s-key.pem", name), "2048"},
		{"openssl", "req", "-new", "-key", fmt.Sprintf("test-keys/%s-key.pem", name), "-out", fmt.Sprintf("test-keys/%s-csr.pem", name), "-subj", fmt.Sprintf("/CN=%s", name)},
		{"openssl", "x509", "-req", "-sha256", "-in", fmt.Sprintf("test-keys/%s-csr.pem", name), "-CA", "test-keys/root-combined.pem", "-CAkey", "test-keys/root-combined.pem", "-CAcreateserial", "-out", fmt.Sprintf("test-keys/%s-cert.pem", name), "-days", "5000", "-extfile", "test-keys/openssl.ext", "-extensions", name},
	}
	if err := runCommands(ctx, commands); err != nil {
		return err
	}

	// Create combined file
	cert, certErr := os.ReadFile(fmt.Sprintf("test-keys/%s-cert.pem", name))
	key, keyErr := os.ReadFile(fmt.Sprintf("test-keys/%s-key.pem", name))
	if certErr != nil || keyErr != nil {
		return fmt.Errorf("failed to read certificate or key: %v / %v", certErr, keyErr)
	}
	combined := append(cert, key...)
	if err := os.WriteFile(fmt.Sprintf("test-keys/%s-combined.pem", name), combined, 0644); err != nil {
		return err
	}

	// Generate PKCS#12 keystore and PKCS#8 key
	keystoreCommands := [][]string{
		{"openssl", "pkcs12", "-export", "-out", fmt.Sprintf("test-keys/%s-keystore.p12", name), "-in", fmt.Sprintf("test-keys/%s-combined.pem", name), "-inkey", fmt.Sprintf("test-keys/%s-combined.pem", name), "-passout", "pass:"},
		{"openssl", "pkcs8", "-topk8", "-inform", "PEM", "-outform", "PEM", "-in", fmt.Sprintf("test-keys/%s-key.pem", name), "-out", fmt.Sprintf("test-keys/%s-pkcs8.pem", name), "-nocrypt"},
	}
	if err := runCommands(ctx, keystoreCommands); err != nil {
		return err
	}

	return nil
}

// SoftHSMImport initializes a SoftHSM token and imports the test server key.
// Automatically generates test keys if they don't exist (via Test.Keys dependency).
// Environment variables can be used to configure SoftHSM:
//   - GHOSTUNNEL_TEST_PKCS11_LABEL: Token label (default: "ghostunnel-pkcs11-test")
//   - GHOSTUNNEL_TEST_PKCS11_PIN: Token PIN (default: "1234")
//   - SOFTHSM2_CONF: SoftHSM config file path (default: "/etc/softhsm/softhsm2.conf")
func (Test) SoftHSMImport(ctx context.Context) error {
	mg.CtxDeps(ctx, Test.Keys)

	// Get configuration from environment variables
	label := os.Getenv("GHOSTUNNEL_TEST_PKCS11_LABEL")
	pin := os.Getenv("GHOSTUNNEL_TEST_PKCS11_PIN")
	if label == "" || pin == "" {
		return fmt.Errorf("GHOSTUNNEL_TEST_PKCS11_LABEL and GHOSTUNNEL_TEST_PKCS11_PIN must be set")
	}

	printf("Initializing SoftHSM token with label: %s\n", label)

	// Initialize and import into SoftHSM token
	softhsmCommands := [][]string{
		{"softhsm2-util", "--init-token", "--slot", "0", "--label", label, "--so-pin", pin, "--pin", pin},
		{"softhsm2-util", "--id", "01", "--token", label, "--label", label, "--so-pin", pin, "--pin", pin, "--import", "test-keys/server-pkcs8.pem"},
	}
	if err := runCommands(ctx, softhsmCommands); err != nil {
		return fmt.Errorf("failed to configure SoftHSM: %w", err)
	}

	printf("SoftHSM token initialized and key imported successfully\n")
	return nil
}

// Docker builds and runs tests in a Docker container.
// Output is streamed in real-time as the container runs.
func (Test) Docker(ctx context.Context) error {
	args := []string{"buildx", "build", "-t", "ghostunnel/ghostunnel-test", "-f", "Dockerfile-test"}
	if !mg.Verbose() {
		args = append(args, "--quiet")
	}
	args = append(args, ".")
	if err := sh.Run("docker", args...); err != nil {
		return fmt.Errorf("failed to build test image: %w", err)
	}

	pwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}

	containerName := fmt.Sprintf("ghostunnel-test-%d", os.Getpid())
	args = []string{"run", "--rm", "--name", containerName, "-v", fmt.Sprintf("%s:/go/src/github.com/ghostunnel/ghostunnel", pwd), "ghostunnel/ghostunnel-test", "--"}
	if mg.Verbose() {
		args = append(args, "-v")
	}
	args = append(args, "test:softhsmimport", "test:all")

	defer func() {
		exec.Command("docker", "rm", "-f", containerName).Run()
	}()

	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// Build builds and tags all Docker containers.
// Uses docker buildx for multi-platform builds. Does not push images.
func (Docker) Build(ctx context.Context) error {
	return buildDocker(ctx, false)
}

// Push builds and publishes all Docker containers to Docker Hub.
// Uses docker buildx for multi-platform builds and pushes images.
func (Docker) Push(ctx context.Context) error {
	return buildDocker(ctx, true)
}

// buildDocker builds and tags all Docker containers, optionally pushing them to Docker Hub.
func buildDocker(ctx context.Context, push bool) error {
	baseTags, err := getDockerTags()
	if err != nil {
		return err
	}

	builds := map[string][]string{}
	for _, baseTag := range baseTags {
		builds["Dockerfile-alpine"] = append(builds["Dockerfile-alpine"],
			fmt.Sprintf("ghostunnel/ghostunnel:%s", baseTag),
			fmt.Sprintf("ghostunnel/ghostunnel:%s-alpine", baseTag),
		)
		builds["Dockerfile-debian"] = append(builds["Dockerfile-debian"],
			fmt.Sprintf("ghostunnel/ghostunnel:%s-debian", baseTag),
		)
		builds["Dockerfile-distroless"] = append(builds["Dockerfile-distroless"],
			fmt.Sprintf("ghostunnel/ghostunnel:%s-distroless", baseTag),
		)
	}

	for dockerfile, tags := range builds {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("context cancelled: %w", err)
		}
		if err := buildDockerImage(dockerfile, tags, push); err != nil {
			return fmt.Errorf("failed to build image: %w", err)
		}
	}

	return nil
}

// buildDockerImage builds a Docker image using buildx with the given Dockerfile, tags, and platforms.
// If push is true, it will push the image to the registry.
func buildDockerImage(dockerfile string, tags []string, push bool) error {
	args := []string{"buildx", "build", "-f", dockerfile}

	platforms := os.Getenv("DOCKER_PLATFORMS")
	if platforms != "" {
		args = append(args, "--platform", platforms)
	}
	for _, tag := range tags {
		args = append(args, "-t", tag)
	}
	if !mg.Verbose() {
		args = append(args, "--quiet")
	}
	if push {
		args = append(args, "--push")
	}

	// Add build context & run
	args = append(args, ".")
	return sh.Run("docker", args...)
}

// getVersion gets the version from git describe.
func getVersion() string {
	output, err := sh.Output("git", "describe", "--always", "--dirty")
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(output)
}

// getDockerTags determines the Docker tags to use based on git state.
// For release tags (refs/tags/v*), returns both the version tag and "latest".
// For master branch, returns "master". For local non-master branches, returns
// the most recent git tag.
func getDockerTags() ([]string, error) {
	// Check if we're on a tag (for GitHub Actions when triggered by tag push)
	// In GitHub Actions, GITHUB_REF will be set, but locally we check git
	githubRef := os.Getenv("GITHUB_REF")
	if githubRef != "" {
		// GitHub Actions: refs/heads/master or refs/tags/v1.2.3
		if strings.HasPrefix(githubRef, "refs/heads/master") {
			return []string{"master"}, nil
		}
		if strings.HasPrefix(githubRef, "refs/tags/") {
			tag := strings.TrimPrefix(githubRef, "refs/tags/")
			return []string{tag, "latest"}, nil
		}
	}

	// Check current branch
	branch, err := sh.Output("git", "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return nil, fmt.Errorf("failed to determine git ref: %w", err)
	}
	if strings.TrimSpace(branch) == "master" {
		return []string{"master"}, nil
	}

	// Not on master, get the most recent tag
	tag, err := sh.Output("git", "describe", "--tags", "--abbrev=0")
	if err != nil {
		return nil, fmt.Errorf("failed to get git tag: %w", err)
	}

	return []string{strings.TrimSpace(tag)}, nil
}

// emailAliases maps email addresses to canonical contributor names.
// This merges commits from the same person who used different email addresses.
var emailAliases = map[string]string{
	"cs@squareup.com":                        "Cedric Staub",
	"css@css.bio":                            "Cedric Staub",
	"cs@css.bio":                             "Cedric Staub",
	"csstaub@users.noreply.github.com":       "Cedric Staub",
	"cedric@staub.dev":                       "Cedric Staub",
	"alok@squareup.com":                      "Alok Menghrajani",
	"alok.menghrajani@gmail.com":             "Alok Menghrajani",
	"mmc@squareup.com":                       "Matthew McPherrin",
	"github@mcpherrin.ca":                    "Matthew McPherrin",
	"git@mcpherrin.ca":                       "Matthew McPherrin",
	"mattm@letsencrypt.org":                  "Matthew McPherrin",
	"amartinezfayo@users.noreply.github.com": "Agustín Martínez Fayó",
	"amartinezfayo@gmail.com":                "Agustín Martínez Fayó",
	"ewdurbin@gmail.com":                     "Ernest W. Durbin III",
	"charlie@squareup.com":                   "Charlie Sanders",
	"sanderscharlie@gmail.com":               "Charlie Sanders",
	"andrew.harding@hpe.com":                 "Andrew Harding",
	"azdagron@gmail.com":                     "Andrew Harding",
}

// botNames is the set of git author names to exclude from the contributors list.
var botNames = map[string]bool{
	"dependabot[bot]":         true,
	"dependabot-preview[bot]": true,
	"copilot-swe-agent[bot]":  true,
	"Claude":                  true,
}

type contributor struct {
	Name    string
	Display string
	Commits int
	First   string
	Last    string
}

// githubContributorLogins fetches the GitHub API to build a mapping from
// git author names to GitHub usernames. It returns two maps: nameToLogin
// (from git author name to GitHub login, resolved via commit lookups) and
// emailToLogin (from noreply email patterns to GitHub login). Returns empty
// maps (not an error) if the API is unavailable.
func githubContributorLogins(repo string) (nameToLogin, emailToLogin map[string]string) {
	nameToLogin = map[string]string{}
	emailToLogin = map[string]string{}

	// Use GITHUB_TOKEN for authenticated requests if available (higher rate limit)
	token := os.Getenv("GITHUB_TOKEN")
	apiGet := func(url string) (*http.Response, error) {
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, err
		}
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		return http.DefaultClient.Do(req)
	}

	// Fetch contributors list
	resp, err := apiGet(fmt.Sprintf("https://api.github.com/repos/%s/contributors?per_page=100", repo))
	if err != nil || resp.StatusCode != 200 {
		return nameToLogin, emailToLogin
	}
	defer resp.Body.Close()

	var contributors []struct {
		Login string `json:"login"`
		ID    int    `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&contributors); err != nil {
		return nameToLogin, emailToLogin
	}

	// Build noreply email → login map (works without extra API calls)
	for _, c := range contributors {
		if strings.HasSuffix(c.Login, "[bot]") {
			continue
		}
		emailToLogin[fmt.Sprintf("%s@users.noreply.github.com", c.Login)] = c.Login
		emailToLogin[fmt.Sprintf("%d+%s@users.noreply.github.com", c.ID, c.Login)] = c.Login
	}

	// For each contributor, fetch one commit to discover their git author name.
	// Stops early if rate-limited.
	for _, c := range contributors {
		if strings.HasSuffix(c.Login, "[bot]") {
			continue
		}
		commitResp, err := apiGet(fmt.Sprintf(
			"https://api.github.com/repos/%s/commits?author=%s&per_page=1", repo, c.Login))
		if err != nil {
			continue
		}
		if commitResp.StatusCode == 403 || commitResp.StatusCode == 429 {
			commitResp.Body.Close()
			printf("Warning: GitHub API rate limit reached, resolved %d of %d contributors\n",
				len(nameToLogin), len(contributors))
			break
		}
		if commitResp.StatusCode != 200 {
			commitResp.Body.Close()
			continue
		}
		var commits []struct {
			Commit struct {
				Author struct {
					Name string `json:"name"`
				} `json:"author"`
			} `json:"commit"`
		}
		if err := json.NewDecoder(commitResp.Body).Decode(&commits); err == nil && len(commits) > 0 {
			gitName := commits[0].Commit.Author.Name
			nameToLogin[gitName] = c.Login
		}
		commitResp.Body.Close()
	}

	printf("Resolved %d GitHub profile links from API\n", len(nameToLogin))
	return nameToLogin, emailToLogin
}

// Contrib generates the contributors page from git history.
// The output is written to website/content/contributors.md.
func (Website) Contrib(ctx context.Context) error {
	printf("Generating contributors page from git history...\n")

	// Get all commits in a single pass: name<tab>email<tab>date
	output, err := sh.Output("git", "log", "--format=%aN\t%aE\t%ai", "--all")
	if err != nil {
		return fmt.Errorf("failed to read git log: %w", err)
	}

	// Count commits per canonical name, track emails and date range
	type info struct {
		commits int
		emails  map[string]bool
		first   string
		last    string
	}
	contributors := map[string]*info{}

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "\t", 3)
		if len(parts) != 3 {
			continue
		}
		name, email, date := parts[0], parts[1], parts[2]
		if len(date) >= 10 {
			date = date[:10]
		}

		if botNames[name] {
			continue
		}

		canonical := name
		if alias, ok := emailAliases[email]; ok {
			canonical = alias
		}

		c, ok := contributors[canonical]
		if !ok {
			c = &info{emails: map[string]bool{}, first: date, last: date}
			contributors[canonical] = c
		}
		c.commits++
		c.emails[email] = true
		if date < c.first {
			c.first = date
		}
		if date > c.last {
			c.last = date
		}
	}

	// Fetch GitHub username mappings from API
	nameLogins, emailLogins := githubContributorLogins("ghostunnel/ghostunnel")

	// Build sorted list
	var list []contributor
	for name, c := range contributors {
		display := name
		// Try to link to GitHub profile: check API name mapping, then email mapping,
		// then fall back to parsing noreply emails from git log
		if login, ok := nameLogins[name]; ok {
			display = fmt.Sprintf("[%s](https://github.com/%s)", name, login)
		} else {
			for email := range c.emails {
				if login, ok := emailLogins[email]; ok {
					display = fmt.Sprintf("[%s](https://github.com/%s)", name, login)
					break
				}
				if strings.HasSuffix(email, "@users.noreply.github.com") {
					user := strings.SplitN(email, "@", 2)[0]
					if idx := strings.Index(user, "+"); idx >= 0 {
						user = user[idx+1:]
					}
					display = fmt.Sprintf("[%s](https://github.com/%s)", name, user)
					break
				}
			}
		}
		list = append(list, contributor{
			Name:    name,
			Display: display,
			Commits: c.commits,
			First:   c.first,
			Last:    c.last,
		})
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].Commits > list[j].Commits
	})

	// Compute total commits
	totalCommits := 0
	for _, c := range list {
		totalCommits += c.Commits
	}

	// Render template from docs/contributors.md.tmpl
	tmplBytes, err := os.ReadFile("docs/contributors.md.tmpl")
	if err != nil {
		return fmt.Errorf("failed to read template: %w", err)
	}
	tmpl := template.Must(template.New("contributors").Parse(string(tmplBytes)))

	if err := os.MkdirAll("website/content", 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	f, err := os.Create("website/content/contributors.md")
	if err != nil {
		return fmt.Errorf("failed to create contributors.md: %w", err)
	}
	defer f.Close()

	data := struct {
		Contributors []contributor
		Total        int
		Commits      int
		Generated    string
	}{list, len(list), totalCommits, time.Now().UTC().Format("January 2, 2006 15:04 UTC")}

	if err := tmpl.Execute(f, data); err != nil {
		return fmt.Errorf("failed to render template: %w", err)
	}

	printf("Generated contributors page: %d contributors, %d commits\n", len(list), totalCommits)
	return nil
}

// Build generates the contributors page and builds the Hugo site.
// Requires Hugo to be installed.
func (Website) Build(ctx context.Context) error {
	mg.CtxDeps(ctx, Website.Contrib)
	return sh.Run("hugo", "--source", "website", "--minify")
}

// Serve generates the contributors page and starts the Hugo dev server.
// Requires Hugo to be installed.
func (Website) Serve(ctx context.Context) error {
	mg.CtxDeps(ctx, Website.Build)
	return sh.RunV("hugo", "server", "--source", "website")
}
