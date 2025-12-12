//go:build mage

package main

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/magefile/mage/mg"
	"github.com/magefile/mage/sh"
)

type Go mg.Namespace
type Git mg.Namespace
type Test mg.Namespace
type Docker mg.Namespace

var Default = Go.Build

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

// Man generates the Ghostunnel man page from the built binary.
// Also generates docs/MANPAGE.md from the man page using pandoc.
func (Go) Man(ctx context.Context) error {
	mg.CtxDeps(ctx, Go.Build)

	output, err := sh.Output("./ghostunnel", "--help-custom-man")
	if err != nil {
		return fmt.Errorf("failed to generate man page: %w", err)
	}

	if err := os.WriteFile("ghostunnel.man", []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write ghostunnel.man: %w", err)
	}

	// Generate docs/MANPAGE.md from the man page using pandoc
	if err := sh.Run("pandoc", "-f", "man", "-t", "markdown", "ghostunnel.man", "-o", "docs/MANPAGE.md"); err != nil {
		return fmt.Errorf("failed to generate docs/MANPAGE.md: %w", err)
	}

	return nil
}

// Clean removes build artifacts.
func (Git) Clean(ctx context.Context) error {
	return sh.Run("git", "clean", "-Xdf")
}

// build builds the *test* binary with coverage instrumentation.
func (Test) build() error {
	return sh.Run("go", "test", "-c", "-covermode=count", "-coverpkg", ".,./auth,./certloader,./proxy,./wildcard,./socket")
}

// All runs both unit and integration tests, then merges coverage.
func (Test) All(ctx context.Context) error {
	mg.CtxDeps(ctx, Test.Unit, Test.Integration)
	mg.CtxDeps(ctx, Test.Coverage)
	return nil
}

// Unit runs the unit tests.
func (Test) Unit(ctx context.Context) error {
	printf("Running unit tests...\n")

	if err := os.MkdirAll("coverage", 0755); err != nil {
		return fmt.Errorf("failed to create coverage directory: %w", err)
	}

	return sh.Run("go", "test", "-v", "-covermode=count", "-coverprofile=coverage/unit-test.profile", "./...")
}

// Integration runs the integration tests.
func (Test) Integration(ctx context.Context) error {
	mg.CtxDeps(ctx, Test.build)

	if err := os.MkdirAll("coverage", 0755); err != nil {
		return fmt.Errorf("failed to create coverage directory: %w", err)
	}

	// Skip integration tests on Windows
	if runtime.GOOS == "windows" {
		fmt.Fprintf(os.Stderr, "Integration tests are not supported on Windows\n")
		return nil
	}

	// Run integration tests
	testFiles, err := filepath.Glob("tests/test-*.py")
	if err != nil || len(testFiles) == 0 {
		return fmt.Errorf("failed to find test files: %w", err)
	}

	// Run each integration test directly
	printf("Running integration tests...\n")
	for _, testFile := range testFiles {
		if err := ctx.Err(); err != nil {
			return fmt.Errorf("context cancelled: %w", err)
		}

		testName := strings.TrimSuffix(filepath.Base(testFile), ".py")
		printf("=== RUN   %s\n", testName)

		// Run the Python test file directly from tests directory
		start := time.Now()
		testFileName := filepath.Base(testFile)
		cmd := exec.CommandContext(ctx, "python3", testFileName)
		cmd.Dir = "tests"

		// Capture stdout and stderr
		var stdout, stderr bytes.Buffer
		cmd.Stdout = &stdout
		cmd.Stderr = &stderr

		err := cmd.Run()
		duration := time.Since(start)
		elapsed := duration.Seconds()

		if err == nil {
			printf("=== PASS: %s (%.2fs)\n", testName, elapsed)
			continue
		}

		// Test failed - output captured stdout/stderr and failure message
		os.Stdout.Write(stdout.Bytes())
		os.Stderr.Write(stderr.Bytes())
		printf("=== FAIL: %s (%.2fs)\n", testName, elapsed)

		// Get exit code if available
		if exitError, ok := err.(*exec.ExitError); ok {
			return fmt.Errorf("integration test %s failed with exit code %d", testName, exitError.ExitCode())
		}

		return fmt.Errorf("integration test %s failed: %w", testName, err)
	}

	return nil
}

// Coverage merges the coverage files into a single file.
func (Test) Coverage(ctx context.Context) error {
	mg.CtxDeps(ctx, Test.Unit, Test.Integration)

	// Get all coverage profile files
	coverageFiles, err := filepath.Glob("coverage/*.profile")
	if err != nil || len(coverageFiles) == 0 {
		return fmt.Errorf("failed to find coverage files: %w", err)
	}

	// Merge coverage files, excluding internal/test
	args := []string{"tool", "gocovmerge"}
	args = append(args, coverageFiles...)

	mergeOutput, err := sh.Output("go", args...)
	if err != nil {
		return fmt.Errorf("failed to merge coverage: %w", err)
	}

	// Filter out internal/test lines (same as Makefile's grep -v)
	lines := strings.Split(string(mergeOutput), "\n")
	var filtered []string
	for _, line := range lines {
		if !strings.Contains(line, "internal/test") {
			filtered = append(filtered, line)
		}
	}

	// Write merged coverage
	return os.WriteFile("coverage/all.profile", []byte(strings.Join(filtered, "\n")), 0644)
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
	args := []string{"build", "-t", "ghostunnel/ghostunnel-test", "-f", "Dockerfile-test"}
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

	args = []string{"run", "-v", fmt.Sprintf("%s:/go/src/github.com/ghostunnel/ghostunnel", pwd), "ghostunnel/ghostunnel-test", "--"}
	if mg.Verbose() {
		args = append(args, "-v")
	}
	args = append(args, "test:softhsmimport", "test:all")
	return sh.Run("docker", args...)
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
	// Determine base tag (latest for master, version tag otherwise)
	baseTag, err := getDockerTag()
	if err != nil {
		return err
	}

	builds := map[string][]string{
		"Dockerfile-alpine": []string{
			fmt.Sprintf("ghostunnel/ghostunnel:%s", baseTag),
			fmt.Sprintf("ghostunnel/ghostunnel:%s-alpine", baseTag),
		},
		"Dockerfile-debian":     []string{fmt.Sprintf("ghostunnel/ghostunnel:%s-debian", baseTag)},
		"Dockerfile-distroless": []string{fmt.Sprintf("ghostunnel/ghostunnel:%s-distroless", baseTag)},
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

// getDockerTag determines the Docker tag to use based on git state.
// Returns "latest" if on master branch, otherwise returns the most recent tag.
func getDockerTag() (string, error) {
	// Check if we're on a tag (for GitHub Actions when triggered by tag push)
	// In GitHub Actions, GITHUB_REF will be set, but locally we check git
	githubRef := os.Getenv("GITHUB_REF")
	if githubRef != "" {
		// GitHub Actions: refs/heads/master or refs/tags/v1.2.3
		if strings.HasPrefix(githubRef, "refs/heads/master") {
			return "latest", nil
		}
		if strings.HasPrefix(githubRef, "refs/tags/") {
			tag := strings.TrimPrefix(githubRef, "refs/tags/")
			return tag, nil
		}
	}

	// Check current branch
	branch, err := sh.Output("git", "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return "", fmt.Errorf("failed to determine git ref: %w", err)
	}
	if strings.TrimSpace(branch) == "master" {
		return "latest", nil
	}

	// Not on master, get the most recent tag
	tag, err := sh.Output("git", "describe", "--tags", "--abbrev=0")
	if err != nil {
		return "", fmt.Errorf("failed to get git tag: %w", err)
	}

	return strings.TrimSpace(tag), nil
}
