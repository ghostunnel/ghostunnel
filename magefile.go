//go:build mage

package main

import (
	"bytes"
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

// Build builds the ghostunnel binary with version injection.
// Version can be overridden by setting the VERSION environment variable.
func Build() error {
	version := os.Getenv("VERSION")
	if version == "" {
		var err error
		version, err = getVersion()
		if err != nil {
			return fmt.Errorf("failed to get version: %w", err)
		}
	}

	// Build the binary
	if err := runWithOutput("go", "build", "-ldflags", fmt.Sprintf("-X main.version=%s", version), "-o", "ghostunnel", "."); err != nil {
		return fmt.Errorf("failed to build binary: %w", err)
	}

	return nil
}

// ManPage generates the ghostunnel man page from the built binary.
// Requires the binary to be built first (via Build target).
func ManPage() error {
	mg.Deps(Build)

	// Generate man page
	output, err := sh.Output("./ghostunnel", "--help-custom-man")
	if err != nil {
		return fmt.Errorf("failed to generate man page: %w", err)
	}

	if err := os.WriteFile("ghostunnel.man", []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write man page: %w", err)
	}

	return nil
}

// testBinary builds the test binary with coverage instrumentation.
// This is an internal function used by Test() and is not exposed as a mage target.
func testBinary() error {
	return runWithOutput("go", "test", "-c", "-covermode=count", "-coverpkg", ".,./auth,./certloader,./proxy,./wildcard,./socket")
}

// Test runs both unit and integration tests, then merges coverage.
func Test() error {
	// Create coverage directory
	if err := os.MkdirAll("coverage", 0755); err != nil {
		return fmt.Errorf("failed to create coverage directory: %w", err)
	}

	// Remove old coverage files to avoid conflicts
	// Use filepath.Glob to expand the pattern cross-platform (Windows doesn't handle * in paths)
	oldCoverageFiles, err := filepath.Glob("coverage/*.profile")
	if err != nil {
		return fmt.Errorf("failed to find old coverage files: %w", err)
	}
	for _, file := range oldCoverageFiles {
		if err := sh.Rm(file); err != nil {
			return fmt.Errorf("failed to remove old coverage file %s: %w", file, err)
		}
	}

	// Run unit tests
	fmt.Println("Running unit tests...")
	if err := runWithOutput("go", "test", "-v", "-covermode=count", "-coverprofile=coverage/unit-test.profile", "./..."); err != nil {
		return fmt.Errorf("unit tests failed: %w", err)
	}

	// Skip integration tests on Windows
	if runtime.GOOS == "windows" {
		fmt.Println("Skipping integration tests on Windows...")
	} else {
		// Build test binary for integration tests
		if err := testBinary(); err != nil {
			return fmt.Errorf("failed to build test binary: %w", err)
		}

		// Run integration tests
		fmt.Println("Running integration tests...")
		testFiles, err := filepath.Glob("tests/test-*.py")
		if err != nil {
			return fmt.Errorf("failed to find test files: %w", err)
		}

		if len(testFiles) == 0 {
			return fmt.Errorf("no integration test files found")
		}

		// Run each integration test directly
		for _, testFile := range testFiles {
			testName := strings.TrimSuffix(filepath.Base(testFile), ".py")
			fmt.Printf("=== RUN   %s\n", testName)

			// Run the Python test file directly (from tests directory, like runner.py did)
			start := time.Now()
			testFileName := filepath.Base(testFile)
			cmd := exec.Command("python3", testFileName)
			cmd.Dir = "tests"

			// Capture stdout and stderr
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Run()
			duration := time.Since(start)
			elapsed := duration.Seconds()

			if err == nil {
				// Test passed
				fmt.Printf("=== PASS: %s (%.2fs)\n", testName, elapsed)
			} else {
				// Test failed - output captured stdout/stderr and failure message
				os.Stdout.Write(stdout.Bytes())
				os.Stderr.Write(stderr.Bytes())
				fmt.Printf("=== FAIL: %s (%.2fs)\n", testName, elapsed)

				// Get exit code if available
				if exitError, ok := err.(*exec.ExitError); ok {
					return fmt.Errorf("integration test %s failed with exit code %d", testName, exitError.ExitCode())
				}
				return fmt.Errorf("integration test %s failed: %w", testName, err)
			}
		}
	}

	// Merge coverage files
	gocovmergePath, err := ensureGocovmerge()
	if err != nil {
		return fmt.Errorf("failed to ensure gocovmerge: %w", err)
	}

	// Get all coverage profile files
	coverageFiles, err := filepath.Glob("coverage/*.profile")
	if err != nil {
		return fmt.Errorf("failed to find coverage files: %w", err)
	}

	if len(coverageFiles) == 0 {
		return fmt.Errorf("no coverage files found")
	}

	// Merge coverage files, excluding internal/test
	mergeOutput, err := sh.Output(gocovmergePath, coverageFiles...)
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
	output := strings.Join(filtered, "\n")
	if err := os.WriteFile("coverage/all.profile", []byte(output), 0644); err != nil {
		return fmt.Errorf("failed to write merged coverage: %w", err)
	}

	fmt.Println("PASS")
	return nil
}

// Clean removes build artifacts.
func Clean() error {
	paths := []string{"ghostunnel", "ghostunnel.man", "coverage", "ghostunnel.test", "test-keys", "tests/__pycache__"}
	for _, path := range paths {
		if err := sh.Rm(path); err != nil {
			return fmt.Errorf("failed to remove %s: %w", path, err)
		}
	}
	return nil
}

// TestKeys generates test certificates and keys for development/testing purposes.
// These should NOT be used in production. The keys are generated in the test-keys directory.
func TestKeys() error {
	// Create test-keys directory
	if err := os.MkdirAll("test-keys", 0755); err != nil {
		return fmt.Errorf("failed to create test-keys directory: %w", err)
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
		return fmt.Errorf("failed to write openssl.ext: %w", err)
	}

	// Generate root key
	if err := runWithOutput("openssl", "genrsa", "-out", "test-keys/root-key.pem", "2048"); err != nil {
		return fmt.Errorf("failed to generate root key: %w", err)
	}

	// Generate root CSR
	if err := runWithOutput("openssl", "req", "-new", "-key", "test-keys/root-key.pem", "-out", "test-keys/root-csr.pem", "-subj", "/CN=root"); err != nil {
		return fmt.Errorf("failed to generate root CSR: %w", err)
	}

	// Generate root certificate
	if err := runWithOutput("openssl", "x509", "-req", "-sha256", "-in", "test-keys/root-csr.pem", "-signkey", "test-keys/root-key.pem", "-out", "test-keys/root-cert.pem", "-days", "5000", "-extfile", "test-keys/openssl.ext", "-extensions", "root"); err != nil {
		return fmt.Errorf("failed to generate root certificate: %w", err)
	}

	// Create root combined file
	rootCert, err := os.ReadFile("test-keys/root-cert.pem")
	if err != nil {
		return fmt.Errorf("failed to read root certificate: %w", err)
	}
	rootKey, err := os.ReadFile("test-keys/root-key.pem")
	if err != nil {
		return fmt.Errorf("failed to read root key: %w", err)
	}
	rootCombined := append(rootCert, rootKey...)
	if err := os.WriteFile("test-keys/root-combined.pem", rootCombined, 0644); err != nil {
		return fmt.Errorf("failed to write root combined file: %w", err)
	}

	// Copy root-cert.pem to cacert.pem (reuse rootCert already read)
	if err := os.WriteFile("test-keys/cacert.pem", rootCert, 0644); err != nil {
		return fmt.Errorf("failed to write cacert.pem: %w", err)
	}

	// Generate server key
	if err := runWithOutput("openssl", "genrsa", "-out", "test-keys/server-key.pem", "2048"); err != nil {
		return fmt.Errorf("failed to generate server key: %w", err)
	}

	// Generate server CSR
	if err := runWithOutput("openssl", "req", "-new", "-key", "test-keys/server-key.pem", "-out", "test-keys/server-csr.pem", "-subj", "/CN=server"); err != nil {
		return fmt.Errorf("failed to generate server CSR: %w", err)
	}

	// Generate server certificate
	if err := runWithOutput("openssl", "x509", "-req", "-sha256", "-in", "test-keys/server-csr.pem", "-CA", "test-keys/root-combined.pem", "-CAkey", "test-keys/root-combined.pem", "-CAcreateserial", "-out", "test-keys/server-cert.pem", "-days", "5000", "-extfile", "test-keys/openssl.ext", "-extensions", "server"); err != nil {
		return fmt.Errorf("failed to generate server certificate: %w", err)
	}

	// Create server combined file
	serverCert, err := os.ReadFile("test-keys/server-cert.pem")
	if err != nil {
		return fmt.Errorf("failed to read server certificate: %w", err)
	}
	serverKey, err := os.ReadFile("test-keys/server-key.pem")
	if err != nil {
		return fmt.Errorf("failed to read server key: %w", err)
	}
	serverCombined := append(serverCert, serverKey...)
	if err := os.WriteFile("test-keys/server-combined.pem", serverCombined, 0644); err != nil {
		return fmt.Errorf("failed to write server combined file: %w", err)
	}

	// Generate server PKCS#12 keystore
	if err := runWithOutput("openssl", "pkcs12", "-export", "-out", "test-keys/server-keystore.p12", "-in", "test-keys/server-combined.pem", "-inkey", "test-keys/server-combined.pem", "-passout", "pass:"); err != nil {
		return fmt.Errorf("failed to generate server keystore: %w", err)
	}

	// Generate server PKCS#8 key
	if err := runWithOutput("openssl", "pkcs8", "-topk8", "-inform", "PEM", "-outform", "PEM", "-in", "test-keys/server-key.pem", "-out", "test-keys/server-pkcs8.pem", "-nocrypt"); err != nil {
		return fmt.Errorf("failed to generate server PKCS#8 key: %w", err)
	}

	// Generate client key
	if err := runWithOutput("openssl", "genrsa", "-out", "test-keys/client-key.pem", "2048"); err != nil {
		return fmt.Errorf("failed to generate client key: %w", err)
	}

	// Generate client CSR
	if err := runWithOutput("openssl", "req", "-new", "-key", "test-keys/client-key.pem", "-out", "test-keys/client-csr.pem", "-subj", "/CN=client"); err != nil {
		return fmt.Errorf("failed to generate client CSR: %w", err)
	}

	// Generate client certificate
	if err := runWithOutput("openssl", "x509", "-req", "-sha256", "-in", "test-keys/client-csr.pem", "-CA", "test-keys/root-combined.pem", "-CAkey", "test-keys/root-combined.pem", "-CAcreateserial", "-out", "test-keys/client-cert.pem", "-days", "5000", "-extfile", "test-keys/openssl.ext", "-extensions", "client"); err != nil {
		return fmt.Errorf("failed to generate client certificate: %w", err)
	}

	// Create client combined file
	clientCert, err := os.ReadFile("test-keys/client-cert.pem")
	if err != nil {
		return fmt.Errorf("failed to read client certificate: %w", err)
	}
	clientKey, err := os.ReadFile("test-keys/client-key.pem")
	if err != nil {
		return fmt.Errorf("failed to read client key: %w", err)
	}
	clientCombined := append(clientCert, clientKey...)
	if err := os.WriteFile("test-keys/client-combined.pem", clientCombined, 0644); err != nil {
		return fmt.Errorf("failed to write client combined file: %w", err)
	}

	// Generate client PKCS#12 keystore
	if err := runWithOutput("openssl", "pkcs12", "-export", "-out", "test-keys/client-keystore.p12", "-in", "test-keys/client-combined.pem", "-inkey", "test-keys/client-combined.pem", "-passout", "pass:"); err != nil {
		return fmt.Errorf("failed to generate client keystore: %w", err)
	}

	// Generate client PKCS#8 key
	if err := runWithOutput("openssl", "pkcs8", "-topk8", "-inform", "PEM", "-outform", "PEM", "-in", "test-keys/client-key.pem", "-out", "test-keys/client-pkcs8.pem", "-nocrypt"); err != nil {
		return fmt.Errorf("failed to generate client PKCS#8 key: %w", err)
	}

	// Clean up temporary files
	for _, pattern := range []string{"test-keys/*.srl", "test-keys/*-csr.pem"} {
		if err := sh.Rm(pattern); err != nil {
			return fmt.Errorf("failed to remove temporary files: %w", err)
		}
	}

	fmt.Println("Test keys generated successfully in test-keys/ directory")
	return nil
}

// SoftHSMImport initializes a SoftHSM token and imports the test server key.
// Automatically generates test keys if they don't exist (via TestKeys dependency).
// Environment variables can be used to configure SoftHSM:
//   - GHOSTUNNEL_TEST_PKCS11_LABEL: Token label (default: "ghostunnel-pkcs11-test")
//   - GHOSTUNNEL_TEST_PKCS11_PIN: Token PIN (default: "1234")
//   - SOFTHSM2_CONF: SoftHSM config file path (default: "/etc/softhsm/softhsm2.conf")
func SoftHSMImport() error {
	mg.Deps(TestKeys)

	// Get configuration from environment variables
	label := os.Getenv("GHOSTUNNEL_TEST_PKCS11_LABEL")
	pin := os.Getenv("GHOSTUNNEL_TEST_PKCS11_PIN")
	if label == "" || pin == "" {
		return fmt.Errorf("GHOSTUNNEL_TEST_PKCS11_LABEL and GHOSTUNNEL_TEST_PKCS11_PIN must be set")
	}

	// Initialize SoftHSM token
	fmt.Printf("Initializing SoftHSM token with label: %s\n", label)
	if err := runWithOutput("softhsm2-util", "--init-token", "--slot", "0",
		"--label", label,
		"--so-pin", pin,
		"--pin", pin); err != nil {
		return fmt.Errorf("failed to initialize SoftHSM token: %w", err)
	}

	// Import server key into SoftHSM
	fmt.Printf("Importing server key into SoftHSM token\n")
	if err := runWithOutput("softhsm2-util", "--id", "01",
		"--token", label,
		"--label", label,
		"--so-pin", pin,
		"--pin", pin,
		"--import", "test-keys/server-pkcs8.pem"); err != nil {
		return fmt.Errorf("failed to import key into SoftHSM: %w", err)
	}

	fmt.Println("SoftHSM token initialized and key imported successfully")
	return nil
}

// DockerTest builds and runs tests in a Docker container.
// Output is streamed in real-time as the container runs.
func DockerTest() error {
	if err := runWithOutput("docker", "build", "-t", "ghostunnel/ghostunnel-test", "-f", "Dockerfile-test", "."); err != nil {
		return fmt.Errorf("failed to build test image: %w", err)
	}

	pwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to get current directory: %w", err)
	}

	// Run docker with output streaming to stdout/stderr in real-time
	cmd := exec.Command("docker", "run", "-v", fmt.Sprintf("%s:/go/src/github.com/ghostunnel/ghostunnel", pwd), "ghostunnel/ghostunnel-test")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("docker test run failed: %w", err)
	}

	return nil
}

// getAlpineTags returns the appropriate tags for the alpine Docker image based on the base tag.
func getAlpineTags(baseTag string) []string {
	if baseTag == "latest" {
		return []string{
			"ghostunnel/ghostunnel:latest",
			"ghostunnel/ghostunnel:latest-alpine",
		}
	}
	return []string{
		fmt.Sprintf("ghostunnel/ghostunnel:%s", baseTag),
		fmt.Sprintf("ghostunnel/ghostunnel:%s-alpine", baseTag),
	}
}

// DockerBuild builds and tags all Docker containers (alpine, debian, distroless).
// Uses docker buildx for multi-platform builds. Does not push images.
func DockerBuild() error {
	platforms := "linux/amd64,linux/arm64,linux/arm/v7"

	// Determine base tag (latest for master, version tag otherwise)
	baseTag, err := getDockerTag()
	if err != nil {
		return err
	}

	// Build alpine (gets both base tag and -alpine suffix)
	if err := buildDockerImage("Dockerfile-alpine", getAlpineTags(baseTag), platforms, false); err != nil {
		return fmt.Errorf("failed to build alpine image: %w", err)
	}

	// Build debian
	debianTag := fmt.Sprintf("ghostunnel/ghostunnel:%s-debian", baseTag)
	if err := buildDockerImage("Dockerfile-debian", []string{debianTag}, platforms, false); err != nil {
		return fmt.Errorf("failed to build debian image: %w", err)
	}

	// Build distroless
	distrolessTag := fmt.Sprintf("ghostunnel/ghostunnel:%s-distroless", baseTag)
	if err := buildDockerImage("Dockerfile-distroless", []string{distrolessTag}, platforms, false); err != nil {
		return fmt.Errorf("failed to build distroless image: %w", err)
	}

	return nil
}

// DockerRelease builds and publishes all Docker containers to Docker Hub.
// Uses docker buildx for multi-platform builds and pushes images.
func DockerRelease() error {
	platforms := "linux/amd64,linux/arm64,linux/arm/v7"

	// Determine base tag (latest for master, version tag otherwise)
	baseTag, err := getDockerTag()
	if err != nil {
		return err
	}

	// Build and push alpine (gets both base tag and -alpine suffix)
	if err := buildDockerImage("Dockerfile-alpine", getAlpineTags(baseTag), platforms, true); err != nil {
		return fmt.Errorf("failed to build and push alpine image: %w", err)
	}

	// Build and push debian
	debianTag := fmt.Sprintf("ghostunnel/ghostunnel:%s-debian", baseTag)
	if err := buildDockerImage("Dockerfile-debian", []string{debianTag}, platforms, true); err != nil {
		return fmt.Errorf("failed to build and push debian image: %w", err)
	}

	// Build and push distroless
	distrolessTag := fmt.Sprintf("ghostunnel/ghostunnel:%s-distroless", baseTag)
	if err := buildDockerImage("Dockerfile-distroless", []string{distrolessTag}, platforms, true); err != nil {
		return fmt.Errorf("failed to build and push distroless image: %w", err)
	}

	return nil
}

// buildDockerImage builds a Docker image using buildx with the given Dockerfile, tags, and platforms.
// If push is true, it will push the image to the registry.
func buildDockerImage(dockerfile string, tags []string, platforms string, push bool) error {
	args := []string{"buildx", "build", "-f", dockerfile, "--platform", platforms}

	// Add all tags
	for _, tag := range tags {
		args = append(args, "-t", tag)
	}

	// Add push flag if needed
	if push {
		args = append(args, "--push")
	}

	// Add build context
	args = append(args, ".")

	return runWithOutput("docker", args...)
}

// getVersion gets the version from git describe.
func getVersion() (string, error) {
	output, err := sh.Output("git", "describe", "--always", "--dirty")
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(output), nil
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

	// Check if HEAD is a tag
	tag, err := sh.Output("git", "describe", "--tags", "--exact-match", "HEAD")
	if err == nil {
		return strings.TrimSpace(tag), nil
	}

	// Check current branch
	branch, err := sh.Output("git", "rev-parse", "--abbrev-ref", "HEAD")
	if err != nil {
		return "", fmt.Errorf("failed to determine git ref: %w", err)
	}

	if strings.TrimSpace(branch) == "master" {
		return "latest", nil
	}

	// Not on master and not on a tag, get the most recent tag
	tag, err = sh.Output("git", "describe", "--tags", "--abbrev=0")
	if err != nil {
		return "", fmt.Errorf("failed to get git tag: %w", err)
	}

	return strings.TrimSpace(tag), nil
}

// runWithOutput runs a command and captures stdout/stderr. If the command fails,
// it prints the output before returning the error. If successful, output is kept silent.
func runWithOutput(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		// Print captured output on failure
		if stdout.Len() > 0 {
			fmt.Fprintf(os.Stderr, "stdout:\n%s\n", stdout.String())
		}
		if stderr.Len() > 0 {
			fmt.Fprintf(os.Stderr, "stderr:\n%s\n", stderr.String())
		}
		return err
	}

	return nil
}

// ensureGocovmerge ensures gocovmerge is installed and returns its full path.
func ensureGocovmerge() (string, error) {
	// Check if gocovmerge is already in PATH
	if path, err := exec.LookPath("gocovmerge"); err == nil {
		return path, nil
	}

	// Try to install it
	fmt.Println("gocovmerge not found, installing...")
	if err := runWithOutput("go", "install", "github.com/wadey/gocovmerge@latest"); err != nil {
		return "", fmt.Errorf("failed to install gocovmerge: %w", err)
	}

	// Check if it's now in GOPATH/bin
	gopath := os.Getenv("GOPATH")
	if gopath == "" {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("failed to get user home directory: %w", err)
		}
		gopath = filepath.Join(homeDir, "go")
	}
	gocovmergePath := filepath.Join(gopath, "bin", "gocovmerge")
	if _, err := os.Stat(gocovmergePath); err == nil {
		return gocovmergePath, nil
	}

	// Try looking in PATH again after installation
	if path, err := exec.LookPath("gocovmerge"); err == nil {
		return path, nil
	}

	return "", fmt.Errorf("gocovmerge not found after installation")
}
