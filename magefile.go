//go:build mage

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
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
type Apple mg.Namespace
type Git mg.Namespace
type Test mg.Namespace
type Docker mg.Namespace

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
