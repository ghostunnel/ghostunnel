# AGENTS.md

This file provides guidance to agents when working with code in this repository.

## Project Overview

Ghostunnel is a TLS proxy with mutual authentication support for securing non-TLS backend applications. It operates in two modes:
- **Server mode**: Accepts TLS connections and proxies to insecure backends (TCP or UNIX sockets)
- **Client mode**: Accepts insecure connections and proxies to TLS-secured services

## Build Commands

This project uses [mage](https://magefile.org) as the build system:

```bash
# Build the binary
mage go:build

# Run all tests (unit + integration)
mage test:all

# Run only unit tests
mage test:unit

# Run only integration tests (requires Python 3.5+)
mage test:integration

# Run tests in Docker (includes PKCS#11 tests with SoftHSM)
mage test:docker

# Generate test certificates for development
mage test:keys

# View coverage
go tool cover -html coverage/all.profile

# Build Docker images
mage docker:build

# List all available targets
mage -l
```

### Running a Single Test

For unit tests:
```bash
go test -v -run TestName ./...
go test -v ./auth/...  # Run all tests in a package
```

For integration tests (Python):
```bash
cd tests && python3 test-name.py
```

### Linting

```bash
golangci-lint run
```

The project uses golangci-lint with configuration in `.golangci.yml`. Standard linters are enabled with exclusions for common error handling patterns.

## Architecture

### Package Structure

- **main** (`main.go`, `doc.go`): Entry point, CLI flag parsing (using kingpin), mode dispatch (server/client)
- **auth**: Authorization via X.509 certificate validation (CN, OU, DNS SAN, URI SAN, IP SAN checks)
- **certloader**: Certificate loading abstractions supporting PEM files, PKCS#12 keystores, PKCS#11 HSMs, SPIFFE Workload API, ACME, and macOS/Windows keychain
- **proxy**: Connection forwarding with configurable timeouts, connection limits, and PROXY protocol support
- **policy**: Open Policy Agent (OPA) integration for declarative access control policies
- **socket**: Network socket utilities including systemd/launchd socket activation
- **wildcard**: Pattern matching for URI-based access control
- **certstore**: Platform-specific keychain integration (macOS/Windows)

### Key Design Patterns

1. **TLSConfigSource interface**: Abstracts certificate sources (files, SPIFFE, ACME, keychain) behind a common interface for hot-reloading
2. **Conditional compilation**: Platform-specific features (PKCS#11, keychain, Landlock) use build tags (`pkcs11_enabled.go`/`pkcs11_disabled.go`)
3. **Signal handling**: SIGHUP triggers certificate reload; SIGTERM/SIGINT trigger graceful shutdown

### Testing

- Unit tests: Go standard testing in `*_test.go` files
- Integration tests: Python scripts in `tests/` directory using `tests/common.py` helper module
- Test certificates are generated in `test-keys/` via `mage test:keys`

## Key Flags

Server mode requires access control: `--allow-all`, `--allow-cn`, `--allow-ou`, `--allow-dns`, `--allow-uri`, `--allow-policy`, or `--disable-authentication`

Certificate sources are mutually exclusive: `--keystore`, `--cert/--key`, `--keychain-identity`, `--use-workload-api`, `--auto-acme-cert`

Safe addresses (localhost, 127.0.0.1, [::1], unix:, systemd:, launchd:) don't require `--unsafe-target` or `--unsafe-listen`
