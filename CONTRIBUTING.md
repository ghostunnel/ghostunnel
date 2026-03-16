# Contributing guidelines

If you would like to contribute code to Ghostunnel you can do so through GitHub
by forking the repository and sending a pull request.

When submitting code, please make efforts to follow existing conventions and
style in order to keep the code as readable as possible. Please also make sure
all tests pass by running `mage test:all`, and format your code with `go fmt`.

## Build & Test Commands

This project uses [mage](https://magefile.org) as the build system (defined in `magefile.go`):

```bash
mage go:build              # Build binary
mage go:lint               # Run golangci-lint (config: .golangci.yml)
mage test:all              # Unit + integration tests with merged coverage
mage test:unit             # Go unit tests only
mage test:integration      # Python integration tests only
mage test:docker           # Full suite in Docker (includes PKCS#11/SoftHSM)
mage test:keys             # Generate test certificates in test-keys/
mage docker:build          # Build Docker images
mage -l                    # List all available targets
```

### Running a Single Test

```bash
go test -v -run TestName ./...       # Single Go unit test
go test -v ./auth/...                # All tests in a package
cd tests && python3 test-name.py     # Single integration test
```

### Linting

The project uses golangci-lint with configuration in `.golangci.yml`:

```bash
mage go:lint
```

### Viewing Coverage

```bash
go tool cover -html coverage/all.profile
```

## Integration Tests

Ghostunnel relies heavily on integration tests written in Python that
run checks on a live instance. If you are adding new features or changing
existing behavior, please add/update the integration tests in the `tests/`
directory accordingly. The tests use the `tests/common.py` helper module.

Test certificates are generated in `test-keys/` via `mage test:keys`.

## Architecture Overview

### Key Packages

- **main** (`main.go`): CLI flags, server/client mode dispatch, signal handling
- **certloader**: Certificate abstraction (`TLSConfigSource` interface) supporting PEM, PKCS#12, PKCS#11, SPIFFE, ACME, macOS/Windows keychain — with hot-reload
- **auth**: Access control via X.509 cert fields (CN, OU, DNS/URI/IP SAN)
- **proxy**: Connection forwarding, connection limits (semaphore), PROXY protocol v2
- **policy**: OPA integration for declarative access control
- **socket**: TCP/UNIX socket binding, systemd/launchd socket activation
- **wildcard**: Glob-style URI pattern matching
- **certstore**: Platform-specific keychain (macOS/Windows)
- **Conditional compilation**: Platform-specific features use build tags (e.g., `pkcs11_enabled.go`/`pkcs11_disabled.go`, `landlock_linux.go`/`landlock_other.go`)
