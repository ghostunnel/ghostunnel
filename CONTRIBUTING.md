# Contributing guidelines

If you would like to contribute code to Ghostunnel you can do so through GitHub
by forking the repository and sending a pull request.

When submitting code, please make efforts to follow existing conventions and
style in order to keep the code as readable as possible. Please also make sure
all tests pass by running `mage test:all`, and format your code with `go fmt`.

## Go Toolchain Setup

This project requires Go 1.25.1+ (see `go.mod`). The default Go on PATH may be
an older version (e.g. 1.24.x) which will fail with a version mismatch error.
Multiple Go versions are installed side-by-side under `/usr/local/`:

```
/usr/local/go/         → default (may be older)
/usr/local/go1.25.1/   → required by this project
```

To use the correct version, prepend it to your PATH before running any Go or
mage commands:

```bash
export PATH="/usr/local/go1.25.1/bin:$PATH"
go version   # should print: go version go1.25.1 linux/amd64
```

Mage is available as a Go tool dependency (no separate install needed):

```bash
go tool mage -l   # list all targets
```

## Build & Test Commands

This project uses [mage](https://magefile.org) as the build system (defined in `magefile.go`).
Invoke it via `go tool mage` (not a standalone `mage` binary):

```bash
go tool mage go:build              # Build binary
go tool mage go:lint               # Run golangci-lint (config: .golangci.yml)
go tool mage test:all              # Unit + integration tests with merged coverage
go tool mage test:unit             # Go unit tests only
go tool mage test:integration      # Python integration tests only
go tool mage test:docker           # Full suite in Docker (includes PKCS#11/SoftHSM)
go tool mage test:keys             # Generate test certificates in test-keys/
go tool mage docker:build          # Build Docker images
go tool mage -l                    # List all available targets
```

### Running a Single Test

```bash
go test -v -run TestName ./...                   # Single Go unit test
go test -v ./auth/...                            # All tests in a package
go tool mage test:single test-server-pem-rsa     # Single integration test (via mage)
cd tests && python3 test-server-pem-rsa.py       # Single integration test (directly)
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

### Prerequisites

1. **Go 1.25.1+** on PATH (see "Go Toolchain Setup" above).
2. **Python 3** with packages used by the test harness (typically already available).
3. **Test certificates** must be generated before the first run:

```bash
go tool mage test:keys        # generates certs in test-keys/
```

### Running Integration Tests

```bash
go tool mage test:integration                              # all integration tests
go tool mage test:single test-server-pem-rsa               # single test by name
GHOSTUNNEL_TEST_PARALLEL=4 go tool mage test:integration   # control parallelism
```

Integration tests run in parallel by default (up to `NumCPU`, capped at 16).
Set `GHOSTUNNEL_TEST_PARALLEL` to control the number of concurrent tests (may exceed the default cap).

The integration test runner first builds a coverage-instrumented test binary
(`go test -c`), then runs each `tests/test-*.py` script against that binary.
Each Python test starts a ghostunnel process, exercises it, and verifies behavior.

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
