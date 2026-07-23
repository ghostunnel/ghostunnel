# Contributing guidelines

If you would like to contribute code to Ghostunnel you can do so through GitHub
by forking the repository and sending a pull request.

When submitting code, please make efforts to follow existing conventions and
style in order to keep the code as readable as possible. Please also make sure
all tests pass by running `go tool mage test:all`, and format your code with `go fmt`.

## Go Toolchain Setup

This project requires the Go version specified in `go.mod`. If the default `go`
on PATH is older, builds will fail with a version mismatch error.

**Cloud development environments:** Some environments (such as Claude Code on
the web) install multiple Go versions side-by-side under `/usr/local/`. The
default `/usr/local/go/` may be older than what this project requires. Check
for a matching version (e.g. `/usr/local/go<VERSION>/bin/go`) and prepend it
to your PATH:

```bash
# Find available Go versions
ls /usr/local/go*/bin/go

# Use the version that matches go.mod (check with: grep '^go ' go.mod)
export PATH="/usr/local/go<VERSION>/bin:$PATH"
go version
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
go tool mage test:race             # Go unit tests under the race detector
go tool mage test:integration      # Python integration tests only
go tool mage test:docker           # Full suite in Docker (includes PKCS#11/SoftHSM)
go tool mage test:keys             # Generate test certificates in test-keys/
go tool mage test:bench            # Go microbenchmarks with allocation stats
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
go tool mage go:lint
```

### Benchmarks

To run benchmarks, you can use the test:bench target in mage:

```bash
go tool mage test:bench > /tmp/bench-head.txt        # on your branch
git checkout master
go tool mage test:bench > /tmp/bench-base.txt        # on the base
benchstat /tmp/bench-base.txt /tmp/bench-head.txt
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

1. **Go** at the version specified in `go.mod` on PATH (see "Go Toolchain Setup" above).
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

The integration test runner first builds a coverage-instrumented binary with
`go build -cover -tags coverage`. Each Python test starts that binary with
`GOCOVERDIR` pointing at a per-run directory; the `coverage` build tag (see
`coverage_enabled.go`) flushes counters on exit so data survives
signal-triggered shutdowns. After the run, `go tool covdata textfmt` converts
the binary coverage data to a text profile, which is then merged with the
unit-test profile.

## Architecture Overview

### Key Packages

- **main** (`main.go`): CLI flags, server/client mode dispatch, signal handling
- **certloader**: Certificate abstraction (`TLSConfigSource` interface) supporting PEM, PKCS#12, JCEKS, PKCS#11, SPIFFE, ACME, macOS/Windows keychain — with hot-reload
- **auth**: Access control via X.509 cert fields (CN, OU, DNS/URI/IP SAN)
- **proxy**: Connection forwarding, connection limits (semaphore), PROXY protocol v2
- **policy**: OPA integration for declarative access control
- **socket**: TCP/UNIX socket binding, systemd/launchd socket activation
- **wildcard**: Glob-style URI pattern matching
- **certstore**: Platform-specific keychain (macOS/Windows)
- **Conditional compilation**: Platform-specific features use build tags (e.g., `pkcs11_enabled.go`/`pkcs11_disabled.go`, `landlock_linux.go`/`landlock_other.go`)

## Logging and Error Message Conventions

### Log messages

- Use lowercase (proper nouns such as Windows and SPIFFE are excepted).
- No trailing `\n` in messages, as `log.Logger` appends one automatically.
- Severity prefixes: only `error:`, `warning:`, or `note:`; message text after prefix stays lowercase.
- Format error values with `%v`, not `%s`. This applies only for logging, fmt.Errorf should use `%w`.

### Returned errors

- Lowercase, no trailing punctuation.
- Never embed the word "error" in the message text (e.g. `"unable to open file"`, not `"error opening file"`).
- Preferred verb style: **"unable to X"** — avoid "failed to X", "could not X", "couldn't X".
- Wrap causes with `%w`; quote paths, names, and user input with `%q`.
- Use `errors.New` when there is nothing to format.
- Use sentinel error variables (`var ErrFoo = ...`) for errors that are repeated or compared with `errors.Is`.
- Bare gerund context wraps are acceptable: `fmt.Errorf("reading alias: %w", err)` is idiomatic Go and does not need to be rewritten as `"unable to read alias: %w"`.

### Fatal startup errors

Fatal startup errors are reported once, by `main()`, not logged at each failure site.

### Fixed log strings

The following substrings appear in Python integration tests and **must not be reworded** without updating the corresponding tests in lockstep:

- `"opening pipe"`, `"closed pipe"`, `"error during copy"`, `"error on dial"`, `"error on TLS handshake"`, `"listening"`, `"reloading"`
