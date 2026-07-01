# Documentation Proofreading Report

A review of `README.md`, `CONTRIBUTING.md`, and everything under `docs/`
(excluding the generated man pages and historical release notes). Factual
claims were cross-checked against the code (`main.go`, `signals.go`,
`certloader/`, `auth/`, `proxy/`, `magefile.go`, Dockerfiles).

Overall the documentation is in very good shape: examples use file names that
`mage test:keys` actually generates, flag defaults match the code, metric
names match `proxy/proxy.go`, the ACME retry/backoff description matches
`certloader/acmetlsconfig.go`, exit codes match `signals.go`, the Docker base
images match the Dockerfiles, and all internal links and Hugo `ref` targets
resolve. The findings below are ordered by importance.

## 1. Accuracy issues (verified against code)

### 1.1 OPA policy flags are *mutually exclusive* with other access-control flags in server mode, but the docs present this as a recommendation

`docs/security/access-flags.md`:

* The "Server mode" section opens with "When multiple access control flags
  are specified, they are OR'd together" (line 17) and then lists
  `--allow-policy`/`--allow-query` among those flags, implying they can be
  combined.
* The "Open Policy Agent" section (line 140) says: "When using OPA, we
  recommend expressing all access control logic in the policy itself and not
  combining it with other access control flags."

In reality, combining `--allow-policy`/`--allow-query` with any `--allow-*`
flag in server mode is a hard error, not a discouraged option
(`main.go:401-403`: "--allow-policy and --allow-query are mutually exclusive
with other access control flags"). In *client* mode, however,
`--verify-policy` **can** be combined with the other `--verify-*` flags and
is OR'd with them (`auth/auth.go`, `VerifyPeerCertificateClient`).

**Suggested fix:** in the OPA section, replace the "we recommend not
combining" sentence with a precise statement, e.g.:

> In server mode, `--allow-policy`/`--allow-query` are mutually exclusive
> with the other access control flags — combining them is an error. In
> client mode, `--verify-policy`/`--verify-query` may be combined with other
> verification flags and are OR'd together with them, though we recommend
> expressing all access control logic in the policy itself.

Also consider a parenthetical in the server-mode intro noting that the OR
semantics apply to the certificate-field flags (`--allow-cn/ou/dns/uri`),
while `--allow-all`, `--allow-policy`, and `--disable-authentication` are
each mutually exclusive with the rest. (`docs/getting-started/flags.md`
already gets this right for `--allow-policy`.)

### 1.2 `--status` also accepts `systemd:NAME` / `launchd:NAME` and an `http(s)://` prefix

The flag help in `main.go:151` reads: "Enable serving /_status and /_metrics
on given [http(s)://]HOST:PORT, unix:PATH, systemd:NAME or launchd:NAME."
The README's Socket Activation section correctly says socket activation
works for `--listen` **and** `--status`. But:

* `docs/getting-started/flags.md` line 81 describes `--status` as only
  "given HOST:PORT (or `unix:SOCKET`)".
* `docs/networking/graceful-shutdown.md` line 78 likewise says
  "HOST:PORT (or `unix:SOCKET`)".

**Suggested fix:** update both tables to
`[http(s)://]HOST:PORT`, `unix:PATH`, `systemd:NAME`, or `launchd:NAME`.
The `http://` prefix in particular is documented only at the very bottom of
`docs/networking/metrics.md`, so surfacing it in the flag table helps.

### 1.3 `formats.md` contradicts itself (and the code) about keystore auto-detection

`docs/certificates/formats.md`:

* Line 8 (intro): format "is auto-detected from the file extension **or by
  inspecting the first few bytes**" — correct.
* Lines 141-143 ("Format Auto-Detection" section): "Ghostunnel detects the
  format of `--keystore` based on file extension" — incomplete, and
  contradicts the intro.

The code (`certloader/decode.go:64-97`) tries the file extension first and
falls back to sniffing magic bytes (PEM, JCEKS, PKCS#12/DER) when the
extension is unrecognized.

**Suggested fix:** make the "Format Auto-Detection" section match the intro:
extension first (`.pem`, `.crt`, `.p12`, `.pfx`, `.jceks`, `.jks`, …), magic
bytes as fallback. The statement that `--cert`/`--key` are always parsed as
PEM remains correct.

### 1.4 README omits JCEKS as a `--keystore` format

`README.md` lines 128-131 say `--keystore` takes "a PKCS#12 keystore or a
combined PEM file". JCEKS/JKS keystores are also supported (documented in
`docs/certificates/formats.md` and implemented in `certloader/jceks/`).
The `--keystore` row in `docs/getting-started/flags.md` (line 22) has the
same omission, even though its own `--storepass` row mentions JCEKS one line
below.

**Suggested fix:** mention JCEKS in both places, e.g. "…or a combined PEM
file… JCEKS/JKS keystores are also supported for legacy use cases."

## 2. Wording and grammar

### 2.1 `docs/security/access-flags.md`

* Line 78: "can redirect verification **at** a different name" → "redirect
  verification **to** a different name" (or "point verification at").
* Lines 77/90/92: inconsistent US/UK spelling within the same page —
  "dialing" (line 77) vs. "dialling" (line 90) and "dialled" (line 78).
  The rest of the docs use US spelling; suggest "dialing"/"dialed".
* Line 38: "Matches the DNS SAN value on the certificate, no DNS lookups are
  performed" — comma splice; use a semicolon or parentheses.

### 2.2 US/UK spelling consistency elsewhere

* `README.md:376`: "signalling" → "signaling".
* `docs/networking/graceful-shutdown.md:67`: "cancelled" → "canceled".

(Only worth fixing if you want consistent US English, which the rest of the
docs use.)

### 2.3 `docs/certificates/spiffe-workload-api.md`

* Lines 51-56: the paragraph ends "Use `--verify-uri` to pin the expected
  SPIFFE ID:" — but the example that immediately follows is the **server**
  example (`--allow-uri`), not the client one. Suggest ending the paragraph
  with a period and introducing the examples separately, or reordering so
  the client example follows the sentence about `--verify-uri`.
* Lines 35-42: the Windows example is in a ` ```bash ` code fence but is a
  Windows command; use `powershell` (as `windows-service.md` does). Also
  double-check the doubled backslashes in
  `npipe:spire-agent\\public\\api` — in PowerShell/cmd the address would be
  typed with single backslashes (`npipe:spire-agent\public\api`); the `\\`
  escaping only applies to POSIX shells.

### 2.4 `docs/networking/metrics.md`

* Line 59: the comment above the `go tool pprof … /debug/pprof/profile`
  example says "Analyze execution trace", but `/debug/pprof/profile` is a
  CPU profile (the execution trace endpoint is `/debug/pprof/trace`).
  Suggest "Analyze CPU profile using pprof tool".
* Line 186: trailing whitespace after "drop the" breaks the sentence across
  lines awkwardly; also missing blank line before the paragraph after the
  YAML block (renders fine, but inconsistent with the rest of the page).

### 2.5 `docs/networking/proxy-protocol.md`

* Line 11: "from Ghostunnel itself -- it does not know" — uses a double
  hyphen where other pages use an em dash (—). Cosmetic.

### 2.6 `docs/certificates/acme.md`

* Line 68: "the ACME CA opens a TLS handshake to port 443" — a handshake
  isn't "opened to" a port; suggest "opens a TLS connection to port 443".

## 3. Improvements to consider

### 3.1 `docs/deployment/systemd.md`

* Both example service units use `WantedBy=default.target`. For system
  services the conventional target is `multi-user.target`;
  `default.target` is usually reserved for user units. Worth switching (or
  noting why `default.target` was chosen).
* The note about `Type=notify` on systemd < 253 says "reload via
  `systemctl reload` will not work" — it can be made to work by adding
  `ExecReload=/bin/kill -HUP $MAINPID` to the unit. Worth mentioning as the
  workaround instead of only "send SIGHUP manually".

### 3.2 `docs/getting-started/flags.md`

* The client-mode "OPA Policy" table doesn't say `--verify-policy` and
  `--verify-query` must be used together (enforced in `main.go:489-491`);
  the server section's `--allow-query` row does say "Must be used with
  `--allow-policy`". Add the same note for symmetry (and note that
  `--allow-policy` also requires `--allow-query`, not just the reverse).
* The server "Access Control" section could state the invariant from the
  README: at least one access-control flag is required in server mode, and
  `--allow-all` / `--disable-authentication` are each mutually exclusive
  with the others (`main.go:354-364`).

### 3.3 `docs/deployment/windows-service.md`

* Line 8: "*Unreleased: this feature ships in the next release, v1.11.0.*"
  — reminder to remove this banner when v1.11.0 final ships (the repo
  currently has release notes only up to `v1.11.0-rc.1`).

### 3.4 README vs. `docs/deployment/docker.md` duplication

The Docker image table exists in both places (README uses column header
"Image", docker.md uses "Variant" plus a "Base" column). Not a bug, but
they'll drift; consider having the README link to the docs page and keep
just one table authoritative.

### 3.5 README man page link

`README.md:118` links only the Linux man page ("There's also a
[man page](docs/reference/manpage-linux.md)"). A Darwin man page exists at
`docs/reference/manpage-darwin.md`; consider linking both or linking the
`docs/reference/` section.

## 4. Related findings in code (doc-adjacent, not in `.md` files)

These surfaced while verifying doc claims; listed here since they produce
user-visible text that contradicts the documentation:

* `main.go:356`: the error message for missing access-control flags refers
  to `--allow-{all,cn,ou,dns-san,ip-san,uri-san}`, but the actual flag names
  are `--allow-dns` and `--allow-uri` (and `--allow-ip` is hidden). A user
  following this error message would type a nonexistent flag.
* `certloader/decode.go:88`: comment says "prefer explicit --format flags",
  but no `--format` flag exists.

## 5. Verified as correct (no action needed)

Spot-checks that all passed, for the record:

* Quickstart/README example file names (`server-cert.pem`, `server-key.pem`,
  `*-combined.pem`, `*-keystore.p12`, `server-pkcs8.pem`) match what
  `mage test:keys` generates (`magefile.go`).
* Flag defaults in `flags.md` (`5m`, `10s`, `1s`, `0s`, `0`, `30s`,
  `ghostunnel`) match `main.go`.
* `--quiet` values (`all`, `conns`, `conn-errs`, `handshake-errs`) match the
  enum in `main.go:154`.
* Environment variable table matches the `Envar(...)` declarations.
* Metric names in `metrics.md` match `proxy/proxy.go:51-58`; the
  `/_metrics?format=prometheus` behavior matches `main.go:905-913`.
* ACME startup retry (5 attempts, 5 s initial backoff, 2 min cap) matches
  `certloader/acmetlsconfig.go`.
* Graceful-shutdown exit codes (0 drained / 1 on timeout) match
  `signals.go:58-63` and `main.go:537-541`.
* Docker base images in `docker.md` (incl.
  `gcr.io/distroless/base-nossl:nonroot`) match the Dockerfiles.
* All relative links in README and all Hugo `{{< ref >}}` targets and
  anchors in `docs/` resolve.
