---
title: Documentation
description: Ghostunnel documentation
weight: 10
---

Documentation for Ghostunnel, covering access control, certificate management,
metrics, and platform-specific features.

## Where to start

| I want to... | Start here |
|--------------|------------|
| See all available flags | [Command-Line Flags]({{< ref "FLAGS.md" >}}) |
| Understand cert/key file formats (PEM, PKCS#12, JCEKS) | [Certificate Formats]({{< ref "CERTIFICATES.md" >}}) |
| Set up mTLS between services | [Access Control Flags]({{< ref "ACCESS-FLAGS.md" >}}) |
| Get automatic certs from Let's Encrypt | [ACME Support]({{< ref "ACME.md" >}}) |
| Use certificates from the macOS Keychain or Windows Certificate Store | [Keychain Support]({{< ref "KEYCHAIN.md" >}}) |
| Store private keys in a hardware security module | [HSM/PKCS#11 Support]({{< ref "HSM-PKCS11.md" >}}) |
| Use SPIFFE/SPIRE for workload identity | [SPIFFE Workload API]({{< ref "SPIFFE-WORKLOAD-API.md" >}}) |
| Understand the TLS settings and security model | [Security & TLS Configuration]({{< ref "SECURITY.md" >}}) |
| Monitor connections or scrape Prometheus metrics | [Metrics & Profiling]({{< ref "METRICS.md" >}}) |
| Run Ghostunnel via systemd or launchd | [Socket Activation]({{< ref "SOCKET-ACTIVATION.md" >}}) |
| Set up systemd watchdog integration | [Systemd Watchdog]({{< ref "WATCHDOG.md" >}}) |
