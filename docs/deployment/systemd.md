---
title: Systemd (Linux)
description: Run Ghostunnel as a systemd service with socket activation, readiness notification, and watchdog support.
weight: 15
aliases:
  - /docs/watchdog/
  - /docs/socket-activation/
---

Ghostunnel integrates with systemd on Linux for service management, socket
activation, readiness notification, and automatic restart via the watchdog
timer.

## Basic Service Unit

The simplest way to run Ghostunnel under systemd is a `Type=simple` service:

```ini
[Unit]
Description=Ghostunnel
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/ghostunnel server \
    --listen=localhost:8443 \
    --target=localhost:8080 \
    --keystore=/etc/ghostunnel/server-keystore.p12 \
    --cacert=/etc/ghostunnel/cacert.pem \
    --allow-cn=client
Restart=always

[Install]
WantedBy=default.target
```

## Notify and Watchdog

*Available since v1.8.0.*

Ghostunnel supports systemd's [notify][sd-notify] and watchdog functionality.
This allows systemd to know when Ghostunnel is ready and to automatically
restart it if it becomes unresponsive.

When running as a [`Type=notify-reload`][systemd-service] service:

* **Notify**: Ghostunnel signals readiness to systemd after it has successfully
  loaded certificates and started listening. Systemd will not consider the
  service "started" until this signal is received.
* **Watchdog**: Ghostunnel periodically sends a heartbeat to systemd at the
  interval specified by `WatchdogSec`. If systemd does not receive a heartbeat
  within the configured interval, it considers the process hung and takes the
  action specified by `Restart` (typically restarting the service).
* **Reload**: When you run `systemctl reload ghostunnel`, systemd sends
  `SIGHUP` to the process, which triggers a certificate reload (same as
  sending `SIGHUP` manually).

### Example Unit File

```ini
[Unit]
Description=Ghostunnel
After=network.target

[Service]
Type=notify-reload
ExecStart=/usr/bin/ghostunnel server \
    --listen=localhost:8443 \
    --target=localhost:8080 \
    --keystore=/etc/ghostunnel/server-keystore.p12 \
    --cacert=/etc/ghostunnel/cacert.pem \
    --allow-cn=client
WatchdogSec=5
Restart=always

[Install]
WantedBy=default.target
```

### Notes

* `Type=notify-reload` requires systemd v253 or later. If you are on an older
  version, use `Type=notify` instead (reload via `systemctl reload` will not
  work, but you can still send `SIGHUP` manually).
* The `WatchdogSec` value should be set based on your tolerance for downtime.
  A value of `5` (5 seconds) is a reasonable default. Very low values (e.g. `1`)
  may cause spurious restarts under heavy load.
* Watchdog and notify functionality is only available on Linux. On other
  platforms, use `Type=simple` and manage restarts via your service manager's
  native mechanisms.

## Socket Activation

Ghostunnel supports systemd [socket activation][systemd-socket] for on-demand
startup. Socket activation is supported for the `--listen` and `--status`
flags by passing an address of the form `systemd:<name>`, where `<name>`
matches the `FileDescriptorName` in the socket unit.

### Socket Unit

A `ghostunnel.socket` unit for listening on `*:8443`:

```ini
[Unit]
Description=Ghostunnel Socket
PartOf=ghostunnel.service

[Socket]
FileDescriptorName=ghostunnel
ListenStream=0.0.0.0:8443

[Install]
WantedBy=sockets.target
```

### Corresponding Service Unit

A `ghostunnel.service` that forwards to `localhost:8080`:

```ini
[Unit]
Description=Ghostunnel
After=network.target ghostunnel.socket
Requires=ghostunnel.socket

[Service]
Type=simple
ExecStart=/usr/bin/ghostunnel server \
    --listen=systemd:ghostunnel \
    --target=localhost:8080 \
    --keystore=/etc/ghostunnel/server-keystore.p12 \
    --cacert=/etc/ghostunnel/cacert.pem \
    --allow-cn=client

[Install]
WantedBy=default.target
```

The `FileDescriptorName` in `ghostunnel.socket` must match the name passed to
`--listen`. If multiple sockets are needed (e.g. for a status port), use the
name to distinguish them.

### Installing

```bash
# Copy unit files into place
sudo cp ghostunnel.socket ghostunnel.service /etc/systemd/system/

# Reload, enable, and start the socket
sudo systemctl daemon-reload
sudo systemctl enable --now ghostunnel.socket
```

systemd will start `ghostunnel.service` on demand when a connection arrives
on the socket.

## Security Hardening

systemd provides [sandboxing options][systemd-exec] that complement
Ghostunnel's built-in Landlock support. These settings restrict the service to
the privileges it needs:

```ini
[Service]
# Run as a dedicated unprivileged user
DynamicUser=yes

# Filesystem restrictions
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectProc=invisible

# Network: only allow AF_INET/AF_INET6 (and AF_UNIX for syslog/notify)
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

# Capabilities: drop everything, Ghostunnel doesn't need any
# (use socket activation or listen on ports > 1024)
CapabilityBoundingSet=
NoNewPrivileges=yes

# System call filter: allow only networking and basic I/O
SystemCallFilter=@system-service
SystemCallArchitectures=native

# Misc
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
RemoveIPC=yes
UMask=0077
```

### Notes

* **`DynamicUser=yes`** allocates a transient user at runtime. If you need
  persistent state or specific file ownership, use a static `User=ghostunnel`
  instead.
* **`CapabilityBoundingSet=`** (empty) drops all capabilities. If you need to
  bind to a privileged port (< 1024) without socket activation, add
  `CAP_NET_BIND_SERVICE` instead.
* **`ProtectSystem=strict`** makes the entire filesystem read-only except
  `/dev`, `/proc`, and `/sys`. Ghostunnel only needs to read certificate
  files, so this is safe. If your certificates live outside the default
  paths, no extra configuration is needed — they are already readable.
* These settings work alongside Ghostunnel's own Landlock sandboxing
  (enabled by default on Linux). The two layers are complementary — systemd
  restricts at the process level, Landlock restricts within the process.
* Run `systemd-analyze security ghostunnel.service` to audit the effective
  security posture of your unit file.

[sd-notify]: https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html
[systemd-service]: https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html
[systemd-exec]: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html
[systemd-socket]: https://www.freedesktop.org/software/systemd/man/latest/systemd.socket.html
