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

```ini {file="ghostunnel.service"}
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
WantedBy=multi-user.target
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

```ini {file="ghostunnel.service"}
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
WantedBy=multi-user.target
```

### Notes

* `Type=notify-reload` requires systemd v253 or later. If you are on an older
  version, use `Type=notify` instead and add
  `ExecReload=/bin/kill -HUP $MAINPID` to the `[Service]` section so that
  `systemctl reload` still triggers a certificate reload. (Without it,
  `systemctl reload` has no effect, though you can always send `SIGHUP`
  manually.)
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

```ini {file="ghostunnel.socket"}
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

```ini {file="ghostunnel.service"}
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
WantedBy=multi-user.target
```

The `FileDescriptorName` in `ghostunnel.socket` must match the name passed to
`--listen`. If multiple sockets are needed (e.g. for a status port), use the
name to distinguish them.

### UNIX Socket Variant

To restrict access to a specific local user (see
[Security]({{< ref "general.md#restricting-to-specific-local-users" >}})),
have systemd create a UNIX domain socket with the desired ownership and mode
instead of binding to TCP:

```ini {file="ghostunnel.socket"}
[Socket]
FileDescriptorName=ghostunnel
ListenStream=/run/ghostunnel.sock
SocketUser=root
SocketGroup=root
SocketMode=0600
```

systemd applies `SocketUser`/`SocketGroup`/`SocketMode` at socket creation
time, so only the intended user can `connect(2)` to it; no firewall rules
required. See [systemd.socket(5)][systemd-socket] for the full list of
options.

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

```ini {file="ghostunnel.service"}
[Service]
# Dedicated unprivileged user. Use User=ghostunnel if you need persistent
# state or specific file ownership instead.
DynamicUser=yes

# Filesystem: most of the system becomes read-only outside /dev, /proc, /sys.
# Ghostunnel only needs read access to certs, which still works from standard
# readable locations such as /etc. Note that ProtectHome=yes makes /home and
# /root inaccessible, so certs should not be stored there unless you relax
# ProtectHome or add an explicit exception with ReadOnlyPaths=.
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectProc=invisible

# Network: only allow AF_INET/AF_INET6/AF_UNIX
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

# Capabilities: drop everything. Add CAP_NET_BIND_SERVICE if binding to a
# privileged port (< 1024) without socket activation.
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

Run `systemd-analyze security ghostunnel.service` to audit the effective
security posture of your unit file.

[sd-notify]: https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html
[systemd-service]: https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html
[systemd-exec]: https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html
[systemd-socket]: https://www.freedesktop.org/software/systemd/man/latest/systemd.socket.html
