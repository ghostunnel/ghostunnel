---
title: Systemd Watchdog
description: Integrate with the systemd watchdog timer for automatic restart on failure.
weight: 20
aliases:
  - /docs/watchdog/
---

*Available since v1.8.0.*

Ghostunnel supports systemd's [notify][sd-notify] and watchdog functionality on
Linux. This allows systemd to know when Ghostunnel is ready and to automatically
restart it if it becomes unresponsive.

## How It Works

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

## Example Unit File

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

## Notes

* `Type=notify-reload` requires systemd v253 or later. If you are on an older
  version, use `Type=notify` instead (reload via `systemctl reload` will not
  work, but you can still send `SIGHUP` manually).
* The `WatchdogSec` value should be set based on your tolerance for downtime.
  A value of `5` (5 seconds) is a reasonable default. Very low values (e.g. `1`)
  may cause spurious restarts under heavy load.
* Watchdog and notify functionality is only available on Linux. On other
  platforms, use `Type=simple` and manage restarts via your service manager's
  native mechanisms.
* For socket activation with systemd, see
  [Socket Activation]({{< ref "socket-activation.md" >}}).

[sd-notify]: https://www.freedesktop.org/software/systemd/man/latest/sd_notify.html
[systemd-service]: https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html
