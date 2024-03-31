Watchdog
========

Ghostunnel supports systemd notify and watchdog functionality. Simply create a
service unit of `Type=notify-reload` with the `Restart=always` and
`WatchdogSec=1` options. Note that this currently requires a development build
of systemd (as of April, 2024) but will land in the next release. If you have
an older version, you will need to use `Type=simple` and watchdog functionality
won't work.

```
[Unit]
Description=Ghostunnel
After=network.target

[Service]
Type=notify-reload
ExecStart=/usr/bin/ghostunnel server --listen=localhost:8443 --target=localhost:8080 --keystore=/etc/ghostunnel/server-keystore.p12 --cacert /etc/ghostunnel/cacert.pem --allow-cn client
WatchdogSec=1
Restart=always

[Install]
WantedBy=default.target
```
