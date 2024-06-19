Watchdog
========

Ghostunnel supports systemd notify and watchdog functionality. Simply create a
service unit of `Type=notify-reload` with the `Restart=always` and
`WatchdogSec=1` options. This functionality was added in version 1.8.0. If you have
an older version, you will need to use `Type=simple` as watchdog functionality
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
