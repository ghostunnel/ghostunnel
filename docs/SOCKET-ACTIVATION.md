---
title: Socket Activation
description: Use systemd (Linux) or launchd (macOS) socket activation for on-demand startup.
weight: 80
---

Ghostunnel supports socket activation via both systemd (on Linux) and launchd
(on macOS). Socket activation is supported for the `--listen` and `--status`
flags, and can be used by passing an address of the form `systemd:<name>` or
`launchd:<name>`, where `<name>` should be the name of the socket as defined in
your systemd/launchd configuration.

Note that socket activation is not available on Windows.

### launchd

See Apple's [Creating Launch Daemons and Agents][launchd-guide] for background
on launchd plists.

A launchd plist to launch Ghostunnel in server mode on :8081,
listening for status connections on :8082, and forwarding connections to :8083
could look like this:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>com.square.ghostunnel</string>
    <key>ProgramArguments</key>
    <array>
      <string>/usr/bin/ghostunnel</string>
      <string>server</string>
      <string>--keystore</string>
      <string>/etc/ghostunnel/server-keystore.p12</string>
      <string>--cacert</string>
      <string>/etc/ghostunnel/cacert.pem</string>
      <string>--target</string>
      <string>localhost:8083</string>
      <string>--listen</string>
      <string>launchd:Listener</string>
      <string>--status</string>
      <string>launchd:Status</string>
      <string>--allow-cn</string>
      <string>client</string>
    </array>
    <key>StandardOutPath</key>
    <string>/var/log/ghostunnel.out.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/ghostunnel.err.log</string>
    <key>Sockets</key>
    <dict>
      <key>Listener</key>
      <dict>
        <key>SockServiceName</key>
        <string>8081</string>
        <key>SockType</key>
        <string>stream</string>
        <key>SockFamily</key>
        <string>IPv4</string>
      </dict>
      <key>Status</key>
      <dict>
        <key>SockServiceName</key>
        <string>8082</string>
        <key>SockType</key>
        <string>stream</string>
        <key>SockFamily</key>
        <string>IPv4</string>
      </dict>
    </dict>
  </dict>
</plist>
```

Note that in the launchd case *both* `SockType` and `SockFamily` need to be
defined for each socket. If for example the family were to be left out, launchd
would open two sockets (IPv4 and IPv6) for the given key (like `Listener`) and
pass them to Ghostunnel which is not currently supported.

### systemd

See the [`systemd.socket`][systemd-socket] man page for the full socket unit
reference.

A systemd unit for a `ghostunnel.socket` for listening on `*:8443` could look
like this:

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

A corresponding `ghostunnel.service` to forward to `localhost:8080` could look
like this:

```ini
[Unit]
Description=Ghostunnel
After=network.target ghostunnel.socket
Requires=ghostunnel.socket

[Service]
Type=simple
ExecStart=/usr/bin/ghostunnel server --listen=systemd:ghostunnel --target=localhost:8080 --keystore=/etc/ghostunnel/server-keystore.p12 --cacert=/etc/ghostunnel/cacert.pem --allow-cn=client

[Install]
WantedBy=default.target
```

Note that the `FileDescriptorName` in `ghostunnel.socket` matches the name passed to
`--listen`. If multiple sockets are needed, e.g. for a status port, the name can be
used to distinguish the listening and status sockets.

Ghostunnel also supports systemd notify and watchdog functionality. See
[WATCHDOG]({{< ref "WATCHDOG.md" >}}) for details on configuring `Type=notify-reload` services.

[launchd-guide]: https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html
[systemd-socket]: https://www.freedesktop.org/software/systemd/man/latest/systemd.socket.html
