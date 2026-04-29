---
title: Launchd (macOS)
description: Run Ghostunnel as a macOS launchd daemon with socket activation.
weight: 20
---

Ghostunnel can run as a macOS daemon managed by [launchd][launchd-guide].
Launchd socket activation is supported for the `--listen` and `--status` flags
by passing an address of the form `launchd:<name>`, where `<name>` matches the
socket key defined in your plist.

Ghostunnel can also load TLS identities from the system keychain via
`--keychain-identity`. See [Keychain]({{< ref "keychain.md" >}}).

## Example Plist

A launchd plist to run Ghostunnel in server mode, listening on `:8081`,
with a status port on `:8082`, forwarding connections to `:8083`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
  <dict>
    <key>Label</key>
    <string>ghostunnel</string>
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
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
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

`RunAtLoad` starts the service when the plist is bootstrapped (or at boot for
system daemons). `KeepAlive` restarts the process if it exits unexpectedly,
equivalent to systemd's `Restart=always`.

Both `SockType` and `SockFamily` must be defined for each socket. If the
family is omitted, launchd opens two sockets (IPv4 and IPv6) for each key,
which Ghostunnel does not currently support.

## Installing

```bash
# Copy the plist into place
sudo cp ghostunnel.plist /Library/LaunchDaemons/

# Load and start (modern macOS)
sudo launchctl bootstrap system/ /Library/LaunchDaemons/ghostunnel.plist

# Stop and unload
sudo launchctl bootout system/ghostunnel
```

On older macOS versions (before 10.11), use `launchctl load` and
`launchctl unload` instead.

Use `~/Library/LaunchAgents/` (with `gui/<uid>/` instead of `system/`)
if running as a user agent rather than a system daemon.

## Reloading Certificates

To reload certificates without restarting the service, send `SIGHUP`:

```bash
sudo launchctl kill SIGHUP system/ghostunnel
```

For automatic periodic reloads (e.g. with short-lived certificates), pass
`--timed-reload DURATION` in the plist's `ProgramArguments`. Ghostunnel
re-reads the keystore at that interval and refreshes the listener if the
certificate changed.

## Graceful Shutdown

By default, launchd waits 20 seconds between `SIGTERM` and `SIGKILL`. If
Ghostunnel's `--shutdown-timeout` (default `5m`) exceeds that window, in-flight
connections will be cut off. To allow the full drain window, raise
`ExitTimeOut` in the plist:

```xml
<key>ExitTimeOut</key>
<integer>360</integer>
```

[launchd-guide]: https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html
