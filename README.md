Ghostunnel
==========

Ghostunnel is a simple SSL/TLS proxy with mutual authentication support for
securing non-TLS services such as Redis. Ghostunnel runs in front of a backend
service and accepts TLS-secured connections, which are then forwarded to the
(insecure) backend. In other words, ghostunnel is a very limited replacement
for stunnel in server mode.

Features
========

***Certificate hotswapping***: Ghostunnel supports reloading certificates at
runtime without dropping existing connections. To reload the certificate,
simply send a `SIGUSR1` signal to the process. This will cause the process to
reload the cert/key files and open a listening socket with the new
certificate. Once successful, the old listening socket will be closed.

***AuthN/AuthZ***: Ghostunnel always enforces AuthN by requiring a valid client
certificate. It also supports AuthZ via checks of the CN or OU fields on the 
subject of a connecting client certificate. To set allowed clients, you
must specify at least one of `--allow-all`, `--allow-cn` or `--allow-ou`. 
It is possible to use both `--allow-cn` and `--allow-ou` together.

Usage
=====

    ghostunnel --listen=LISTEN --target=TARGET --key=KEY --cert=CERT --cacert=CACERT [<flags>]
    
    Flags:
      --help           Show help (also see --help-long and --help-man).
      --listen=LISTEN  Address and port to listen on
      --target=TARGET  Address to foward connections to
      --key=KEY        Path to private key file (PEM/PKCS1)
      --cert=CERT      Path to certificate chain file (PEM/X509)
      --cacert=CACERT  Path to certificate authority bundle file (PEM/X509)
      --syslog         Send logs to syslog instead of stderr
      --allow-all      Allow all clients, do not check client cert subject
      --allow-cn=CN    Allow clients with given common name (can be repeated)
      --allow-ou=OU    Allow clients with organizational unit name (can be repeated)
