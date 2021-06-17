module github.com/ghostunnel/ghostunnel

replace github.com/github/certstore => ./certstore

require (
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver v1.5.0 // indirect
	github.com/alecthomas/units v0.0.0-20210208195552-ff826a37aa15 // indirect
	github.com/caddyserver/certmagic v0.14.1-0.20210616191643-647f27cf265e
	github.com/coreos/go-systemd v0.0.0-20191104093116-d3cd4ed1dbcf
	github.com/cyberdelia/go-metrics-graphite v0.0.0-20161219230853-39f87cc3b432
	github.com/deathowl/go-metrics-prometheus v0.0.0-20200518174047-74482eab5bfb
	github.com/github/certstore v0.1.0
	github.com/hashicorp/go-syslog v1.0.0
	github.com/huandu/xstrings v1.3.2 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/kavu/go_reuseport v1.5.0
	github.com/letsencrypt/pkcs11key/v4 v4.0.0
	github.com/mholt/acmez v0.1.3
	github.com/miekg/pkcs11 v1.0.3 // indirect
	github.com/mitchellh/copystructure v1.1.2 // indirect
	github.com/mwitkow/go-http-dialer v0.0.0-20161116154839-378f744fb2b8
	github.com/pires/go-proxyproto v0.5.0
	github.com/prometheus/client_golang v1.10.0
	github.com/prometheus/common v0.21.0 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20201227073835-cf1acfcdf475
	github.com/spiffe/go-spiffe v1.1.0
	github.com/square/certigo v1.12.1
	github.com/square/go-sq-metrics v0.0.0-20170531223841-ae72f332d0d9
	github.com/stretchr/testify v1.7.0
	golang.org/x/sys v0.0.0-20210423185535-09eb48e85fd7 // indirect
	google.golang.org/genproto v0.0.0-20210423144448-3a41ef94ed2b // indirect
	google.golang.org/grpc v1.37.0 // indirect
	gopkg.in/alecthomas/kingpin.v2 v2.2.6
)

go 1.16
