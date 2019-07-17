# SPIFFE Workload API Support Demo

The following demonstrates using the SPIFFE Workload API to supply Ghostunnel
with an X.509 identity and trusted CA roots that are used to facilite
communication between a frontend and backend service.

## Prerequisites

* `ghostunnel` binary from [Ghostunnel](https://github.com/square/ghostunnel/releases/latest)
* `spire-server` and `spire-agent` binaries from [SPIRE](https://github.com/spiffe/spire/releases/latest)
* `socat`

## Architecture

There are several processes involved in the demo:

* A backend server that receives TCP data
* A frontend client that sends TCP data
* A backend ghostunnel that receives TCP data over SPIFFE-authenticated mutual
  TLS and forwards it to the backend server
* A frontend ghostunnel that receives TCP data forwards it to the backend
  ghostunnel over SPIFFE-authenticated mutual TLS.
* SPIRE server that mints the identities and delivers them to agents according
  to workload registration
* Backend SPIRE agent that identifies the backend ghostunnel and issues it a
  backend SPIFFE identity.
* Frontend SPIRE agent that identifies the frontend ghostunnel and issues it a
  frontend SPIFFE identity.


```
           TCP                         mTLS                         TCP
Frontend ------> Frontend Ghostunnel --------> Backend Ghostunnel ------> Backend
                         ^                            ^
                         |                            |
                         |                            |
                 Frontend SPIRE Agent          Backend SPIRE Agent
                         ^                            ^
                         |                            |
                         +                            +
                          \                          /
                           \                        /
                            +---- SPIRE Server ----+
```


## Steps

### Run SPIRE Server

```
$ ./01-run-spire-server.sh
```

### Run Backend SPIRE Agent

```
$ ./02-run-backend-agent.sh
```

### Run Frontend SPIRE Agent

```
$ ./03-run-frontend-agent.sh
```

### Register Frontend and Backend Ghostunnel Workloads

```
$ ./04-register-ghostunnel-workloads.sh
```

### Run Backend Ghostunnel

```
$ ./05-run-backend-ghostunnel.sh
```

### Run Frontend Ghostunnel

```
$ ./06-run-frontend-ghostunnel.sh
```

### Run Backend

```
$ ./07-run-backend.sh
```

### Send Frontend Request

```
$ ./08-send-frontend-request.sh
```
