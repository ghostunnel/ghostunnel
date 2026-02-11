# SPIFFE Workload API Support Demo

The following demonstrates using the SPIFFE Workload API to supply Ghostunnel
with an X.509 identity and trusted CA roots that are used to facilitate
communication between a frontend and backend service.

## Prerequisites

* `ghostunnel` binary from [Ghostunnel](https://github.com/ghostunnel/ghostunnel/releases/latest)
* `spire-server` and `spire-agent` binaries from [SPIRE](https://github.com/spiffe/spire/releases/latest)
* `socat`

## Architecture

There are several processes involved in the demo:

* Frontend client that sends TCP data
* Frontend Ghostunnel that receives TCP data forwards it to the backend
  Ghostunnel over SPIFFE-authenticated mutual TLS
* Backend Ghostunnel that receives TCP data over SPIFFE-authenticated mutual
  TLS and forwards it to the backend server
* Backend server that receives TCP data
* Frontend SPIRE agent that identifies the frontend Ghostunnel and issues it a
  frontend SPIFFE identity
* Backend SPIRE agent that identifies the backend Ghostunnel and issues it a
  backend SPIFFE identity
* SPIRE server that mints the identities and delivers them to agents according
  to workload registration

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

### Send the Frontend Request

Run the following to send a request from the frontend.

```
$ ./08-send-frontend-request.sh
```

You should see the backend print out a message!
