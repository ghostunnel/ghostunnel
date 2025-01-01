SOURCE_FILES := $(shell find . \( -name '*.go' -not -path './vendor/*' \))
INTEGRATION_TESTS := $(shell find tests -name 'test-*.py' -exec basename {} .py \;)
VERSION := $(shell git describe --always --dirty)

# Ghostunnel binary
ghostunnel: $(SOURCE_FILES)
	go build -ldflags '-X main.version=${VERSION}' -o ghostunnel .

# Ghostunnel binary with certstore enabled
ghostunnel.certstore: $(SOURCE_FILES)
	go build -tags certstore -ldflags '-X main.version=${VERSION}' -o ghostunnel.certstore .

# Man page
ghostunnel.man: ghostunnel
	./ghostunnel --help-custom-man > $@

# Test binary with coverage instrumentation
ghostunnel.test: $(SOURCE_FILES)
	go test -c -covermode=count -coverpkg .,./auth,./certloader,./proxy,./wildcard,./socket

# Clean build output
clean:
	rm -rf ghostunnel coverage ghostunnel.test tests/__pycache__
.PHONY: clean

# Run all tests (unit + integration tests)
test: unit integration
	gocovmerge coverage/*.profile | grep -v "internal/test" > coverage/all.profile
	@echo "PASS"
.PHONY: test

# Run unit tests
unit:
	@mkdir -p coverage
	go test -v -covermode=count -coverprofile=coverage/unit-test.profile ./...
.PHONY: unit

integration: $(INTEGRATION_TESTS)
.PHONY: integration

# Run integration tests
$(INTEGRATION_TESTS): ghostunnel.test
	@mkdir -p coverage
	@cd tests && ./runner.py $@
.PHONY: $(INTEGRATION_TESTS)

# Import test keys into SoftHSM (v2)
softhsm-import:
	softhsm2-util --init-token --slot 0 \
		--label ${GHOSTUNNEL_TEST_PKCS11_LABEL} \
		--so-pin ${GHOSTUNNEL_TEST_PKCS11_PIN} \
		--pin ${GHOSTUNNEL_TEST_PKCS11_PIN}
	softhsm2-util --id 01 \
		--token ${GHOSTUNNEL_TEST_PKCS11_LABEL} \
		--label ${GHOSTUNNEL_TEST_PKCS11_LABEL} \
		--so-pin ${GHOSTUNNEL_TEST_PKCS11_PIN} \
		--pin ${GHOSTUNNEL_TEST_PKCS11_PIN} \
		--import test-keys/server-pkcs8.pem
.PHONY: softhsm-import

# Build Docker image
docker-build:
	docker build -t ghostunnel/ghostunnel .
.PHONY: docker-build

# Run unit and integration tests in Docker container
docker-test:
	docker build --build-arg GO_VERSION=${GO_VERSION} -t ghostunnel/ghostunnel-test -f Dockerfile-test .
	docker run -v ${PWD}:/go/src/github.com/ghostunnel/ghostunnel ghostunnel/ghostunnel-test
.PHONY: docker-test
