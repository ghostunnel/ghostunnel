SOURCE_FILES := $(shell find . \( -name '*.go' -not -path './vendor/*' \))
INTEGRATION_TESTS := $(shell find tests -name 'test-*.py' -exec basename {} .py \;)
VERSION := $(shell git describe --always --dirty)

# Ghostunnel binary
ghostunnel: $(SOURCE_FILES)
	go build -ldflags '-X main.version=${VERSION}' -o ghostunnel .

# Test binary with coverage instrumentation
ghostunnel.test: $(SOURCE_FILES)
	go test -c -covermode=count -coverpkg .,./auth,./certloader

# Clean build output
clean:
	rm -rf ghostunnel *.out */*.out ghostunnel.test tests/__pycache__
.PHONY: clean

# Run all tests (unit + integration tests)
test: unit $(INTEGRATION_TESTS)
	gocovmerge *.out */*.out > coverage-merged.out
	@echo "PASS"
.PHONY: test

# Run unit tests
unit:
	go test -v -covermode=count -coverprofile=coverage-unit-test-base.out .
	go test -v -covermode=count -coverprofile=coverage-unit-test-auth.out ./auth
	go test -v -covermode=count -coverprofile=coverage-unit-test-certloader.out ./certloader
.PHONY: unit

# Run integration tests
$(INTEGRATION_TESTS): ghostunnel.test
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
	docker build -t squareup/ghostunnel .
.PHONY: docker-build

# Run unit and integration tests in Docker container
docker-test:
	docker build --build-arg GO_VERSION=${GO_VERSION} -t squareup/ghostunnel-test -f Dockerfile-test .
	docker run -v ${PWD}:/go/src/github.com/square/ghostunnel squareup/ghostunnel-test
.PHONY: docker-test
