SOURCE_FILES := $(shell find . \( -name '*.go' -not -path './vendor*' \))
INTEGRATION_TESTS := $(shell find tests -name 'test-*.py' -exec basename {} .py \;)

# Test binary with coverage instrumentation
ghostunnel.test: $(SOURCE_FILES)
	go test -c -covermode=count -coverpkg .

clean:
	rm -rf *.out */*.out ghostunnel.test tests/__pycache__

test: unit $(INTEGRATION_TESTS)
	gocovmerge *.out */*.out > coverage-merged.out
	@echo "PASS"

unit:
	go test -v -covermode=count -coverprofile=coverage-unit-test.out

$(INTEGRATION_TESTS): ghostunnel.test
	@cd tests && ./runner.py $@

softhsm-import:
	softhsm2-util --init-token --slot 0 --label ${PKCS11_LABEL} --so-pin ${PKCS11_PIN} --pin ${PKCS11_PIN}
	softhsm2-util --id 01 --token ${PKCS11_LABEL} --label ${PKCS11_LABEL} --import test-keys/server.pkcs8.key --so-pin ${PKCS11_PIN} --pin ${PKCS11_PIN}

docker-build:
	docker build -t squareup/ghostunnel .

docker-test-build:
	docker build --build-arg GO_VERSION=${GO_VERSION} -t squareup/ghostunnel-test -f Dockerfile-test .

docker-test-run:
	docker run -v /dev/log:/dev/log -v ${PWD}:/go/src/github.com/square/ghostunnel squareup/ghostunnel-test

docker-test: docker-test-build docker-test-run

.PHONY: $(INTEGRATION_TESTS) test unit softhsm-import docker-build docker-test-build docker-test-run docker-test clean
