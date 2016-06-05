SOURCE_FILES := $(shell find . \( -name '*.go' -not -path './vendor*' \))
INTEGRATION_TESTS := $(shell find tests -name 'test-*.py' -exec basename {} .py \;)

# Test binary with coverage instrumentation
ghostunnel.test: $(SOURCE_FILES)
	go test -c -covermode=count -coverpkg .

test: unit $(INTEGRATION_TESTS)
	gocovmerge *.out */*.out > coverage-merged.out
	@echo "PASS"

unit:
	go test -v -covermode=count -coverprofile=coverage-unit-test.out

$(INTEGRATION_TESTS): ghostunnel.test
	@cd tests && ./runner.py $@

.PHONY: $(INTEGRATION_TESTS) test unit
