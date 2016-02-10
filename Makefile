export GO15VENDOREXPERIMENT = 1

INTEGRATION_TESTS := $(shell find tests -name 'test-*.py' -exec basename {} .py \;)

# Build
build: depends
	go build -ldflags "-X \"main.buildRevision=`git describe --long --always --abbrev=8 HEAD`\" -X \"main.buildCompiler=`go version`\""

# Dependencies 
depends:
	@glide install

update-depends:
	@glide update

# Run all tests
test: unit integration

# Run unit tests
pre-unit: 
	@echo "*** Running unit tests ***"

unit: pre-unit
	go test -v

# Run integration tests
pre-integration: 
	@echo "*** Running integration tests ***"

integration: pre-integration $(INTEGRATION_TESTS)
	@echo "PASS"

test-%:
	@echo "=== RUN tests/$@"
	@cd tests && python ./$@.py
	@echo "--- PASS: tests/$@"
