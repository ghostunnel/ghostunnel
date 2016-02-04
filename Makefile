INTEGRATION_TESTS := $(shell find tests -name 'test-*.py' -exec basename {} .py \;)

build: depends
	go build -ldflags "-X \"main.buildRevision=`git describe --long --always --abbrev=8 HEAD`\" -X \"main.buildCompiler=`go version`\""

depends:
	go get ./...

test: unit integration

# Run unit tests
pre-unit: 
	@echo "*** Running unit tests ***"

unit: pre-unit
	go get github.com/stretchr/testify/assert
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
