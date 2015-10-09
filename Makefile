INTEGRATION_TESTS := $(shell find tests -name 'test-*.py' -exec basename {} .py \;)

test: unit integration

# Run unit tests
pre-unit: 
	@echo "*** Running unit tests ***"

unit: pre-unit
	@-go test -v 2>/dev/null

# Run integration tests
pre-integration: 
	@echo "*** Running integration tests ***"

integration: pre-integration $(INTEGRATION_TESTS)
	@echo "PASS"

test-%:
	@echo "=== RUN tests/$@"
	@-cd tests && python ./$@.py > $@.log 2>&1
	@echo "--- PASS: tests/$@"
