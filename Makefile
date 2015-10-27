INTEGRATION_TESTS := $(shell find tests -name 'test-*.py' -exec basename {} .py \;)
BENCHMARKS := $(shell find tests -name 'benchmark-*.py' -exec basename {} .py \;)

test: unit integration

benchmark: $(BENCHMARKS) 

# Run unit tests
pre-unit: 
	@echo "*** Running unit tests ***"

unit: pre-unit
	@go test -v

# Run integration tests
pre-integration: 
	@echo "*** Running integration tests ***"

integration: pre-integration $(INTEGRATION_TESTS)
	@echo "PASS"

test-%:
	@echo "=== RUN tests/$@"
	@cd tests && python ./$@.py
	@echo "--- PASS: tests/$@"

benchmark-%:
	@echo "=== RUN tests/$@"
	@cd tests && python ./$@.py
	@echo "--- PASS: tests/$@"
