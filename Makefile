TESTS := $(shell find tests -name 'test-*.py' -exec basename {} \;)

all: build test

build:
	go build -v

test: unit $(TESTS)

unit:
	go test -v

test-%.py:
	@echo "------- running $@ --------"
	cd tests && python ./$@
