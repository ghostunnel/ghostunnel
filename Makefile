### Build
REVISION := $(shell git describe --long --always --abbrev=8 HEAD)

build: depends
	go build -ldflags "-X main.buildRevision=$(REVISION)"

depends:
	glide -q install

### Tests
INTEGRATION_TESTS := $(shell find tests -name 'test-*.py' -exec basename {} .py \;)

test: unit integration

unit:
	go test -v -covermode=count -coverprofile=coverage.out

pre-integration: 
	go test -c -covermode=count -coverpkg .

integration: pre-integration $(INTEGRATION_TESTS)

test-%:
	@cd tests && ./test_runner.py $@
