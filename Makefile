export GO15VENDOREXPERIMENT = 1

INTEGRATION_TESTS := $(shell find tests -name 'test-*.py' -exec basename {} .py \;)

# Build
build: depends git-fsck
	go build -ldflags "-X \"main.buildRevision=`git describe --long --always --abbrev=8 HEAD`\" -X \"main.buildCompiler=`go version`\""

# Dependencies 
depends:
	glide -q install

update-depends:
	glide -q update

# Check integrity of dependencies
git-fsck: 
	@for repo in `find vendor -name .git`; do \
		echo "git --git-dir=$$repo fsck --full --strict --no-dangling"; \
		git --git-dir=$$repo fsck --full --strict --no-dangling || exit 1; \
	done

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
	@cd tests && ./$@.py
	@echo "--- PASS: tests/$@"
