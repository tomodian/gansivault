GO ?= go
COVERAGE ?= coverage.out

.PHONY: all
all: fmt vet test

.PHONY: fmt
fmt:
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "not gofmt'd:"; echo "$$unformatted"; exit 1; \
	fi

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: test
test:
	$(GO) test -race ./...

.PHONY: cover
cover:
	$(GO) test -covermode=atomic -coverprofile=$(COVERAGE) ./...
	@total=$$($(GO) tool cover -func=$(COVERAGE) | awk '/^total:/ {print $$3}'); \
	if [ "$$total" != "100.0%" ]; then \
		echo "coverage is $$total, this project requires 100.0%"; \
		$(GO) tool cover -func=$(COVERAGE) | grep -v '100.0%$$' || true; \
		exit 1; \
	fi; \
	echo "coverage is $$total"

.PHONY: cover-html
cover-html: cover
	$(GO) tool cover -html=$(COVERAGE)

.PHONY: lint
lint:
	golangci-lint run

# Actions live in the workflow as full commit SHAs. pinact rewrites the tags
# in .github/workflows to SHAs, and pin-check is what CI runs.
.PHONY: pin
pin:
	pinact run

.PHONY: pin-check
pin-check:
	pinact run --check --verify

.PHONY: interop
interop:
	$(GO) test -v -run TestInteropWithRealAnsibleVault .

.PHONY: build
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -o bin/gansivault ./cmd/gansivault

.PHONY: tidy
tidy:
	$(GO) mod tidy

.PHONY: clean
clean:
	rm -rf bin $(COVERAGE)
