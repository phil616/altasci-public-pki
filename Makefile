VERSION := $(shell git describe --tags --abbrev=0 2>/dev/null | tr -d '[:alpha:]')
LDFLAGS := "-s -w -X github.com/cloudflare/cfssl/cli/version.version=$(VERSION)"
PKI_CONSOLE_VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
PKI_CONSOLE_LDFLAGS := "-s -w -X main.version=$(PKI_CONSOLE_VERSION)"

export GOFLAGS := -mod=vendor
export GOPROXY := off
GOVULNCHECK ?= govulncheck
PYTHON ?= python3

# Preserve the existing RFC 3161 large-OID/parser fixes when updating modules.
.PHONY: vendor
vendor:
	go mod vendor
	git apply vendor-patches/timestamp-oid.patch

.PHONY: pki-console-security
pki-console-security:
	$(GOVULNCHECK) ./cmd/pki-console
	cd web && npm audit --audit-level=low

.PHONY: pki-console-docs
pki-console-docs:
	$(PYTHON) scripts/check_docs.py

.PHONY: all
all: bin/cfssl bin/cfssl-bundle bin/cfssl-certinfo bin/cfssl-newkey bin/cfssl-scan bin/cfssljson bin/mkbundle bin/multirootca

.PHONY: pki-console
pki-console: bin/pki-console

.PHONY: pki-console-web
pki-console-web:
	cd web && npm ci --no-audit --no-fund
	cd web && npm run build

.PHONY: pki-console-system
pki-console-system: pki-console

.PHONY: pki-console-check
pki-console-check:
	go test -p 1 ./console/... ./cmd/pki-console
	go vet ./console/... ./cmd/pki-console
	$(PYTHON) -B -m unittest discover -s scripts -p test_signing_client.py
	cd web && npm ci --no-audit --no-fund
	cd web && npm run check

.PHONY: pki-console-e2e
pki-console-e2e:
	cd web && npm ci --no-audit --no-fund
	cd web && npm run test:e2e

bin/pki-console: pki-console-web $(shell find console cmd/pki-console -type f -name '*.go') go.mod go.sum Makefile
	@mkdir -p $(dir $@)
ifneq ($(and $(TARGETOS),$(TARGETARCH)),)
	CGO_ENABLED=0 GOOS=$(TARGETOS) GOARCH=$(TARGETARCH) go build -trimpath -ldflags $(PKI_CONSOLE_LDFLAGS) -o $@ ./cmd/pki-console
else
	CGO_ENABLED=0 go build -trimpath -ldflags $(PKI_CONSOLE_LDFLAGS) -o $@ ./cmd/pki-console
endif

bin/%: $(shell find . -type f -name '*.go')
	@mkdir -p $(dir $@)
ifneq ($(and $(TARGETOS),$(TARGETARCH)),)
	GOOS=$(TARGETOS) GOARCH=$(TARGETARCH) go build -ldflags $(LDFLAGS) -o $@ ./cmd/$(@F)
else
	go build -ldflags $(LDFLAGS) -o $@ ./cmd/$(@F)
endif

.PHONY: install
install: install-cfssl install-cfssl-bundle install-cfssl-certinfo install-cfssl-newkey install-cfssl-scan install-cfssljson install-mkbundle install-multirootca

.PHONY: install-%
install-%:
	go install ./cmd/$(@F:install-%=%)

.PHONY: serve
serve: bin/cfssl
serve:
	./bin/cfssl serve

bin/goose: $(shell find vendor -type f -name '*.go')
	@mkdir -p $(dir $@)
ifneq ($(and $(TARGETOS),$(TARGETARCH)),)
	GOOS=$(TARGETOS) GOARCH=$(TARGETARCH) go build -o $@ ./vendor/bitbucket.org/liamstask/goose/cmd/goose
else
	go build -o $@ ./vendor/bitbucket.org/liamstask/goose/cmd/goose
endif

.PHONY: clean
clean:
	rm -rf bin *.deb *.rpm

# Check that given variables are set and all have non-empty values,
# die with an error otherwise.
#
# Params:
#   1. Variable name(s) to test.
#   2. (optional) Error message to print.
#
# cf: https://stackoverflow.com/questions/10858261/abort-makefile-if-variable-not-set
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1,$(strip $(value 2)))))
__check_defined = \
	$(if $(value $1),, \
		$(error Undefined $1$(if $2, ($2))))

.PHONY: snapshot
snapshot:
	goreleaser --clean --snapshot --skip=publish

.PHONY: github-release
github-release:
	@:$(call check_defined, GITHUB_TOKEN)
	goreleaser --clean

.PHONY: release
release: github-release

BUILD_PATH   := $(CURDIR)/build
INSTALL_PATH := $(BUILD_PATH)/usr/local/bin

FPM = fakeroot fpm -C $(BUILD_PATH) \
	-a $(shell uname -m) \
	-s dir \
	-v $(VERSION) \
	--url 'https://github.com/cloudflare/cfssl' \
	--vendor Cloudflare \
	-n cfssl

.PHONY: package
package: package-deb package-rpm

.PHONY: package-deb
package-deb: all
	$(RM) -r build
	mkdir -p $(INSTALL_PATH)
	cp bin/* $(INSTALL_PATH)
	$(FPM) -t deb .

.PHONY: package-rpm
package-rpm: all
	$(RM) -r build
	mkdir -p $(INSTALL_PATH)
	cp bin/* $(INSTALL_PATH)
	$(FPM) -t rpm .
