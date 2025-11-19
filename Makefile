# Run `make help` to display help
.DEFAULT_GOAL := help

# --- Global -------------------------------------------------------------------
O = out
COVERAGE = 63
VERSION ?= $(shell git describe --tags --dirty --always)

## Build and lint
all: build lint test check-coverage
	@if [ -e .git/rebase-merge ]; then git --no-pager log -1 --pretty='%h %s'; fi
	@echo '$(COLOUR_GREEN)Success$(COLOUR_NORMAL)'

## Full clean build and up-to-date checks as run on CI
ci: clean check-uptodate all

# GENERATED_FILES is apended at targets that generate or modify files that are
# required to be up-to-date.
GENERATED_FILES :=
check-uptodate: tidy godoc
	test -z "$$(git status --porcelain -- $(GENERATED_FILES))" || { git status; false; }

## Remove generated files
clean::
	-rm -rf $(O)

.PHONY: all check-uptodate ci clean

# --- Build --------------------------------------------------------------------
BIN_NAME = flapjak
GO_TAGS =
GO_LDFLAGS = -X main.version=$(VERSION)
GO_FLAGS += $(if $(GO_TAGS),-tags='$(GO_TAGS)')
GO_FLAGS += $(if $(GO_LDFLAGS),-ldflags='$(GO_LDFLAGS)')
GO_BIN_SUFFIX = $(if $(GOOS),_$(GOOS))$(if $(GOARCH),_$(GOARCH))
GO_BIN_NAME = $(BIN_NAME)$(GO_BIN_SUFFIX)

## Build flapjak binary
build: | $(O)
	go build -o $(O)/$(GO_BIN_NAME) $(GO_FLAGS) .

GENERATED_FILES += go.mod go.sum
## Tidy go modules with "go mod tidy"
tidy:
	go mod tidy

.PHONY: build tidy

# --- Test ---------------------------------------------------------------------
COVERFILE = $(O)/coverage.txt

## Run tests and generate a coverage file
test: | $(O)
	go test -coverprofile=$(COVERFILE) ./...

## Check that test coverage meets the required level
check-coverage: test
	@go tool cover -func=$(COVERFILE) | $(CHECK_COVERAGE) || $(FAIL_COVERAGE)

## Show test coverage in your browser
cover: test
	go tool cover -html=$(COVERFILE)

CHECK_COVERAGE = awk -F '[ \t%]+' '/^total:/ {print; if ($$3 < $(COVERAGE)) exit 1}'
FAIL_COVERAGE = { echo '$(COLOUR_RED)FAIL - Coverage below $(COVERAGE)%$(COLOUR_NORMAL)'; exit 1; }

.PHONY: check-coverage cover test

# --- Lint ---------------------------------------------------------------------
## Lint go source code
lint:
	golangci-lint run

.PHONY: lint

# --- Docs ---------------------------------------------------------------------

GENERATED_FILES += main.go
## Generate Go doc comment for command with usage.
godoc: build
	./bin/gengodoc.awk main.go > $(O)/out.go
	mv $(O)/out.go main.go

.PHONY: godoc

# --- OCI image ----------------------------------------------------------------

# OCI builds can target different environments by defining the platform,
# container registry and image tag for the environment and setting OCI_BUILD
# to the environment name. The "release" environment is pre-defined for
# releasing formal OCI images. The default null environment produces an image
# for the local image store, local architecture with no image tag (which means
# "latest" to Docker).
# For example, you might set the following in a direnv .envrc file for developing
# local container images:
#   OCI_BUILD=local
#   OCI_PLATFORM_local = linux/amd64
#   OCI_REGISTRY_local = reg.example.com
#   OCI_TAG_local = dev
# This will locally build only amd64, push the image to reg.example.com and tag
# it with a tag of "dev".

OCI_PLATFORM_release = linux/amd64,linux/arm64
OCI_REGISTRY_release = docker.io
OCI_TAG_release = $(VERSION)

OCI_PLATFORM = $(OCI_PLATFORM_$(OCI_BUILD))
OCI_REGISTRY = $(OCI_REGISTRY_$(OCI_BUILD))
OCI_TAG = $(OCI_TAG_$(OCI_BUILD))

OCI_REPOSITORY = foxygoat/flapjak
OCI_IMAGE = $(if $(OCI_REGISTRY),$(OCI_REGISTRY)/)$(OCI_REPOSITORY)$(if $(OCI_TAG),:$(OCI_TAG))

## Build OCI container image
build-oci:
	docker buildx build \
		--tag $(OCI_IMAGE) \
		--build-arg VERSION=$(VERSION) \
		$(if $(OCI_PLATFORM),--platform $(OCI_PLATFORM)) \
		$(if $(PUSH),--push,--load) \
		.

## Log into container registry $OCI_REGISTRY with $DOCKER_USERNAME:$DOCKER_PASSWORD
docker-login:
	@if [ -z "${DOCKER_USERNAME}" ]; then echo 'DOCKER_USERNAME not set' >&2; exit 1; fi
	@if ! printenv DOCKER_PASSWORD >/dev/null; then echo 'DOCKER_PASSWORD not set' >&2; exit 1; fi
	printenv DOCKER_PASSWORD | \
		docker login --password-stdin --username $(DOCKER_USERNAME) $(OCI_REGISTRY)

.PHONY: build-oci docker-login

# --- Release ------------------------------------------------------------------
RELEASE_DIR = $(O)/release

## Tag and release binaries for different OS on GitHub release
release: tag-release .WAIT build-release build-release-oci .WAIT publish-release

tag-release: nexttag
	git tag $(RELEASE_TAG)
	git push origin $(RELEASE_TAG)

build-release:
	$(MAKE) build CGO_ENABLED=0 GOOS=linux GOARCH=amd64 O=$(RELEASE_DIR)
	$(MAKE) build CGO_ENABLED=0 GOOS=linux GOARCH=arm64 O=$(RELEASE_DIR)
	$(MAKE) build CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 O=$(RELEASE_DIR)
	$(MAKE) build CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 O=$(RELEASE_DIR)

build-release-oci:
	$(MAKE) build-oci OCI_BUILD=release PUSH=1

publish-release:
	gh release create $(RELEASE_TAG) --generate-notes $(RELEASE_DIR)/*

nexttag:
	$(if $(RELEASE_TAG),,$(eval RELEASE_TAG := $(shell $(NEXTTAG_CMD))))

.PHONY: build-release build-release-oci nexttag publish-release release tag-release

define NEXTTAG_CMD
{ git tag --list --merged HEAD --sort=-v:refname; echo v0.0.0; }
| grep -E "^v?[0-9]+.[0-9]+.[0-9]+$$"
| head -n1
| awk -F . '{ print $$1 "." $$2 "." $$3 + 1 }'
endef

# --- Utilities ----------------------------------------------------------------
COLOUR_NORMAL = $(shell tput sgr0 2>/dev/null)
COLOUR_RED    = $(shell tput setaf 1 2>/dev/null)
COLOUR_GREEN  = $(shell tput setaf 2 2>/dev/null)
COLOUR_WHITE  = $(shell tput setaf 7 2>/dev/null)

help:
	$(eval export HELP_AWK)
	@awk "$${HELP_AWK}" $(MAKEFILE_LIST) | sort | column -s "$$(printf \\t)" -t

$(O):
	@mkdir -p $@

.PHONY: help

# Awk script to extract and print target descriptions for `make help`.
define HELP_AWK
/^## / { desc = desc substr($$0, 3) }
/^[A-Za-z0-9%_-]+:/ && desc {
	sub(/::?$$/, "", $$1)
	printf "$(COLOUR_WHITE)%s$(COLOUR_NORMAL)\t%s\n", $$1, desc
	desc = ""
}
endef

define nl


endef
ifndef ACTIVE_HERMIT
$(eval $(subst \n,$(nl),$(shell bin/hermit env -r | sed 's/^\(.*\)$$/export \1\\n/')))
endif

# Ensure make version is gnu make 4.4 or higher (for .WAIT target)
ifeq ($(filter shell-export,$(value .FEATURES)),)
$(error Unsupported Make version. \
	$(nl)Use GNU Make 4.4 or higher (current: $(MAKE_VERSION)). \
	$(nl)Activate 🐚 hermit with `. bin/activate-hermit` and run again \
	$(nl)or use `bin/make`)
endif
