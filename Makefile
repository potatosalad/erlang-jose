PROJECT = jose
PROJECT_DESCRIPTION = JSON Object Signing and Encryption (JOSE) for Erlang and Elixir.
PROJECT_VERSION = 1.11.10

TEST_DEPS = jiffy jsone jsx libdecaf libsodium ojson proper thoas

dep_jiffy = hex 1.1.2
dep_jsone = hex 1.9.0
dep_jsx = hex 3.1.0
# dep_keccakf1600 = hex 3.0.0
dep_libdecaf = hex 2.1.1
dep_libsodium = hex 2.0.1
dep_ojson = hex 1.0.0
dep_thoas = hex 1.2.1
dep_proper = git https://github.com/proper-testing/proper.git 5640d0715d4b346676267504d8e84398e2a29f75

include erlang.mk

.PHONY: docker-build docker-load docker-setup docker-save docker-shell docker-test docker-test-build

DOCKER_OTP_VERSION ?= 27.3-alpine-3.19.7
CT_SUITES ?=

docker-build::
	$(gen_verbose) docker build \
		--tag ${DOCKER_OTP_VERSION} \
		--file test/Dockerfile \
		--build-arg OTP_VERSION=${DOCKER_OTP_VERSION} \
		test

docker-load::
	$(gen_verbose) docker load \
		--input "${DOCKER_OTP_VERSION}/image.tar"

docker-save::
	$(verbose) mkdir -p "${DOCKER_OTP_VERSION}"
	$(gen_verbose) docker save \
		--output "${DOCKER_OTP_VERSION}/image.tar" \
		${DOCKER_OTP_VERSION}

docker-setup::
	$(verbose) if [ -f "${DOCKER_OTP_VERSION}/image.tar" ]; then \
		$(MAKE) docker-load; \
	else \
		$(MAKE) docker-build; \
		$(MAKE) docker-save; \
	fi

docker-shell::
	$(verbose) docker run \
		--volume "$(shell pwd)":"/build/jose" --rm --interactive --tty "${DOCKER_OTP_VERSION}" \
		/bin/bash -l

ifeq ($(CT_SUITES),)
docker-test::
	$(gen_verbose) docker run \
		--volume "$(shell pwd)":"/build/jose" \
		"${DOCKER_OTP_VERSION}" \
		sh -c 'cd jose && make ct'
else
docker-test::
	$(gen_verbose) docker run \
		--volume "$(shell pwd)":"/build/jose" \
		-e CT_SUITES="${CT_SUITES}" \
		"${DOCKER_OTP_VERSION}" \
		sh -c 'cd jose && make ct'
endif

docker-test-build::
	$(gen_verbose) docker run \
		--volume "$(shell pwd)":"/build/jose" \
		"${DOCKER_OTP_VERSION}" \
		sh -c 'cd jose && make test-build'

.PHONY: eqwalize eqwalize-all distclean-elp

# Arch detection.

ifeq ($(ARCH),)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_M),amd64)
ARCH = x86_64
else ifeq ($(UNAME_M),x86_64)
ARCH = x86_64
else ifeq ($(UNAME_M),arm64)
ARCH = aarch64
else ifeq ($(UNAME_M),aarch64)
ARCH = aarch64
else
$(error Unable to detect architecture. Please open a ticket with the output of uname -s.)
endif

export ARCH
endif

# Configuration.
ELP_VERSION ?= 2025-09-01
ELP_OTP_VERSION ?= 28

ELP ?= $(CURDIR)/elp
export ELP

ifeq ($(PLATFORM),darwin)
	ELP_URL ?= https://github.com/WhatsApp/erlang-language-platform/releases/download/${ELP_VERSION}/elp-macos-${ARCH}-apple-darwin-otp-${ELP_OTP_VERSION}.tar.gz
else
	ELP_URL ?= https://github.com/WhatsApp/erlang-language-platform/releases/download/${ELP_VERSION}/elp-linux-${ARCH}-unknown-linux-gnu-otp-${ELP_OTP_VERSION}.tar.gz
endif

ELP_OPTS ?=
ELP_BUILD_DIR ?= $(CURDIR)/_elp_build
ELP_ARCHIVE = elp-$(ELP_VERSION).tar.gz

# Core targets.

help::
	$(verbose) printf "%s\n" "" \
		"elp targets:" \
		"  eqwalize     Run 'elp eqwalize-app argo' on the current project" \
		"  eqwalize-all Run 'elp eqwalize-all' on the current project"

distclean:: distclean-elp

# Plugin-specific targets.

$(ELP):
	$(verbose) mkdir -p $(ELP_BUILD_DIR)
	$(verbose) echo "Downloading eqwalizer from: "$(ELP_URL)
	$(verbose) $(call core_http_get,$(ELP_BUILD_DIR)/$(ELP_ARCHIVE),$(ELP_URL))
	$(verbose) cd $(ELP_BUILD_DIR) && \
		tar -xzf $(ELP_ARCHIVE)
	$(gen_verbose) cp $(ELP_BUILD_DIR)/elp $(ELP)
	$(verbose) chmod +x $(ELP)
	$(verbose) rm -rf $(ELP_BUILD_DIR)

eqwalize: $(ELP)
	$(verbose) $(ELP) eqwalize $(PROJECT)

eqwalize-all: $(ELP)
	$(verbose) $(ELP) eqwalize-all

distclean-elp:
	$(gen_verbose) rm -rf $(ELP)

.PHONY: erlfmt erlfmt-check distclean-erlfmt format

# Configuration.
ERLFMT_VERSION ?= 1.7.0

ERLFMT ?= $(CURDIR)/erlfmt
export ERLFMT

ERLFMT_URL ?= https://github.com/WhatsApp/erlfmt/archive/refs/tags/v$(ERLFMT_VERSION).tar.gz
ERLFMT_OPTS ?=
ERLFMT_BUILD_DIR ?= $(CURDIR)/_erlfmt_build
ERLFMT_CODE_ARCHIVE = $(ERLFMT_VERSION).tar.gz

ERLFMT_REBAR3_URL ?= https://s3.amazonaws.com/rebar3/rebar3
ERLFMT_REBAR3 ?= rebar3

# Core targets.

help::
	$(verbose) printf "%s\n" "" \
		"erlfmt targets:" \
		"  erlfmt       Run erlfmt or download the default otherwise" \
		"  elrfmt-check Run erlfmt --check"

distclean:: distclean-erlfmt

# Plugin-specific targets.

$(ERLFMT):
	$(verbose) mkdir -p $(ERLFMT_BUILD_DIR)
ifeq ($(shell command -v $(ERLFMT_REBAR3)),)
	$(verbose) echo "Downloading Rebar3 from: "$(ERLFMT_REBAR3_URL)
	$(verbose) $(call core_http_get,$(ERLFMT_BUILD_DIR)/rebar3,$(ERLFMT_REBAR3_URL))
	$(verbose) chmod +x $(ERLFMT_BUILD_DIR)/rebar3
	$(eval ERLFMT_REBAR3 := $(ERLFMT_BUILD_DIR)/rebar3)
else
	$(verbose) echo "Using Rebar3: "$(ERLFMT_REBAR3)
endif
	$(verbose) echo "Downloading erlfmt from: "$(ERLFMT_URL)
	$(verbose) $(call core_http_get,$(ERLFMT_BUILD_DIR)/$(ERLFMT_CODE_ARCHIVE),$(ERLFMT_URL))
	$(verbose) cd $(ERLFMT_BUILD_DIR) && \
		tar -xzf $(ERLFMT_CODE_ARCHIVE) && \
		cd erlfmt-$(ERLFMT_VERSION) && \
		$(ERLFMT_REBAR3) as release escriptize
	$(gen_verbose) cp $(ERLFMT_BUILD_DIR)/erlfmt-$(ERLFMT_VERSION)/_build/release/bin/erlfmt $(ERLFMT)
	$(verbose) chmod +x $(ERLFMT)
	$(verbose) rm -rf $(ERLFMT_BUILD_DIR)/erlfmt-$(ERLFMT_VERSION)
	$(verbose) rm $(ERLFMT_BUILD_DIR)/$(ERLFMT_CODE_ARCHIVE)
	$(verbose) rm -f $(ERLFMT_BUILD_DIR)/rebar3
	$(verbose) rm -rf $(ERLFMT_BUILD_DIR)

erlfmt: $(ERLFMT)
	$(verbose) $(ERLFMT) --verbose --write --require-pragma --print-width=120 \
		'{src,codegen,include,test}/**/*.{hrl,erl,app.src,app.src.script}' \
		'test/**/*.config' \
		'{rebar.config,rebar.config.script}'

erlfmt-check: $(ERLFMT)
	$(verbose) $(ERLFMT) --check --require-pragma --print-width=120 \
		'{src,codegen,include,test}/**/*.{hrl,erl,app.src,app.src.script}' \
		'test/**/*.config' \
		'{rebar.config,rebar.config.script}'

distclean-erlfmt:
	$(gen_verbose) rm -rf $(ERLFMT)

format: $(ERLFMT)
	$(verbose) $(MAKE) erlfmt
	$(verbose) mix format --migrate

.PHONY: lint lint-dialyzer lint-eqwalizer lint-format lint-xref

lint:: lint-format lint-eqwalizer lint-xref lint-dialyzer

lint-dialyzer:
	$(verbose) rebar3 dialyzer

lint-eqwalizer: eqwalize-all

lint-format: erlfmt-check

lint-xref:
	$(verbose) rebar3 xref
