PROJECT = jose
PROJECT_DESCRIPTION = JSON Object Signing and Encryption (JOSE) for Erlang and Elixir.
PROJECT_VERSION = 1.11.8

TEST_DEPS = \
	jiffy \
	jsone \
	jsx \
	libdecaf \
	libsodium \
	ojson \
	proper \
	thoas

dep_jiffy = hex 1.1.1
dep_jsone = hex 1.8.0
dep_jsx = hex 3.1.0
# dep_keccakf1600 = hex 3.0.0
dep_libdecaf = hex 2.1.1
dep_libsodium = hex 2.0.1
dep_ojson = hex 1.0.0
dep_thoas = hex 1.0.0
dep_proper = git https://github.com/proper-testing/proper.git def84f172df92635cc62f3356e3e7ad054638eb4

include erlang.mk

.PHONY: docker-build docker-load docker-setup docker-save docker-shell docker-test docker-test-build

DOCKER_OTP_VERSION ?= 26.0.2-alpine-3.18.2
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

.PHONY: erlfmt erlfmt-check distclean-erlfmt format

# Configuration.
ERLFMT_VERSION ?= 1.3.0

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
		'{src,include,test}/**/*.{hrl,erl,app.src}' \
		'{rebar.config,rebar.config.script}'

erlfmt-check: $(ERLFMT)
	$(verbose) $(ERLFMT) --check --require-pragma --print-width=120 \
		'{src,include,test}/**/*.{hrl,erl,app.src}' \
		'{rebar.config,rebar.config.script}'

distclean-erlfmt:
	$(gen_verbose) rm -rf $(ERLFMT)

format: $(ERLFMT)
	$(verbose) $(MAKE) erlfmt

.PHONY: eqwalizer distclean-eqwalizer

# Configuration.
EQWALIZER_VERSION ?= 0.25.3

ELP ?= $(CURDIR)/elp
export ELP

ifeq ($(PLATFORM),darwin)
	EQWALIZER_URL ?= https://github.com/WhatsApp/eqwalizer/releases/download/v$(EQWALIZER_VERSION)/elp-macos.tar.gz
else
	EQWALIZER_URL ?= https://github.com/WhatsApp/eqwalizer/releases/download/v$(EQWALIZER_VERSION)/elp-linux.tar.gz
endif

EQWALIZER_OPTS ?=
EQWALIZER_BUILD_DIR ?= $(CURDIR)/_eqwalizer_build
EQWALIZER_ARCHIVE = $(EQWALIZER_VERSION).tar.gz

# Core targets.

help::
	$(verbose) printf "%s\n" "" \
		"eqwalizer targets:" \
		"  eqwalizer    Run 'elp eqwalize-all' on the current project"

distclean:: distclean-eqwalizer

# Plugin-specific targets.

$(ELP):
	$(verbose) mkdir -p $(EQWALIZER_BUILD_DIR)
	$(verbose) echo "Downloading eqwalizer from: "$(EQWALIZER_URL)
	$(verbose) $(call core_http_get,$(EQWALIZER_BUILD_DIR)/$(EQWALIZER_ARCHIVE),$(EQWALIZER_URL))
	$(verbose) cd $(EQWALIZER_BUILD_DIR) && \
		tar -xzf $(EQWALIZER_ARCHIVE)
	$(gen_verbose) cp $(EQWALIZER_BUILD_DIR)/elp $(ELP)
	$(verbose) chmod +x $(ELP)
	$(verbose) rm -rf $(EQWALIZER_BUILD_DIR)

eqwalizer: $(ELP)
	$(verbose) $(ELP) eqwalize-all

distclean-eqwalizer:
	$(gen_verbose) rm -rf $(ELP)

.PHONY: lint lint-dialyzer lint-eqwalizer lint-format lint-xref

lint:: lint-format lint-eqwalizer lint-xref lint-dialyzer

lint-dialyzer:
	$(verbose) rebar3 dialyzer

lint-eqwalizer: eqwalizer

lint-format: erlfmt-check

lint-xref:
	$(verbose) rebar3 xref
