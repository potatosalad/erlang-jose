PROJECT = jose
PROJECT_DESCRIPTION = JSON Object Signing and Encryption (JOSE) for Erlang and Elixir.
PROJECT_VERSION = 1.11.9

TEST_DEPS = jiffy jsone jsx libdecaf libsodium ojson proper thoas

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
