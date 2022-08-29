PROJECT = jose
PROJECT_DESCRIPTION = JSON Object Signing and Encryption (JOSE) for Erlang and Elixir.
PROJECT_VERSION = 1.11.3

TEST_DEPS = jiffy jsone jsx libdecaf ojson proper

dep_jiffy = hex 1.1.1
dep_jsone = hex 1.7.0
dep_jsx = hex 3.1.0
# dep_keccakf1600 = hex 3.0.0
dep_libdecaf = hex 2.1.0
# dep_libsodium = git https://github.com/talklittle/erlang-libsodium.git otp-23-remove-erl-interface
dep_ojson = hex 1.0.0
dep_proper = git https://github.com/proper-testing/proper.git bfd7d862dd5082eeca65c192a7021d0e4de5973e

include erlang.mk

.PHONY: docker-build docker-load docker-setup docker-save docker-shell docker-test

docker-build::
	$(gen_verbose) docker build \
		-t ${DOCKER_OTP_VERSION} \
		-f test/Dockerfile \
		--build-arg OTP_VERSION=${DOCKER_OTP_VERSION} \
		test

docker-load::
	$(gen_verbose) docker load \
		-i "${DOCKER_OTP_VERSION}/image.tar"

docker-save::
	$(verbose) mkdir -p "${DOCKER_OTP_VERSION}"
	$(gen_verbose) docker save \
		-o "${DOCKER_OTP_VERSION}/image.tar" \
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
		-v "$(shell pwd)":"/build/jose" --rm -it "${DOCKER_OTP_VERSION}" \
		/bin/bash -l

docker-test::
	$(gen_verbose) docker run \
		-v "$(shell pwd)":"/build/jose" "${DOCKER_OTP_VERSION}" \
		sh -c 'cd jose && make ct'
