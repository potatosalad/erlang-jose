PROJECT = jose
PROJECT_DESCRIPTION = JSON Object Signing and Encryption (JOSE) for Erlang and Elixir.
PROJECT_VERSION = 1.9.0

TEST_DEPS = jiffy jsone jsx libdecaf libsodium ojson proper

dep_jiffy = git git://github.com/davisp/jiffy.git master
dep_jsone = git git://github.com/sile/jsone.git master
dep_jsx = git git://github.com/talentdeficit/jsx.git v2.10.0
dep_keccakf1600 = git git://github.com/potatosalad/erlang-keccakf1600.git master
dep_libdecaf = git https://github.com/talklittle/erlang-libdecaf.git otp-23-remove-erl-interface
dep_libsodium = git https://github.com/talklittle/erlang-libsodium.git otp-23-remove-erl-interface
dep_ojson = git git://github.com/potatosalad/erlang-ojson.git master
dep_proper = git git://github.com/proper-testing/proper.git v1.3

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
