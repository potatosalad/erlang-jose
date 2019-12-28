PROJECT = jose
PROJECT_DESCRIPTION = JSON Object Signing and Encryption (JOSE) for Erlang and Elixir.
PROJECT_VERSION = 1.9.0

TEST_DEPS = jiffy jsone jsx libdecaf libsodium ojson proper

dep_jiffy = git git://github.com/davisp/jiffy.git master
dep_jsone = git git://github.com/sile/jsone.git master
dep_jsx = git git://github.com/talentdeficit/jsx.git master
dep_keccakf1600 = git git://github.com/potatosalad/erlang-keccakf1600.git master
dep_libdecaf = git git://github.com/potatosalad/erlang-libdecaf.git master
dep_libsodium = git git://github.com/potatosalad/erlang-libsodium.git master
dep_ojson = git git://github.com/potatosalad/erlang-ojson.git master
dep_proper = git git://github.com/proper-testing/proper.git v1.3

include erlang.mk

.PHONY: docker-build docker-load docker-setup docker-save docker-shell docker-test

DOCKER_OTP_VERSION ?= 22.2.1

docker-build::
	$(gen_verbose) docker build \
		-t docker-otp-${DOCKER_OTP_VERSION} \
		-f test/Dockerfile \
		--build-arg OTP_VERSION=${DOCKER_OTP_VERSION} \
		test

docker-load::
	$(gen_verbose) docker load \
		-i "docker-otp-${DOCKER_OTP_VERSION}/image.tar"

docker-save::
	$(verbose) mkdir -p "docker-otp-${DOCKER_OTP_VERSION}"
	$(gen_verbose) docker save \
		-o "docker-otp-${DOCKER_OTP_VERSION}/image.tar" \
		docker-otp-${DOCKER_OTP_VERSION}

docker-setup::
	$(verbose) if [ -f "docker-otp-${DOCKER_OTP_VERSION}/image.tar" ]; then \
		$(MAKE) docker-load; \
	else \
		$(MAKE) docker-build; \
		$(MAKE) docker-save; \
	fi

docker-shell::
	$(verbose) docker run \
		-v "$(shell pwd)":"/build/jose" --rm -it "docker-otp-${DOCKER_OTP_VERSION}" \
		/bin/bash -l

docker-test::
	$(gen_verbose) docker run \
		-v "$(shell pwd)":"/build/jose" "docker-otp-${DOCKER_OTP_VERSION}" \
		sh -c 'cd jose && make tests'

# DOCKER_OTP_VERSION ?= 21.2
# DOCKER_ELIXIR_VERSION ?= 1.7.4

# docker-build::
# 	$(gen_verbose) docker build \
# 		-t docker-otp-${DOCKER_OTP_VERSION}-elixir-${DOCKER_ELIXIR_VERSION} \
# 		-f priv/Dockerfile \
# 		--build-arg OTP_VERSION=${DOCKER_OTP_VERSION} \
# 		--build-arg ELIXIR_VERSION=${DOCKER_ELIXIR_VERSION} priv

# docker-load::
# 	$(gen_verbose) docker load \
# 		-i "docker-otp-${DOCKER_OTP_VERSION}-elixir-${DOCKER_ELIXIR_VERSION}/image.tar"

# docker-save::
# 	$(verbose) mkdir -p "docker-otp-${DOCKER_OTP_VERSION}-elixir-${DOCKER_ELIXIR_VERSION}"
# 	$(gen_verbose) docker save \
# 		-o "docker-otp-${DOCKER_OTP_VERSION}-elixir-${DOCKER_ELIXIR_VERSION}/image.tar" \
# 		docker-otp-${DOCKER_OTP_VERSION}-elixir-${DOCKER_ELIXIR_VERSION}

# docker-setup::
# 	$(verbose) if [ -f "docker-otp-${DOCKER_OTP_VERSION}-elixir-${DOCKER_ELIXIR_VERSION}/image.tar" ]; then \
# 		$(MAKE) docker-load; \
# 	else \
# 		$(MAKE) docker-build; \
# 		$(MAKE) docker-save; \
# 	fi

# docker-test::
# 	$(gen_verbose) docker run \
# 		-v "$(shell pwd)":"/build/jose" "docker-otp-${DOCKER_OTP_VERSION}-elixir-${DOCKER_ELIXIR_VERSION}" \
# 		sh -c 'cd jose && mix local.hex --force && mix local.rebar --force && mix deps.get && mix test && rm -rf _build deps ebin && make ct'
