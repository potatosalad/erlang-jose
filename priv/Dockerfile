FROM ubuntu:xenial

ARG OTP_VERSION=local
ENV OTP_VERSION ${OTP_VERSION}

ARG ELIXIR_VERSION=local
ENV ELIXIR_VERSION ${ELIXIR_VERSION}

RUN apt-get update && \
    apt-get -y install curl && \
    curl -O https://packages.erlang-solutions.com/erlang-solutions_1.0_all.deb && \
    dpkg -i erlang-solutions_1.0_all.deb && \
    apt-get update && \
    apt-get -y install esl-erlang=1:${OTP_VERSION} elixir=${ELIXIR_VERSION}-1 git make clang-3.8 autoconf automake libtool locales openssl libssl-dev && \
    sed -i 's/^# \(en_US.UTF-8 UTF-8\)/\1/' /etc/locale.gen && \
    locale-gen

ENV LANG en_US.UTF-8
ENV CC clang-3.8
ENV CXX clang++-3.8
ENV ARCHFLAGS -Wgcc-compat
ENV MIX_ENV test

RUN mkdir /build
WORKDIR /build