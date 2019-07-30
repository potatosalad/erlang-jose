ARG OTP_VERSION=alpine
FROM erlang:${OTP_VERSION}-alpine

# Setup environment
ENV LANG=C.UTF-8 TERM=xterm

# Add dependencies
RUN apk upgrade --update musl && \
    apk add --no-cache autoconf automake bash bc build-base curl git libtool make openssl python rsync unzip && \
    rm -rf /var/cache/apk/*

RUN mkdir /build
WORKDIR /build
