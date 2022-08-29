ARG OTP_VERSION
FROM hexpm/erlang:${OTP_VERSION}

# Setup environment
ENV LANG=C.UTF-8 TERM=xterm

# Add dependencies
RUN apk upgrade --update musl && \
    apk add --no-cache autoconf automake bash bc build-base cmake curl git libtool make openssl python3 rsync unzip && \
    rm -rf /var/cache/apk/* && \
    ln -s /usr/bin/python3 /usr/bin/python

RUN mkdir /build
WORKDIR /build
