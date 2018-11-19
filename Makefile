PROJECT = jose
PROJECT_DESCRIPTION = JSON Object Signing and Encryption (JOSE) for Erlang and Elixir.
PROJECT_VERSION = 1.8.5

DEPS = base64url

dep_base64url = git git://github.com/dvv/base64url.git master

TEST_DEPS = cutkey jiffy jsone jsx libdecaf libsodium ojson triq

dep_cutkey = git git://github.com/potatosalad/cutkey.git master
dep_jiffy = git git://github.com/davisp/jiffy.git master
dep_jsone = git git://github.com/sile/jsone.git master
dep_jsx = git git://github.com/talentdeficit/jsx.git master
dep_keccakf1600 = git git://github.com/potatosalad/erlang-keccakf1600.git master
dep_libdecaf = git git://github.com/potatosalad/erlang-libdecaf.git master
dep_libsodium = git git://github.com/potatosalad/erlang-libsodium.git master
dep_ojson = git git://github.com/potatosalad/erlang-ojson.git master
dep_triq = git git://github.com/krestenkrab/triq.git master

include erlang.mk

otp_release = $(shell erl -noshell -eval 'io:fwrite("~s\n", [erlang:system_info(otp_release)]).' -s erlang halt)
otp_ge_17 = $(shell echo $(otp_release) | grep -q -E "^[[:digit:]]+$$" && echo true)
ifeq ($(otp_ge_17),true)
	otp_ge_18 = $(shell [ $(otp_release) -ge "18" ] && echo true)
endif

ifeq ($(otp_ge_18),true)
	ERLC_OPTS += -Doptional_callbacks=1
	TEST_ERLC_OPTS += -Doptional_callbacks=1
endif
