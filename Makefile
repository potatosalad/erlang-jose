PROJECT = jose

DEPS = base64url

dep_base64url = git git://github.com/dvv/base64url.git master

TEST_DEPS = cutkey jsx triq

dep_cutkey = git git://github.com/potatosalad/cutkey.git master
dep_jsx = git git://github.com/talentdeficit/jsx.git master
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
