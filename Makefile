PROJECT = jose
DEPS = base64url
dep_base64url = git git://github.com/dvv/base64url.git master
TEST_DEPS = cutkey jsx triq
dep_cutkey = git git://github.com/potatosalad/cutkey.git master
dep_jsx = git git://github.com/talentdeficit/jsx.git master
dep_triq = git git://github.com/krestenkrab/triq.git master
include erlang.mk
