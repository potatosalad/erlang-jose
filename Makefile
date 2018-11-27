PROJECT = jose
PROJECT_DESCRIPTION = JSON Object Signing and Encryption (JOSE) for Erlang and Elixir.
PROJECT_VERSION = 1.8.4

DEPS = base64url

dep_base64url = git git://github.com/dvv/base64url.git master

TEST_DEPS = cutkey jiffy jsone jsx libdecaf libsodium ojson proper

dep_cutkey = git git://github.com/potatosalad/cutkey.git master
dep_jiffy = git git://github.com/davisp/jiffy.git master
dep_jsone = git git://github.com/sile/jsone.git master
dep_jsx = git git://github.com/talentdeficit/jsx.git master
dep_keccakf1600 = git git://github.com/potatosalad/erlang-keccakf1600.git master
dep_libdecaf = git git://github.com/potatosalad/erlang-libdecaf.git master
dep_libsodium = git git://github.com/potatosalad/erlang-libsodium.git master
dep_ojson = git git://github.com/potatosalad/erlang-ojson.git master
dep_proper = git git://github.com/proper-testing/proper.git v1.3

include erlang.mk
