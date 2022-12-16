#!/usr/bin/env bash

set -eo pipefail
set -x

erlc +debug_info jose_base.erl
erlc -pa . +debug_info jose_base64.erl
../erlfmt --write --require-pragma --print-width=132 jose_base64.encode_char.erl
../erlfmt --write --require-pragma --print-width=132 jose_base64.encode_pair.erl
erlc -pa . +debug_info jose_base64url.erl
../erlfmt --write --require-pragma --print-width=132 jose_base64url.encode_char.erl
../erlfmt --write --require-pragma --print-width=132 jose_base64url.encode_pair.erl

exit 0
