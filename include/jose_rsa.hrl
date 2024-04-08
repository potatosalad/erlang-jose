%%%-----------------------------------------------------------------------------
%%% Copyright (c) Andrew Bennett
%%%
%%% This source code is licensed under the MIT license found in the
%%% LICENSE.md file in the root directory of this source tree.
%%%
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright (c) Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  08 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-----------------------------------------------------------------------------
%%% % @format
-ifndef(JOSE_RSA_HRL).

-define(is_rsa_key_integer(X), (is_binary(X) andalso byte_size(X) >= 1)).

-record(jose_rsa_public_key, {
    e = undefined :: jose_rsa:rsa_public_exponent(),
    n = undefined :: jose_rsa:rsa_modulus()
}).

-record(jose_rsa_other_prime_info, {
    r = undefined :: jose_rsa:rsa_prime_factor(),
    d = undefined :: jose_rsa:rsa_factor_crt_exponent(),
    t = undefined :: jose_rsa:rsa_factor_crt_coefficient()
}).

-record(jose_rsa_private_key, {
    e = undefined :: jose_rsa:rsa_public_exponent(),
    n = undefined :: jose_rsa:rsa_modulus(),
    d = undefined :: jose_rsa:rsa_private_exponent(),
    p = undefined :: undefined | jose_rsa:rsa_first_prime_factor(),
    q = undefined :: undefined | jose_rsa:rsa_second_prime_factor(),
    dp = undefined :: undefined | jose_rsa:rsa_first_factor_crt_exponent(),
    dq = undefined :: undefined | jose_rsa:rsa_second_factor_crt_exponent(),
    qi = undefined :: undefined | jose_rsa:rsa_first_crt_coefficient(),
    oth = [] :: [jose_rsa:rsa_other_prime_info()]
}).

-define(JOSE_RSA_HRL, 1).

-endif.
