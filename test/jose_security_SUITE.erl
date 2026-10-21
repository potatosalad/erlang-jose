%% Security regressions through public APIs and the affected fallback paths.
-module(jose_security_SUITE).

-include_lib("common_test/include/ct.hrl").
-include_lib("public_key/include/public_key.hrl").
-include("jose.hrl").
-include("jose_public_key.hrl").

-export([all/0, init_per_suite/1, end_per_suite/1]).
-export([gcm_tag_lengths/1, gcm_public_forgery/1, ecdsa_lengths/1,
         zip_public_limit/1, rsa_public_rejection/1, shared_secret_types/1,
         password_export_and_legacy_import/1, curve_providers/1]).

%% Configuration mutations below must run serially and be restored.
all() ->
    [gcm_tag_lengths, gcm_public_forgery, ecdsa_lengths, zip_public_limit,
     rsa_public_rejection, shared_secret_types, password_export_and_legacy_import,
     curve_providers].

init_per_suite(Config) ->
    {ok, _} = application:ensure_all_started(jose),
    Config.

end_per_suite(_Config) ->
    ok = application:stop(jose).

gcm_tag_lengths(_Config) ->
    lists:foreach(fun(Bits) ->
        Cipher = {aes_gcm, Bits},
        Key = crypto:strong_rand_bytes(Bits div 8),
        IV = crypto:strong_rand_bytes(12),
        Plain = <<"authenticated plaintext">>,
        AAD = <<"protected">>,
        {CT, Tag} = jose_jwa_aes:block_encrypt(Cipher, Key, IV, {AAD, Plain}),
        Plain = jose_jwa_aes:block_decrypt(Cipher, Key, IV, {AAD, CT, Tag}),
        lists:foreach(fun(Len) ->
            Invalid = case Len < 16 of
                true -> binary:part(Tag, 0, Len);
                false -> <<Tag/binary, 0:((Len - 16) * 8)>>
            end,
            error = jose_jwa_aes:block_decrypt(Cipher, Key, IV, {AAD, CT, Invalid}),
            error = jose_jwa:block_decrypt(Cipher, Key, IV, {AAD, CT, Invalid})
        end, lists:seq(0, 15) ++ lists:seq(17, 32)),
        <<First, Rest/binary>> = Tag,
        error = jose_jwa_aes:block_decrypt(Cipher, Key, IV, {AAD, CT, <<(First bxor 1), Rest/binary>>})
    end, [128, 192, 256]),
    ok.

gcm_public_forgery(_Config) ->
    Cipher = {aes_gcm, 256},
    JWK = jose_jwk:from_oct(crypto:strong_rand_bytes(32)),
    Plain = <<"victim plaintext">>,
    {Modules, Encrypted} = jose_jwe:block_encrypt(JWK, Plain, #{<<"alg">> => <<"dir">>, <<"enc">> => <<"A256GCM">>}),
    Original = ets:lookup_element(jose_jwa, {cipher, Cipher}, 2),
    try
        lists:foreach(fun(Provider) ->
            true = ets:insert(jose_jwa, {{cipher, Cipher}, Provider}),
            {Plain, _} = jose_jwe:block_decrypt(JWK, {Modules, Encrypted}),
            {_, Compact} = jose_jwe:compact({Modules, Encrypted}),
            {Plain, _} = jose_jwe:block_decrypt(JWK, Compact),
            Forged = Encrypted#{<<"ciphertext">> => b64(<<"attacker chosen ciphertext">>)},
            %% Enumerate every possible 8-bit tag, with no key knowledge.
            lists:foreach(fun(Byte) ->
                Attack = Forged#{<<"tag">> => b64(<<Byte>>)},
                {error, _} = jose_jwe:block_decrypt(JWK, {Modules, Attack})
            end, lists:seq(0, 255)),
            lists:foreach(fun(Len) ->
                {error, _} = jose_jwe:block_decrypt(JWK, {Modules, Forged#{<<"tag">> => b64(<<0:(Len * 8)>>)}})
            end, [0, 2, 8, 12, 15, 16, 17, 32])
        end, [Original, {jose_jwa_aes, Cipher}])
    after
        true = ets:insert(jose_jwa, {{cipher, Cipher}, Original})
    end,
    ok.

ecdsa_lengths(_Config) ->
    lists:foreach(fun({Curve, Alg, Size}) ->
        Private = jose_jwk:generate_key({ec, Curve}),
        Public = jose_jwk:to_public(Private),
        Message = <<"unchanged signed payload">>,
        {Modules, Signed} = jose_jws:sign(Private, Message, #{<<"alg">> => Alg}),
        {true, Message, _} = jose_jws:verify(Public, {Modules, Signed}),
        Signature = jose_jwa_base64url:decode(maps:get(<<"signature">>, Signed)),
        Size = byte_size(Signature),
        Half = Size div 2,
        <<R:Half/binary, S:Half/binary>> = Signature,
        lists:foreach(fun(Pad) ->
            Zeros = binary:copy(<<0>>, Pad),
            Attack = Signed#{<<"signature">> => b64(<<Zeros/binary, R/binary, Zeros/binary, S/binary>>)},
            {false, Message, _} = jose_jws:verify(Public, {Modules, Attack}),
            {_, Compact} = jose_jws:compact({Modules, Attack}),
            {false, Message, _} = jose_jws:verify(Public, Compact)
        end, [1, 2, 8]),
        lists:foreach(fun(Len) ->
            Attack = Signed#{<<"signature">> => b64(binary:part(Signature, 0, Len))},
            {false, Message, _} = jose_jws:verify(Public, {Modules, Attack})
        end, lists:seq(0, Size - 1))
    end, [{<<"P-256">>, <<"ES256">>, 64}, {<<"P-384">>, <<"ES384">>, 96},
          {<<"P-521">>, <<"ES512">>, 132}, {<<"secp256k1">>, <<"ES256K">>, 64}]),
    ok.

zip_public_limit(_Config) ->
    Original = jose:zip_size_maximum(),
    Private = jose_jwk:generate_key({rsa, 2048}),
    Public = jose_jwk:to_public(Private),
    Header = #{<<"alg">> => <<"RSA-OAEP">>, <<"enc">> => <<"A256GCM">>, <<"zip">> => <<"DEF">>},
    try
        %% Cross the safeInflate chunk boundary and accept the exact maximum.
        Limit = 32768,
        ok = jose:zip_size_maximum(Limit),
        Plain = binary:copy(<<0>>, Limit),
        {Plain, _} = jose_jwe:block_decrypt(Private, jose_jwe:block_encrypt(Public, Plain, Header)),
        Bomb = binary:copy(<<0>>, 16 * 1024 * 1024),
        {_, Compact} = jose_jwe:compact(jose_jwe:block_encrypt(Public, Bomb, Header)),
        ct:pal("public-key bomb: ~p bytes expand to ~p; cap ~p", [byte_size(Compact), byte_size(Bomb), Limit]),
        rejects(fun() -> jose_jwe:block_decrypt(Private, Compact) end),
        rejects(fun() -> jose_jwe_zip:uncompress(jose_jwe_zip:compress(<<Plain/binary, 0>>, zlib), zlib) end),
        ok = jose:zip_size_maximum(0),
        <<>> = jose_jwe_zip:uncompress(jose_jwe_zip:compress(<<>>, zlib), zlib),
        rejects(fun() -> jose_jwe_zip:uncompress(jose_jwe_zip:compress(<<0>>, zlib), zlib) end),
        ok = jose:zip_size_maximum(Limit + 1),
        Larger = <<Plain/binary, 0>>,
        Larger = jose_jwe_zip:uncompress(jose_jwe_zip:compress(Larger, zlib), zlib),
        %% Malformed and truncated streams must still fail; cleanup permits a next call.
        Compressed = jose_jwe_zip:compress(Plain, zlib),
        rejects(fun() -> jose_jwe_zip:uncompress(binary:part(Compressed, 0, byte_size(Compressed) - 2), zlib) end),
        Plain = jose_jwe_zip:uncompress(Compressed, zlib)
    after
        ok = jose:zip_size_maximum(Original)
    end,
    ok.

rsa_public_rejection(_Config) ->
    Private = jose_jwk:generate_key({rsa, 2048}),
    Public = jose_jwk:to_public(Private),
    Original = ets:lookup_element(jose_jwa, {rsa_crypt, rsa1_5}, 2),
    try
        lists:foreach(fun(Provider) ->
            true = ets:insert(jose_jwa, {{rsa_crypt, rsa1_5}, Provider}),
            lists:foreach(fun(Enc) ->
                Header = #{<<"alg">> => <<"RSA1_5">>, <<"enc">> => Enc},
                Plain = <<"valid RSA1_5 plaintext">>,
                {Modules, Map} = jose_jwe:block_encrypt(Public, Plain, Header),
                {Plain, _} = jose_jwe:block_decrypt(Private, {Modules, Map}),
                EK = jose_jwa_base64url:decode(maps:get(<<"encrypted_key">>, Map)),
                K = byte_size(EK),
                JWE = jose_jwe:from_map(Header),
                ValidKey = jose_jwe:key_decrypt(Private, EK, JWE),
                %% Valid padding with a wrong CEK length must reject too.
                {_, PublicKey} = jose_jwk:to_key(Public),
                WrongSize = public_key:encrypt_public(<<"short">>, PublicKey, [{rsa_padding, rsa_pkcs1_padding}]),
                lists:foreach(fun(BadKey) ->
                    Substitute = jose_jwe:key_decrypt(Private, BadKey, JWE),
                    true = is_binary(Substitute),
                    true = (byte_size(Substitute) =:= byte_size(ValidKey)),
                    true = (Substitute =/= ValidKey),
                    {error, _} = jose_jwe:block_decrypt(Private, {Modules, Map#{<<"encrypted_key">> => b64(BadKey)}})
                end, [<<>>, <<0:(K * 8)>>, binary:copy(<<255>>, K),
                      binary:part(EK, 0, K - 1), <<EK/binary, 0>>, WrongSize])
            end, [<<"A256GCM">>, <<"A128CBC-HS256">>, <<"A192CBC-HS384">>, <<"A256CBC-HS512">>])
        end, [Original, {jose_jwa_pkcs1, [{rsa_padding, rsa_pkcs1_padding}]}])
    after
        true = ets:insert(jose_jwa, {{rsa_crypt, rsa1_5}, Original})
    end,
    ok.

shared_secret_types(_Config) ->
    My = jose_jwk:generate_key({ec, <<"P-256">>}),
    Peer = jose_jwk:generate_key({ec, <<"P-256">>}),
    Secret = jose_jwk:shared_secret(jose_jwk:to_public(Peer), My),
    Secret = jose_jwk:shared_secret(jose_jwk:to_public(My), Peer),
    RSA = jose_jwk:to_public(jose_jwk:generate_key({rsa, 1024})),
    {_, Map} = jose_jwk:to_map(RSA),
    lists:foreach(fun(Other) ->
        rejects(fun() -> jose_jwk:shared_secret(Other, My) end)
    end, [RSA, Map, jose_jwk:from_oct(<<0:256>>), jose_jwk:from_map(#{<<"keys">> => []})]),
    ok.

password_export_and_legacy_import(_Config) ->
    Key = public_key:generate_key({namedCurve, secp256r1}),
    JWK = jose_jwk:from_key(Key),
    Password = <<"correct-horse">>,
    {_, DER} = jose_jwk:to_der(Password, JWK),
    #'EncryptedPrivateKeyInfo'{encryptionAlgorithm = Algorithm} = jose_public_key:der_decode(DER),
    Params = assert_pbes2(jose_public_key:decrypt_parameters(Algorithm)),
    JWK = jose_jwk:from_der(Password, DER),
    {_, PEM} = jose_jwk:to_pem(Password, JWK),
    [{'PrivateKeyInfo', _, Info}] = jose_public_key:pem_decode(PEM),
    _ = assert_pbes2(Info),
    JWK = jose_jwk:from_pem(Password, PEM),
    %% OTP must import the stronger export independently of our KDF path.
    Key = public_key:pem_entry_decode(hd(public_key:pem_decode(PEM)), binary_to_list(Password)),
    %% Make an independent legacy PKCS#8 PEM with OTP's serializer and the
    %% original 2048-iteration / 8-byte salt parameters. Never weaken exports.
    KDF = Params#'PBES2-params'.keyDerivationFunc,
    PBKDF2 = KDF#'PBES2-params_keyDerivationFunc'.parameters,
    LegacyKDF = KDF#'PBES2-params_keyDerivationFunc'{parameters = PBKDF2#'PBKDF2-params'{
        salt = {specified, <<0:64>>}, iterationCount = 2048}},
    Legacy = Params#'PBES2-params'{keyDerivationFunc = LegacyKDF},
    lists:foreach(fun(OID) ->
        LegacyParams = LegacyKDF#'PBES2-params_keyDerivationFunc'.parameters,
        PRF = LegacyParams#'PBKDF2-params'.prf,
        DigestKDF = LegacyKDF#'PBES2-params_keyDerivationFunc'{parameters = LegacyParams#'PBKDF2-params'{
            prf = PRF#'PBKDF2-params_prf'{algorithm = OID}}},
        DigestParams = Legacy#'PBES2-params'{keyDerivationFunc = DigestKDF},
        Entry = public_key:pem_entry_encode('PrivateKeyInfo', Key, {{"AES-256-CBC", DigestParams}, binary_to_list(Password)}),
        LegacyPEM = public_key:pem_encode([Entry]),
        JWK = jose_jwk:from_pem(Password, LegacyPEM)
    end, [?'id-hmacWithSHA1', ?'id-hmacWithSHA224', ?'id-hmacWithSHA256',
          ?'id-hmacWithSHA384', ?'id-hmacWithSHA512']),
    rejects(fun() -> jose_jwk:from_der(<<"wrong-password">>, DER) end),
    ok.

curve_providers(_Config) ->
    %% Load the actual shipped app resource, independently of test configuration.
    AppPath = filename:join(filename:dirname(code:which(jose)), "jose.app"),
    {ok, [{application, jose, Properties}]} = file:consult(AppPath),
    false = proplists:get_value(crypto_fallback, proplists:get_value(env, Properties)),
    Previous = jose:crypto_fallback(),
    try
        ok = jose:crypto_fallback(false),
        true = (jose:curve25519_module() =/= jose_curve25519_unsupported),
        true = (jose:curve448_module() =/= jose_curve448_unsupported),
        lists:foreach(fun({Module, KeyPair, Shared}) ->
            {AP, AS} = Module:KeyPair(),
            {BP, BS} = Module:KeyPair(),
            AB = Module:Shared(AS, BP),
            AB = Module:Shared(BS, AP)
        end, [{jose_curve25519_crypto, x25519_keypair, x25519_shared_secret},
              {jose_curve448_crypto, x448_keypair, x448_shared_secret}]),
        rejects(fun() -> jose_curve25519_fallback:x25519_shared_secret(<<0:256>>, <<9, 0:248>>) end),
        Scalar448 = <<0:448>>,
        Native448 = jose_curve448_crypto:x448_secret_to_public(Scalar448),
        Native448 = jose_curve448:x448_secret_to_public(Scalar448),
        %% Explicit fallback remains available for compatibility. This is
        %% a functional check, not evidence that bignum arithmetic is constant time.
        ok = jose:crypto_fallback(true),
        Scalar = <<0:256>>,
        Native = jose_curve25519_crypto:x25519_secret_to_public(Scalar),
        Native = jose_curve25519_fallback:x25519_secret_to_public(Scalar)
    after
        ok = jose:crypto_fallback(Previous)
    end,
    ok.

assert_pbes2({_Cipher, Params = #'PBES2-params'{keyDerivationFunc = KDF}}) ->
    #'PBES2-params_keyDerivationFunc'{algorithm = ?'id-PBKDF2', parameters =
        #'PBKDF2-params'{salt = {specified, Salt}, iterationCount = Count,
                        prf = #'PBKDF2-params_prf'{algorithm = ?'id-hmacWithSHA256'}}} = KDF,
    true = (byte_size(Salt) >= 16),
    true = (Count >= 600000),
    Params.

b64(Binary) -> jose_jwa_base64url:encode(Binary).

%% Bound regressions that used to spin forever. Never accept binary plaintext
%% or a parsed key as a rejection, even when a negative call returns normally.
rejects(Fun) ->
    Parent = self(),
    {Pid, Ref} = spawn_monitor(fun() ->
        Result = try Fun() of
            {error, _} -> rejected;
            error -> rejected;
            Other -> {accepted, Other}
        catch _:_ -> rejected end,
        Parent ! {self(), Result}
    end),
    receive
        {Pid, rejected} -> erlang:demonitor(Ref, [flush]), ok;
        {Pid, Other} -> ct:fail(Other);
        {'DOWN', Ref, process, Pid, Reason} -> ct:fail({unexpected_exit, Reason})
    after 3000 ->
        exit(Pid, kill),
        erlang:demonitor(Ref, [flush]),
        ct:fail(rejection_timeout)
    end.
