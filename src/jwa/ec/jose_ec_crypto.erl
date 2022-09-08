%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2022, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  08 Sep 2022 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_ec_crypto).

-include_lib("public_key/include/public_key.hrl").

-behaviour(jose_provider).
-behaviour(jose_ec).

%% jose_provider callbacks
-export([provider_info/0]).
%% jose_ec callbacks
-export([
    ec_secp256k1_keypair/0,
	ec_secp256k1_keypair/1,
	ec_secp256k1_secret_to_public/1,
	ecdh_secp256k1_shared_secret/2,
	ecdsa_secp256k1_sha256_sign/2,
	ecdsa_secp256k1_sha256_verify/3,
	ec_secp256r1_keypair/0,
	ec_secp256r1_keypair/1,
	ec_secp256r1_secret_to_public/1,
	ecdh_secp256r1_shared_secret/2,
	ecdsa_secp256r1_sha256_sign/2,
	ecdsa_secp256r1_sha256_verify/3,
	ec_secp384r1_keypair/0,
	ec_secp384r1_keypair/1,
	ec_secp384r1_secret_to_public/1,
	ecdh_secp384r1_shared_secret/2,
	ecdsa_secp384r1_sha384_sign/2,
	ecdsa_secp384r1_sha384_verify/3,
	ec_secp521r1_keypair/0,
	ec_secp521r1_keypair/1,
	ec_secp521r1_secret_to_public/1,
	ecdh_secp521r1_shared_secret/2,
	ecdsa_secp521r1_sha512_sign/2,
	ecdsa_secp521r1_sha512_verify/3
]).

%%====================================================================
%% jose_provider callbacks
%%====================================================================

-spec provider_info() -> jose_provider:info().
provider_info() ->
	#{
		behaviour => jose_ec,
		priority => high,
		requirements => [
			{app, crypto},
			crypto
		]
	}.

%%====================================================================
%% jose_ec callbacks
%%====================================================================

-spec ec_secp256k1_keypair() -> {PublicKey, SecretKey} when
	PublicKey :: jose_ec:ec_secp256k1_public_key(),
	SecretKey :: jose_ec:ec_secp256k1_secret_key().
ec_secp256k1_keypair() ->
	{DerPK, SK} = crypto:generate_key(ecdh, secp256k1),
    PK = ec_secp256k1_public_key_pack(DerPK),
    {PK, SK}.

-spec ec_secp256k1_keypair(Seed) -> {PublicKey, SecretKey} when
	Seed :: jose_ec:ec_secp256k1_seed(),
	PublicKey :: jose_ec:ec_secp256k1_public_key(),
	SecretKey :: jose_ec:ec_secp256k1_secret_key().
ec_secp256k1_keypair(Seed)
		when bit_size(Seed) =:= 256 ->
	{DerPK, SK} = crypto:generate_key(ecdh, secp256k1, Seed),
    PK = ec_secp256k1_public_key_pack(DerPK),
    {PK, SK}.

-spec ec_secp256k1_secret_to_public(SecretKey) -> PublicKey when
	SecretKey :: jose_ec:ec_secp256k1_secret_key(),
	PublicKey :: jose_ec:ec_secp256k1_public_key().
ec_secp256k1_secret_to_public(SecretKey)
		when bit_size(SecretKey) =:= 256 ->
	{DerPK, _SK} = crypto:generate_key(ecdh, secp256k1, SecretKey),
    PK = ec_secp256k1_public_key_pack(DerPK),
    PK.

-spec ecdh_secp256k1_shared_secret(MySecretKey, YourPublicKey) -> SharedSecret when
	MySecretKey :: jose_ec:ec_secp256k1_secret_key(),
	YourPublicKey :: jose_ec:ec_secp256k1_public_key(),
	SharedSecret :: jose_ec:ecdh_secp256k1_shared_secret().
ecdh_secp256k1_shared_secret(MySecretKey, YourPublicKey)
		when bit_size(MySecretKey) =:= 256
		andalso bit_size(YourPublicKey) =:= 512 ->
    YourDerPK = ec_secp256k1_public_key_unpack(YourPublicKey),
    crypto:compute_key(ecdh, YourDerPK, MySecretKey, secp256k1).

-spec ecdsa_secp256k1_sha256_sign(Message, SecretKey) -> Signature when
    Message :: jose_ec:message(),
    SecretKey :: jose_ec:ec_secp256k1_secret_key(),
    Signature :: jose_ec:ecdsa_secp256k1_sha256_signature().
ecdsa_secp256k1_sha256_sign(Message, SecretKey)
		when is_binary(Message)
		andalso bit_size(SecretKey) =:= 256 ->
    DerSignature = crypto:sign(ecdsa, sha256, Message, [SecretKey, secp256k1]),
	ecdsa_secp256k1_sha256_signature_pack(DerSignature).

-spec ecdsa_secp256k1_sha256_verify(Signature, Message, PublicKey) -> boolean() when
    Signature :: jose_ec:maybe_invalid_signature(jose_ec:ecdsa_secp256k1_sha256_signature()),
    Message :: jose_ec:message(),
    PublicKey :: jose_ec:ec_secp256k1_public_key().
ecdsa_secp256k1_sha256_verify(Signature, Message, PublicKey)
		when is_binary(Signature)
		andalso is_binary(Message)
		andalso bit_size(PublicKey) =:= 512 ->
    case ecdsa_secp256k1_sha256_signature_unpack(Signature) of
        DerSignature when is_binary(DerSignature) ->
            DerPK = ec_secp256k1_public_key_unpack(PublicKey),
            crypto:verify(ecdsa, sha256, Message, DerSignature, [DerPK, secp256k1]);
        error ->
            false
    end.

-spec ec_secp256r1_keypair() -> {PublicKey, SecretKey} when
	PublicKey :: jose_ec:ec_secp256r1_public_key(),
	SecretKey :: jose_ec:ec_secp256r1_secret_key().
ec_secp256r1_keypair() ->
	{DerPK, SK} = crypto:generate_key(ecdh, secp256r1),
    PK = ec_secp256r1_public_key_pack(DerPK),
    {PK, SK}.

-spec ec_secp256r1_keypair(Seed) -> {PublicKey, SecretKey} when
	Seed :: jose_ec:ec_secp256r1_seed(),
	PublicKey :: jose_ec:ec_secp256r1_public_key(),
	SecretKey :: jose_ec:ec_secp256r1_secret_key().
ec_secp256r1_keypair(Seed)
		when bit_size(Seed) =:= 256 ->
	{DerPK, SK} = crypto:generate_key(ecdh, secp256r1, Seed),
    PK = ec_secp256r1_public_key_pack(DerPK),
    {PK, SK}.

-spec ec_secp256r1_secret_to_public(SecretKey) -> PublicKey when
	SecretKey :: jose_ec:ec_secp256r1_secret_key(),
	PublicKey :: jose_ec:ec_secp256r1_public_key().
ec_secp256r1_secret_to_public(SecretKey)
		when bit_size(SecretKey) =:= 256 ->
	{DerPK, _SK} = crypto:generate_key(ecdh, secp256r1, SecretKey),
    PK = ec_secp256r1_public_key_pack(DerPK),
    PK.

-spec ecdh_secp256r1_shared_secret(MySecretKey, YourPublicKey) -> SharedSecret when
	MySecretKey :: jose_ec:ec_secp256r1_secret_key(),
	YourPublicKey :: jose_ec:ec_secp256r1_public_key(),
	SharedSecret :: jose_ec:ecdh_secp256r1_shared_secret().
ecdh_secp256r1_shared_secret(MySecretKey, YourPublicKey)
		when bit_size(MySecretKey) =:= 256
		andalso bit_size(YourPublicKey) =:= 512 ->
    YourDerPK = ec_secp256r1_public_key_unpack(YourPublicKey),
    crypto:compute_key(ecdh, YourDerPK, MySecretKey, secp256r1).

-spec ecdsa_secp256r1_sha256_sign(Message, SecretKey) -> Signature when
    Message :: jose_ec:message(),
    SecretKey :: jose_ec:ec_secp256r1_secret_key(),
    Signature :: jose_ec:ecdsa_secp256r1_sha256_signature().
ecdsa_secp256r1_sha256_sign(Message, SecretKey)
		when is_binary(Message)
		andalso bit_size(SecretKey) =:= 256 ->
    DerSignature = crypto:sign(ecdsa, sha256, Message, [SecretKey, secp256r1]),
	ecdsa_secp256r1_sha256_signature_pack(DerSignature).

-spec ecdsa_secp256r1_sha256_verify(Signature, Message, PublicKey) -> boolean() when
    Signature :: jose_ec:maybe_invalid_signature(jose_ec:ecdsa_secp256r1_sha256_signature()),
    Message :: jose_ec:message(),
    PublicKey :: jose_ec:ec_secp256r1_public_key().
ecdsa_secp256r1_sha256_verify(Signature, Message, PublicKey)
		when is_binary(Signature)
		andalso is_binary(Message)
		andalso bit_size(PublicKey) =:= 512 ->
    case ecdsa_secp256r1_sha256_signature_unpack(Signature) of
        DerSignature when is_binary(DerSignature) ->
            DerPK = ec_secp256r1_public_key_unpack(PublicKey),
            crypto:verify(ecdsa, sha256, Message, DerSignature, [DerPK, secp256r1]);
        error ->
            false
    end.

-spec ec_secp384r1_keypair() -> {PublicKey, SecretKey} when
	PublicKey :: jose_ec:ec_secp384r1_public_key(),
	SecretKey :: jose_ec:ec_secp384r1_secret_key().
ec_secp384r1_keypair() ->
	{DerPK, SK} = crypto:generate_key(ecdh, secp384r1),
    PK = ec_secp384r1_public_key_pack(DerPK),
    {PK, SK}.

-spec ec_secp384r1_keypair(Seed) -> {PublicKey, SecretKey} when
	Seed :: jose_ec:ec_secp384r1_seed(),
	PublicKey :: jose_ec:ec_secp384r1_public_key(),
	SecretKey :: jose_ec:ec_secp384r1_secret_key().
ec_secp384r1_keypair(Seed)
		when bit_size(Seed) =:= 384 ->
	{DerPK, SK} = crypto:generate_key(ecdh, secp384r1, Seed),
    PK = ec_secp384r1_public_key_pack(DerPK),
    {PK, SK}.

-spec ec_secp384r1_secret_to_public(SecretKey) -> PublicKey when
	SecretKey :: jose_ec:ec_secp384r1_secret_key(),
	PublicKey :: jose_ec:ec_secp384r1_public_key().
ec_secp384r1_secret_to_public(SecretKey)
		when bit_size(SecretKey) =:= 384 ->
	{DerPK, _SK} = crypto:generate_key(ecdh, secp384r1, SecretKey),
    PK = ec_secp384r1_public_key_pack(DerPK),
    PK.

-spec ecdh_secp384r1_shared_secret(MySecretKey, YourPublicKey) -> SharedSecret when
	MySecretKey :: jose_ec:ec_secp384r1_secret_key(),
	YourPublicKey :: jose_ec:ec_secp384r1_public_key(),
	SharedSecret :: jose_ec:ecdh_secp384r1_shared_secret().
ecdh_secp384r1_shared_secret(MySecretKey, YourPublicKey)
		when bit_size(MySecretKey) =:= 384
		andalso bit_size(YourPublicKey) =:= 768 ->
    YourDerPK = ec_secp384r1_public_key_unpack(YourPublicKey),
    crypto:compute_key(ecdh, YourDerPK, MySecretKey, secp384r1).

-spec ecdsa_secp384r1_sha384_sign(Message, SecretKey) -> Signature when
    Message :: jose_ec:message(),
    SecretKey :: jose_ec:ec_secp384r1_secret_key(),
    Signature :: jose_ec:ecdsa_secp384r1_sha384_signature().
ecdsa_secp384r1_sha384_sign(Message, SecretKey)
		when is_binary(Message)
		andalso bit_size(SecretKey) =:= 384 ->
    DerSignature = crypto:sign(ecdsa, sha384, Message, [SecretKey, secp384r1]),
	ecdsa_secp384r1_sha384_signature_pack(DerSignature).

-spec ecdsa_secp384r1_sha384_verify(Signature, Message, PublicKey) -> boolean() when
    Signature :: jose_ec:maybe_invalid_signature(jose_ec:ecdsa_secp384r1_sha384_signature()),
    Message :: jose_ec:message(),
    PublicKey :: jose_ec:ec_secp384r1_public_key().
ecdsa_secp384r1_sha384_verify(Signature, Message, PublicKey)
		when is_binary(Signature)
		andalso is_binary(Message)
		andalso bit_size(PublicKey) =:= 768 ->
    case ecdsa_secp384r1_sha384_signature_unpack(Signature) of
        DerSignature when is_binary(DerSignature) ->
            DerPK = ec_secp384r1_public_key_unpack(PublicKey),
            crypto:verify(ecdsa, sha384, Message, DerSignature, [DerPK, secp384r1]);
        error ->
            false
    end.

-spec ec_secp521r1_keypair() -> {PublicKey, SecretKey} when
	PublicKey :: jose_ec:ec_secp521r1_public_key(),
	SecretKey :: jose_ec:ec_secp521r1_secret_key().
ec_secp521r1_keypair() ->
	{DerPK, SK} = crypto:generate_key(ecdh, secp521r1),
    PK = ec_secp521r1_public_key_pack(DerPK),
    {PK, SK}.

-spec ec_secp521r1_keypair(Seed) -> {PublicKey, SecretKey} when
	Seed :: jose_ec:ec_secp521r1_seed(),
	PublicKey :: jose_ec:ec_secp521r1_public_key(),
	SecretKey :: jose_ec:ec_secp521r1_secret_key().
ec_secp521r1_keypair(Seed)
		when bit_size(Seed) =:= 528 ->
	{DerPK, SK} = crypto:generate_key(ecdh, secp521r1, Seed),
    PK = ec_secp521r1_public_key_pack(DerPK),
    {PK, SK}.

-spec ec_secp521r1_secret_to_public(SecretKey) -> PublicKey when
	SecretKey :: jose_ec:ec_secp521r1_secret_key(),
	PublicKey :: jose_ec:ec_secp521r1_public_key().
ec_secp521r1_secret_to_public(SecretKey)
		when bit_size(SecretKey) =:= 528 ->
	{DerPK, _SK} = crypto:generate_key(ecdh, secp521r1, SecretKey),
    PK = ec_secp521r1_public_key_pack(DerPK),
    PK.

-spec ecdh_secp521r1_shared_secret(MySecretKey, YourPublicKey) -> SharedSecret when
	MySecretKey :: jose_ec:ec_secp521r1_secret_key(),
	YourPublicKey :: jose_ec:ec_secp521r1_public_key(),
	SharedSecret :: jose_ec:ecdh_secp521r1_shared_secret().
ecdh_secp521r1_shared_secret(MySecretKey, YourPublicKey)
		when bit_size(MySecretKey) =:= 528
		andalso bit_size(YourPublicKey) =:= 1056 ->
    YourDerPK = ec_secp521r1_public_key_unpack(YourPublicKey),
    crypto:compute_key(ecdh, YourDerPK, MySecretKey, secp521r1).

-spec ecdsa_secp521r1_sha512_sign(Message, SecretKey) -> Signature when
    Message :: jose_ec:message(),
    SecretKey :: jose_ec:ec_secp521r1_secret_key(),
    Signature :: jose_ec:ecdsa_secp521r1_sha512_signature().
ecdsa_secp521r1_sha512_sign(Message, SecretKey)
		when is_binary(Message)
		andalso bit_size(SecretKey) =:= 528 ->
    DerSignature = crypto:sign(ecdsa, sha512, Message, [SecretKey, secp521r1]),
	ecdsa_secp521r1_sha512_signature_pack(DerSignature).

-spec ecdsa_secp521r1_sha512_verify(Signature, Message, PublicKey) -> boolean() when
    Signature :: jose_ec:maybe_invalid_signature(jose_ec:ecdsa_secp521r1_sha512_signature()),
    Message :: jose_ec:message(),
    PublicKey :: jose_ec:ec_secp521r1_public_key().
ecdsa_secp521r1_sha512_verify(Signature, Message, PublicKey)
		when is_binary(Signature)
		andalso is_binary(Message)
		andalso bit_size(PublicKey) =:= 1056 ->
    case ecdsa_secp521r1_sha512_signature_unpack(Signature) of
        DerSignature when is_binary(DerSignature) ->
            DerPK = ec_secp521r1_public_key_unpack(PublicKey),
            crypto:verify(ecdsa, sha512, Message, DerSignature, [DerPK, secp521r1]);
        error ->
            false
    end.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
ec_secp256k1_public_key_pack(<<4, X:256/bits, Y:256/bits>>) ->
    <<X:256/bits, Y:256/bits>>.

%% @private
ec_secp256k1_public_key_unpack(<<X:256/bits, Y:256/bits>>) ->
    <<4, X:256/bits, Y:256/bits>>.

%% @private
ecdsa_secp256k1_sha256_signature_pack(DerSignature) ->
    #'ECDSA-Sig-Value'{ r = R, s = S } = public_key:der_decode('ECDSA-Sig-Value', DerSignature),
    <<R:256/unsigned-big-integer-unit:1, S:256/unsigned-big-integer-unit:1>>.

%% @private
ecdsa_secp256k1_sha256_signature_unpack(<<R:256/unsigned-big-integer-unit:1, S:256/unsigned-big-integer-unit:1>>) ->
    public_key:der_encode('ECDSA-Sig-Value', #'ECDSA-Sig-Value'{ r = R, s = S });
ecdsa_secp256k1_sha256_signature_unpack(_) ->
    error.

%% @private
ec_secp256r1_public_key_pack(<<4, X:256/bits, Y:256/bits>>) ->
    <<X:256/bits, Y:256/bits>>.

%% @private
ec_secp256r1_public_key_unpack(<<X:256/bits, Y:256/bits>>) ->
    <<4, X:256/bits, Y:256/bits>>.

%% @private
ecdsa_secp256r1_sha256_signature_pack(DerSignature) ->
    #'ECDSA-Sig-Value'{ r = R, s = S } = public_key:der_decode('ECDSA-Sig-Value', DerSignature),
    <<R:256/unsigned-big-integer-unit:1, S:256/unsigned-big-integer-unit:1>>.

%% @private
ecdsa_secp256r1_sha256_signature_unpack(<<R:256/unsigned-big-integer-unit:1, S:256/unsigned-big-integer-unit:1>>) ->
    public_key:der_encode('ECDSA-Sig-Value', #'ECDSA-Sig-Value'{ r = R, s = S });
ecdsa_secp256r1_sha256_signature_unpack(_) ->
    error.

%% @private
ec_secp384r1_public_key_pack(<<4, X:384/bits, Y:384/bits>>) ->
    <<X:384/bits, Y:384/bits>>.

%% @private
ec_secp384r1_public_key_unpack(<<X:384/bits, Y:384/bits>>) ->
    <<4, X:384/bits, Y:384/bits>>.

%% @private
ecdsa_secp384r1_sha384_signature_pack(DerSignature) ->
    #'ECDSA-Sig-Value'{ r = R, s = S } = public_key:der_decode('ECDSA-Sig-Value', DerSignature),
    <<R:384/unsigned-big-integer-unit:1, S:384/unsigned-big-integer-unit:1>>.

%% @private
ecdsa_secp384r1_sha384_signature_unpack(<<R:384/unsigned-big-integer-unit:1, S:384/unsigned-big-integer-unit:1>>) ->
    public_key:der_encode('ECDSA-Sig-Value', #'ECDSA-Sig-Value'{ r = R, s = S });
ecdsa_secp384r1_sha384_signature_unpack(_) ->
    error.

%% @private
ec_secp521r1_public_key_pack(<<4, X:528/bits, Y:528/bits>>) ->
    <<X:528/bits, Y:528/bits>>.

%% @private
ec_secp521r1_public_key_unpack(<<X:528/bits, Y:528/bits>>) ->
    <<4, X:528/bits, Y:528/bits>>.

%% @private
ecdsa_secp521r1_sha512_signature_pack(DerSignature) ->
    #'ECDSA-Sig-Value'{ r = R, s = S } = public_key:der_decode('ECDSA-Sig-Value', DerSignature),
    <<R:528/unsigned-big-integer-unit:1, S:528/unsigned-big-integer-unit:1>>.

%% @private
ecdsa_secp521r1_sha512_signature_unpack(<<R:528/unsigned-big-integer-unit:1, S:528/unsigned-big-integer-unit:1>>) ->
    public_key:der_encode('ECDSA-Sig-Value', #'ECDSA-Sig-Value'{ r = R, s = S });
ecdsa_secp521r1_sha512_signature_unpack(_) ->
    error.
