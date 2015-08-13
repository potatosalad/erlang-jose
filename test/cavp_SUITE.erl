%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2015, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  11 Aug 2015 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(cavp_SUITE).

-include_lib("common_test/include/ct.hrl").

-include_lib("public_key/include/public_key.hrl").
-include_lib("stdlib/include/zip.hrl").

%% ct.
-export([all/0]).
-export([groups/0]).
-export([init_per_suite/1]).
-export([end_per_suite/1]).
-export([init_per_group/2]).
-export([end_per_group/2]).

%% Tests.
-export([emc_rsa_oaep_encrypt_and_decrypt/1]).
-export([emc_rsa_pss_sign_and_verify/1]).
-export([fips_aes_encrypt_and_decrypt/1]).
-export([fips_aes_gcm_encrypt_and_decrypt/1]).
-export([fips_rsa_pss_sign/1]).
-export([fips_rsa_pss_verify/1]).
-export([pbkdf2/1]).

all() ->
	[
		{group, '186-3rsatestvectors'},
		{group, 'aesmmt'},
		{group, 'gcmtestvectors'},
		{group, 'KAT_AES'},
		{group, 'pkcs-1v2-1-vec'},
		{group, 'pkcs-5'}
	].

groups() ->
	[
		{'186-3rsatestvectors', [], [
			fips_rsa_pss_sign,
			fips_rsa_pss_verify
		]},
		{'aesmmt', [], [
			fips_aes_encrypt_and_decrypt
		]},
		{'gcmtestvectors', [], [
			fips_aes_gcm_encrypt_and_decrypt
		]},
		{'KAT_AES', [], [
			fips_aes_encrypt_and_decrypt
		]},
		{'pkcs-1v2-1-vec', [], [
			emc_rsa_oaep_encrypt_and_decrypt,
			emc_rsa_pss_sign_and_verify
		]},
		{'pkcs-5', [], [
			pbkdf2
		]}
	].

init_per_suite(Config) ->
	application:set_env(jose, crypto_fallback, true),
	_ = application:ensure_all_started(jose),
	data_setup(Config).

end_per_suite(_Config) ->
	_ = application:stop(jose),
	ok.

init_per_group('186-3rsatestvectors', Config) ->
	SigGenFile = data_file("186-3rsatestvectors/SigGenPSS_186-3.txt", Config),
	SigVerFile = data_file("186-3rsatestvectors/SigVerPSS_186-3.rsp", Config),
	[{sig_gen_file, SigGenFile}, {sig_ver_file, SigVerFile} | Config];
init_per_group('aesmmt', Config) ->
	Folder = data_file("aesmmt", Config),
	{ok, Entries} = file:list_dir(Folder),
	Files = [filename:join([Folder, Entry]) || Entry <- Entries],
	[{aes_files, Files} | Config];
init_per_group('gcmtestvectors', Config) ->
	Folder = data_file("gcmtestvectors", Config),
	{ok, Entries} = file:list_dir(Folder),
	Files = [filename:join([Folder, Entry]) || Entry <- Entries],
	[{aes_gcm_files, Files} | Config];
init_per_group('KAT_AES', Config) ->
	Folder = data_file("KAT_AES", Config),
	{ok, Entries} = file:list_dir(Folder),
	Files = [filename:join([Folder, Entry]) || Entry <- Entries],
	[{aes_files, Files} | Config];
init_per_group('pkcs-1v2-1-vec', Config) ->
	OAEPVectFile = data_file("pkcs-1v2-1-vec/oaep-vect.txt", Config),
	PSSVectFile = data_file("pkcs-1v2-1-vec/pss-vect.txt", Config),
	[{oaep_vect_file, OAEPVectFile}, {pss_vect_file, PSSVectFile} | Config];
init_per_group('pkcs-5', Config) ->
	Vectors = [
		%% See [https://tools.ietf.org/html/rfc6070]
		{sha,
			<<"password">>,
			<<"salt">>,
			1,
			20,
			hex:hex_to_bin(<<"0c60c80f961f0e71f3a9b524af6012062fe037a6">>)},
		{sha,
			<<"password">>,
			<<"salt">>,
			2,
			20,
			hex:hex_to_bin(<<"ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957">>)},
		{sha,
			<<"password">>,
			<<"salt">>,
			4096,
			20,
			hex:hex_to_bin(<<"4b007901b765489abead49d926f721d065a429c1">>)},
		{sha,
			<<"password">>,
			<<"salt">>,
			16777216,
			20,
			hex:hex_to_bin(<<"eefe3d61cd4da4e4e9945b3d6ba2158c2634e984">>)},
		{sha,
			<<"passwordPASSWORDpassword">>,
			<<"saltSALTsaltSALTsaltSALTsaltSALTsalt">>,
			4096,
			25,
			hex:hex_to_bin(<<"3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038">>)},
		{sha,
			<<"pass\0word">>,
			<<"sa\0lt">>,
			4096,
			16,
			hex:hex_to_bin(<<"56fa6aa75548099dcc37d7f03425e0c3">>)},
		%% See [http://stackoverflow.com/a/5136918/818187]
		{sha256,
			<<"password">>,
			<<"salt">>,
			1,
			32,
			hex:hex_to_bin(<<"120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b">>)},
		{sha256,
			<<"password">>,
			<<"salt">>,
			2,
			32,
			hex:hex_to_bin(<<"ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43">>)},
		{sha256,
			<<"password">>,
			<<"salt">>,
			4096,
			32,
			hex:hex_to_bin(<<"c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a">>)},
		{sha256,
			<<"password">>,
			<<"salt">>,
			16777216,
			32,
			hex:hex_to_bin(<<"cf81c66fe8cfc04d1f31ecb65dab4089f7f179e89b3b0bcb17ad10e3ac6eba46">>)},
		{sha256,
			<<"passwordPASSWORDpassword">>,
			<<"saltSALTsaltSALTsaltSALTsaltSALTsalt">>,
			4096,
			40,
			hex:hex_to_bin(<<"348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9">>)},
		{sha256,
			<<"pass\0word">>,
			<<"sa\0lt">>,
			4096,
			16,
			hex:hex_to_bin(<<"89b69d0516f829893c696226650a8687">>)}
	],
	[{vectors, Vectors} | Config].

end_per_group(_Group, _Config) ->
	ok.

%%====================================================================
%% Tests
%%====================================================================

emc_rsa_oaep_encrypt_and_decrypt(Config) ->
	Vectors = emc_testvector:from_file(?config(oaep_vect_file, Config)),
	emc_rsa_oaep_encrypt_and_decrypt(Vectors, Config).

emc_rsa_pss_sign_and_verify(Config) ->
	Vectors = emc_testvector:from_file(?config(pss_vect_file, Config)),
	emc_rsa_pss_sign_and_verify(Vectors, Config).

fips_aes_encrypt_and_decrypt(Config) ->
	Files = ?config(aes_files, Config),
	lists:foldl(fun fips_aes_encrypt_and_decrypt/2, Config, Files).

fips_aes_gcm_encrypt_and_decrypt(Config) ->
	Files = ?config(aes_gcm_files, Config),
	lists:foldl(fun fips_aes_gcm_encrypt_and_decrypt/2, Config, Files).

fips_rsa_pss_sign(Config) ->
	Vectors = fips_testvector:from_file(?config(sig_gen_file, Config)),
	fips_rsa_pss_sign(Vectors, Config).

fips_rsa_pss_verify(Config) ->
	Vectors = fips_testvector:from_file(?config(sig_ver_file, Config)),
	fips_rsa_pss_verify(Vectors, Config).

pbkdf2(Config) ->
	Vectors = ?config(vectors, Config),
	pbkdf2(Vectors, Config).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
data_file(File, Config) ->
	filename:join([?config(data_dir, Config), File]).

%% @private
data_setup(Config) ->
	lists:foldl(fun(F, C) ->
		data_setup(F, C)
	end, Config, [
		"186-3rsatestvectors.zip",
		"aesmmt.zip",
		"gcmtestvectors.zip",
		"KAT_AES.zip",
		"pkcs-1v2-1-vec.zip"
	]).

%% @private
data_setup(F = "186-3rsatestvectors.zip", Config) ->
	Zip = data_file(F, Config),
	Dir = data_file("186-3rsatestvectors", Config),
	URL = "http://csrc.nist.gov/groups/STM/cavp/documents/dss/186-3rsatestvectors.zip",
	ok = data_setup(Zip, Dir, URL),
	Filter = fun
		(#zip_file{name = "SigGenPSS_186-3.txt"}) ->
			true;
		(#zip_file{name = "SigVerPSS_186-3.rsp"}) ->
			true;
		(_) ->
			false
	end,
	ok = data_setup(Zip, Dir, "SigGenPSS_186-3.txt", Filter),
	Config;
data_setup(F = "aesmmt.zip", Config) ->
	Zip = data_file(F, Config),
	Dir = data_file("aesmmt", Config),
	URL = "http://csrc.nist.gov/groups/STM/cavp/documents/aes/aesmmt.zip",
	ok = data_setup(Zip, Dir, URL),
	Filter = fun
		(#zip_file{name = "CBC" ++ _}) ->
			true;
		(#zip_file{name = "ECB" ++ _}) ->
			true;
		(_) ->
			false
	end,
	ok = data_setup(Zip, Dir, "CBCMMT128.rsp", Filter),
	Config;
data_setup(F = "gcmtestvectors.zip", Config) ->
	Zip = data_file(F, Config),
	Dir = data_file("gcmtestvectors", Config),
	URL = "http://csrc.nist.gov/groups/STM/cavp/documents/mac/gcmtestvectors.zip",
	ok = data_setup(Zip, Dir, URL),
	case filelib:is_file(filename:join([Dir, "gcmDecrypt128.rsp"])) of
		true ->
			ok;
		false ->
			{ok, FileList} = zip:unzip(Zip, [
				{cwd, Dir}
			]),
			_ = [begin
				file:change_mode(File, 8#00644)
			end || File <- FileList],
			ok
	end,
	Config;
data_setup(F = "KAT_AES.zip", Config) ->
	Zip = data_file(F, Config),
	Dir = data_file("KAT_AES", Config),
	URL = "http://csrc.nist.gov/groups/STM/cavp/documents/aes/KAT_AES.zip",
	ok = data_setup(Zip, Dir, URL),
	Filter = fun
		(#zip_file{name = "CBC" ++ _}) ->
			true;
		(#zip_file{name = "ECB" ++ _}) ->
			true;
		(_) ->
			false
	end,
	ok = data_setup(Zip, Dir, "CBCGFSbox128.rsp", Filter),
	Config;
data_setup(F = "pkcs-1v2-1-vec.zip", Config) ->
	Zip = data_file(F, Config),
	Dir = data_file("pkcs-1v2-1-vec", Config),
	URL = "ftp://ftp.rsasecurity.com/pub/pkcs/pkcs-1/pkcs-1v2-1-vec.zip",
	ok = data_setup(Zip, Dir, URL),
	Filter = fun
		(#zip_file{name = "oaep-vect.txt"}) ->
			true;
		(#zip_file{name = "pss-vect.txt"}) ->
			true;
		(_) ->
			false
	end,
	ok = data_setup(Zip, Dir, "oaep-vect.txt", Filter),
	Config.

%% @private
data_setup(Zip, Directory, URL) ->
	case filelib:is_file(Zip) of
		true ->
			ok;
		false ->
			ok = fetch:fetch(URL, Zip)
	end,
	case filelib:is_dir(Directory) of
		true ->
			ok;
		false ->
			ok = file:make_dir(Directory)
	end,
	ok.

%% @private
data_setup(Zip, Dir, Check, Filter) ->
	case filelib:is_file(filename:join([Dir, Check])) of
		true ->
			ok;
		false ->
			Options = case is_function(Filter, 1) of
				false ->
					[{cwd, Dir}];
				true ->
					[{cwd, Dir}, {file_filter, Filter}]
			end,
			{ok, FileList} = zip:unzip(Zip, Options),
			_ = [begin
				file:change_mode(File, 8#00644)
			end || File <- FileList],
			ok
	end.

%% @private
emc_rsa_oaep_encrypt_and_decrypt([
			divider,
			{example, Example},
			{component, <<"Components of the RSA Key Pair">>},
			{vector, {<<"RSA modulus n">>, N}},
			{vector, {<<"RSA public exponent e">>, E}},
			{vector, {<<"RSA private exponent d">>, D}},
			{vector, {<<"Prime p">>, P}},
			{vector, {<<"Prime q">>, Q}},
			{vector, {<<"p's CRT exponent dP">>, DP}},
			{vector, {<<"q's CRT exponent dQ">>, DQ}},
			{vector, {<<"CRT coefficient qInv">>, QI}}
			| Vectors
		], Config) ->
	RSAPrivateKey = #'RSAPrivateKey'{
		version = 'two-prime',
		otherPrimeInfos = 'asn1_NOVALUE',
		privateExponent = crypto:bytes_to_integer(D),
		exponent1 = crypto:bytes_to_integer(DP),
		exponent2 = crypto:bytes_to_integer(DQ),
		publicExponent = crypto:bytes_to_integer(E),
		modulus = crypto:bytes_to_integer(N),
		prime1 = crypto:bytes_to_integer(P),
		prime2 = crypto:bytes_to_integer(Q),
		coefficient = crypto:bytes_to_integer(QI)
	},
	RSAPublicKey = #'RSAPublicKey'{
		publicExponent = crypto:bytes_to_integer(E),
		modulus = crypto:bytes_to_integer(N)
	},
	io:format("~s", [Example]),
	emc_rsa_oaep_encrypt_and_decrypt(Vectors, {RSAPrivateKey, RSAPublicKey}, Config);
emc_rsa_oaep_encrypt_and_decrypt([divider], _Config) ->
	ok;
emc_rsa_oaep_encrypt_and_decrypt([], _Config) ->
	ok.

%% @private
emc_rsa_oaep_encrypt_and_decrypt([
			{component, Component},
			{vector, {<<"Message to be encrypted">>, Message}},
			{vector, {<<"Seed">>, Seed}},
			{vector, {<<"Encryption">>, Encryption}}
			| Vectors
		], {RSAPrivateKey, RSAPublicKey}, Config) ->
	io:format("\t~s", [Component]),
	HashFun = sha,
	Label = <<>>,
	case jose_jwa_pkcs1:rsaes_oaep_encrypt(HashFun, Message, Label, Seed, RSAPublicKey) of
		{ok, Encryption} ->
			ok;
		EncryptError ->
			ct:fail({{jose_jwa_pkcs1, rsaes_oaep_encrypt, [HashFun, Message, Label, Seed, RSAPublicKey]}, {expected, {ok, Encryption}}, {got, EncryptError}})
	end,
	case jose_jwa_pkcs1:rsaes_oaep_decrypt(HashFun, Encryption, Label, RSAPrivateKey) of
		Message ->
			emc_rsa_oaep_encrypt_and_decrypt(Vectors, {RSAPrivateKey, RSAPublicKey}, Config);
		DecryptError ->
			ct:fail({{jose_jwa_pkcs1, rsaes_oaep_decrypt, [HashFun, Encryption, Label, RSAPrivateKey]}, {expected, Message}, {got, DecryptError}})
	end;
emc_rsa_oaep_encrypt_and_decrypt(Vectors = [divider | _], _RSAKeyPair, Config) ->
	emc_rsa_oaep_encrypt_and_decrypt(Vectors, Config).

%% @private
emc_rsa_pss_sign_and_verify([
			divider,
			{example, Example},
			{component, <<"Components of the RSA Key Pair">>},
			{vector, {<<"RSA modulus n">>, N}},
			{vector, {<<"RSA public exponent e">>, E}},
			{vector, {<<"RSA private exponent d">>, D}},
			{vector, {<<"Prime p">>, P}},
			{vector, {<<"Prime q">>, Q}},
			{vector, {<<"p's CRT exponent dP">>, DP}},
			{vector, {<<"q's CRT exponent dQ">>, DQ}},
			{vector, {<<"CRT coefficient qInv">>, QI}}
			| Vectors
		], Config) ->
	RSAPrivateKey = #'RSAPrivateKey'{
		version = 'two-prime',
		otherPrimeInfos = 'asn1_NOVALUE',
		privateExponent = crypto:bytes_to_integer(D),
		exponent1 = crypto:bytes_to_integer(DP),
		exponent2 = crypto:bytes_to_integer(DQ),
		publicExponent = crypto:bytes_to_integer(E),
		modulus = crypto:bytes_to_integer(N),
		prime1 = crypto:bytes_to_integer(P),
		prime2 = crypto:bytes_to_integer(Q),
		coefficient = crypto:bytes_to_integer(QI)
	},
	RSAPublicKey = #'RSAPublicKey'{
		publicExponent = crypto:bytes_to_integer(E),
		modulus = crypto:bytes_to_integer(N)
	},
	io:format("~s", [Example]),
	emc_rsa_pss_sign_and_verify(Vectors, {RSAPrivateKey, RSAPublicKey}, Config);
emc_rsa_pss_sign_and_verify([divider], _Config) ->
	ok;
emc_rsa_pss_sign_and_verify([], _Config) ->
	ok.

%% @private
emc_rsa_pss_sign_and_verify([
			{component, Component},
			{vector, {<<"Message to be signed">>, Message}},
			{vector, {<<"Salt">>, Salt}},
			{vector, {<<"Signature">>, Signature}}
			| Vectors
		], {RSAPrivateKey, RSAPublicKey}, Config) ->
	io:format("\t~s", [Component]),
	HashFun = sha,
	case jose_jwa_pkcs1:rsassa_pss_sign(HashFun, Message, Salt, RSAPrivateKey) of
		{ok, Signature} ->
			ok;
		Other ->
			ct:fail({{jose_jwa_pkcs1, rsassa_pss_sign, [HashFun, Message, Salt, RSAPrivateKey]}, {expected, {ok, Signature}}, {got, Other}})
	end,
	SaltLen = byte_size(Salt),
	case jose_jwa_pkcs1:rsassa_pss_verify(HashFun, Message, Signature, SaltLen, RSAPublicKey) of
		true ->
			emc_rsa_pss_sign_and_verify(Vectors, {RSAPrivateKey, RSAPublicKey}, Config);
		false ->
			ct:fail({{jose_jwa_pkcs1, rsassa_pss_verify, [HashFun, Message, Signature, SaltLen, RSAPublicKey]}, {expected, true}, {got, false}})
	end;
emc_rsa_pss_sign_and_verify(Vectors = [divider | _], _RSAKeyPair, Config) ->
	emc_rsa_pss_sign_and_verify(Vectors, Config).

%% @private
fips_aes_encrypt_and_decrypt(File, Config) ->
	VectorsName = iolist_to_binary(filename:basename(File)),
	Algorithm = case VectorsName of
		<< "CBC", _/binary >> ->
			aes_cbc;
		<< "ECB", _/binary >> ->
			aes_ecb
	end,
	{Pos, 3} = binary:match(VectorsName, [<<"128">>, <<"192">>, <<"256">>]),
	Bits = binary_to_integer(binary:part(VectorsName, Pos, 3)),
	Cipher = {Algorithm, Bits},
	Vectors = fips_testvector:from_file(File),
	io:format("~s", [VectorsName]),
	fips_aes_encrypt_and_decrypt(Vectors, Cipher, Config).

%% @private
fips_aes_encrypt_and_decrypt([
			{vector, {<<"COUNT">>, Count}, _},
			{vector, {<<"KEY">>, Key}, _},
			{vector, {<<"PLAINTEXT">>, PlainText}, _},
			{vector, {<<"CIPHERTEXT">>, CipherText}, _}
			| Vectors
		], Cipher, Config) ->
	io:format("\tENCRYPT = ~w", [Count]),
	case jose_jwa_aes:block_encrypt(Cipher, Key, PlainText) of
		CipherText ->
			fips_aes_encrypt_and_decrypt(Vectors, Cipher, Config);
		EncryptError ->
			ct:fail({{jose_jwa_aes, block_encrypt, [Cipher, Key, PlainText]}, {expected, CipherText}, {got, EncryptError}})
	end;
fips_aes_encrypt_and_decrypt([
			{vector, {<<"COUNT">>, Count}, _},
			{vector, {<<"KEY">>, Key}, _},
			{vector, {<<"CIPHERTEXT">>, CipherText}, _},
			{vector, {<<"PLAINTEXT">>, PlainText}, _}
			| Vectors
		], Cipher, Config) ->
	io:format("\tDECRYPT = ~w", [Count]),
	case jose_jwa_aes:block_decrypt(Cipher, Key, CipherText) of
		PlainText ->
			fips_aes_encrypt_and_decrypt(Vectors, Cipher, Config);
		DecryptError ->
			ct:fail({{jose_jwa_aes, block_decrypt, [Cipher, Key, CipherText]}, {expected, PlainText}, {got, DecryptError}})
	end;
fips_aes_encrypt_and_decrypt([
			{vector, {<<"COUNT">>, Count}, _},
			{vector, {<<"KEY">>, Key}, _},
			{vector, {<<"IV">>, IV}, _},
			{vector, {<<"PLAINTEXT">>, PlainText}, _},
			{vector, {<<"CIPHERTEXT">>, CipherText}, _}
			| Vectors
		], Cipher, Config) ->
	io:format("\tENCRYPT = ~w", [Count]),
	case jose_jwa_aes:block_encrypt(Cipher, Key, IV, PlainText) of
		CipherText ->
			fips_aes_encrypt_and_decrypt(Vectors, Cipher, Config);
		EncryptError ->
			ct:fail({{jose_jwa_aes, block_encrypt, [Cipher, Key, IV, PlainText]}, {expected, CipherText}, {got, EncryptError}})
	end;
fips_aes_encrypt_and_decrypt([
			{vector, {<<"COUNT">>, Count}, _},
			{vector, {<<"KEY">>, Key}, _},
			{vector, {<<"IV">>, IV}, _},
			{vector, {<<"CIPHERTEXT">>, CipherText}, _},
			{vector, {<<"PLAINTEXT">>, PlainText}, _}
			| Vectors
		], Cipher, Config) ->
	io:format("\tDECRYPT = ~w", [Count]),
	case jose_jwa_aes:block_decrypt(Cipher, Key, IV, CipherText) of
		PlainText ->
			fips_aes_encrypt_and_decrypt(Vectors, Cipher, Config);
		DecryptError ->
			ct:fail({{jose_jwa_aes, block_decrypt, [Cipher, Key, IV, CipherText]}, {expected, PlainText}, {got, DecryptError}})
	end;
fips_aes_encrypt_and_decrypt([
			{flag, Flag}
			| Vectors
		], Cipher, Config)
			when Flag =:= <<"DECRYPT">>
			orelse Flag =:= <<"ENCRYPT">> ->
	fips_aes_encrypt_and_decrypt(Vectors, Cipher, Config);
fips_aes_encrypt_and_decrypt([], _Cipher, Config) ->
	Config.

%% @private
fips_aes_gcm_encrypt_and_decrypt(File, Config) ->
	VectorsName = iolist_to_binary(filename:basename(File)),
	{Algorithm, Mode} = case VectorsName of
		<< "gcmDecrypt", _/binary >> ->
			{aes_gcm, decrypt};
		<< "gcmEncrypt", _/binary >> ->
			{aes_gcm, encrypt}
	end,
	{Pos, 3} = binary:match(VectorsName, [<<"128">>, <<"192">>, <<"256">>]),
	Bits = binary_to_integer(binary:part(VectorsName, Pos, 3)),
	Cipher = {Algorithm, Bits},
	Vectors = fips_testvector:from_file(File),
	io:format("~s", [VectorsName]),
	fips_aes_gcm_encrypt_and_decrypt(Vectors, {Cipher, Mode, undefined}, Config).

%% @private
fips_aes_gcm_encrypt_and_decrypt([
			{vector, {<<"Count">>, Count}, _},
			{vector, {<<"Key">>, Key}, _},
			{vector, {<<"IV">>, IV}, _},
			{vector, {<<"CT">>, CT}, _},
			{vector, {<<"AAD">>, AAD}, _},
			{vector, {<<"Tag">>, Tag}, _},
			{token, <<"FAIL">>}
			| Vectors
		], {Cipher, decrypt, {Keylen, IVlen, PTlen, AADlen, Taglen, Counts}}, Config)
			when bit_size(Key) =:= Keylen
			andalso bit_size(IV) =:= IVlen
			andalso bit_size(CT) =:= PTlen
			andalso bit_size(AAD) =:= AADlen
			andalso bit_size(Tag) =:= Taglen ->
	% io:format("\tDECRYPT = ~w", [Count]),
	case jose_jwa_aes:block_decrypt(Cipher, Key, IV, {AAD, CT, Tag}) of
		error ->
			fips_aes_gcm_encrypt_and_decrypt(Vectors, {Cipher, decrypt, {Keylen, IVlen, PTlen, AADlen, Taglen, << Counts/binary, (integer_to_binary(Count))/binary, "..." >>}}, Config);
		OtherDecrypt ->
			io:format("\t\tCounts = ~s", [<< Counts/binary, (integer_to_binary(Count))/binary, "..." >>]),
			ct:fail({{jose_jwa_aes, block_decrypt, [Cipher, Key, IV, {AAD, CT, Tag}]}, {expected, error}, {got, OtherDecrypt}})
	end;
fips_aes_gcm_encrypt_and_decrypt([
			{vector, {<<"Count">>, Count}, _},
			{vector, {<<"Key">>, Key}, _},
			{vector, {<<"IV">>, IV}, _},
			{vector, {<<"CT">>, CT}, _},
			{vector, {<<"AAD">>, AAD}, _},
			{vector, {<<"Tag">>, Tag}, _},
			{vector, {<<"PT">>, PT}, _}
			| Vectors
		], {Cipher, decrypt, {Keylen, IVlen, PTlen, AADlen, Taglen, Counts}}, Config)
			when bit_size(Key) =:= Keylen
			andalso bit_size(IV) =:= IVlen
			andalso bit_size(CT) =:= PTlen
			andalso bit_size(AAD) =:= AADlen
			andalso bit_size(Tag) =:= Taglen
			andalso bit_size(PT) =:= PTlen ->
	% io:format("\tDECRYPT = ~w", [Count]),
	case jose_jwa_aes:block_decrypt(Cipher, Key, IV, {AAD, CT, Tag}) of
		PT ->
			fips_aes_gcm_encrypt_and_decrypt(Vectors, {Cipher, decrypt, {Keylen, IVlen, PTlen, AADlen, Taglen, << Counts/binary, (integer_to_binary(Count))/binary, "..." >>}}, Config);
		OtherDecrypt ->
			io:format("\t\tCounts = ~s", [<< Counts/binary, (integer_to_binary(Count))/binary, "..." >>]),
			io:format("{Cipher, Key, IV, CT, AAD, Tag, PT} = ~w~n", [{Cipher, Key, IV, CT, AAD, Tag, PT}]),
			ct:fail({{jose_jwa_aes, block_decrypt, [Cipher, Key, IV, {AAD, CT, Tag}]}, {expected, PT}, {got, OtherDecrypt}})
	end;
fips_aes_gcm_encrypt_and_decrypt([
			{vector, {<<"Count">>, Count}, _},
			{vector, {<<"Key">>, Key}, _},
			{vector, {<<"IV">>, IV}, _},
			{vector, {<<"PT">>, PT}, _},
			{vector, {<<"AAD">>, AAD}, _},
			{vector, {<<"CT">>, CT}, _},
			{vector, {<<"Tag">>, Tag}, _}
			| Vectors
		], {Cipher, encrypt, {Keylen, IVlen, PTlen, AADlen, Taglen, Counts}}, Config)
			when bit_size(Key) =:= Keylen
			andalso bit_size(IV) =:= IVlen
			andalso bit_size(PT) =:= PTlen
			andalso bit_size(AAD) =:= AADlen
			andalso bit_size(CT) =:= PTlen
			andalso bit_size(Tag) =:= Taglen ->
	% io:format("\tENCRYPT = ~w", [Count]),
	case jose_jwa_aes:block_encrypt(Cipher, Key, IV, {AAD, PT}) of
		{CT, << Tag:Taglen/bitstring, _/bitstring >>} ->
			fips_aes_gcm_encrypt_and_decrypt(Vectors, {Cipher, encrypt, {Keylen, IVlen, PTlen, AADlen, Taglen, << Counts/binary, (integer_to_binary(Count))/binary, "..." >>}}, Config);
		OtherEncrypt ->
			io:format("\t\tCounts = ~s", [<< Counts/binary, (integer_to_binary(Count))/binary, "..." >>]),
			ct:fail({{jose_jwa_aes, block_encrypt, [Cipher, Key, IV, {AAD, PT}]}, {expected, {CT, Tag}}, {got, OtherEncrypt}})
	end;
% fips_aes_gcm_encrypt_and_decrypt([{flag, _Flag} | Vectors], Cipher, Config) ->
% 	fips_aes_gcm_encrypt_and_decrypt(Vectors, Cipher, Config);
% fips_aes_gcm_encrypt_and_decrypt([{option, _Option} | Vectors], Cipher, Config) ->
% 	fips_aes_gcm_encrypt_and_decrypt(Vectors, Cipher, Config);
fips_aes_gcm_encrypt_and_decrypt([
			{option, {<<"Keylen">>, Keylen}},
			{option, {<<"IVlen">>, IVlen}},
			{option, {<<"PTlen">>, PTlen}},
			{option, {<<"AADlen">>, AADlen}},
			{option, {<<"Taglen">>, Taglen}}
			| Vectors
		], {Cipher, Mode, undefined}, Config) ->
	Options = {
		binary_to_integer(Keylen),
		binary_to_integer(IVlen),
		binary_to_integer(PTlen),
		binary_to_integer(AADlen),
		binary_to_integer(Taglen),
		<<>>
	},
	% io:format("\t[~w] Keylen = ~s, IVlen = ~s, PTlen = ~s, AADlen = ~s, Taglen = ~s", [
	% 	Mode,
	% 	Keylen,
	% 	IVlen,
	% 	PTlen,
	% 	AADlen,
	% 	Taglen
	% ]),
	fips_aes_gcm_encrypt_and_decrypt(Vectors, {Cipher, Mode, Options}, Config);
fips_aes_gcm_encrypt_and_decrypt(Vectors, {Cipher, Mode, {_Keylen, _IVlen, _PTlen, _AADlen, _Taglen, _Counts}}, Config) ->
	% io:format("\t\tCounts = ~s", [binary:part(Counts, 0, byte_size(Counts) - 3)]),
	fips_aes_gcm_encrypt_and_decrypt(Vectors, {Cipher, Mode, undefined}, Config);
fips_aes_gcm_encrypt_and_decrypt([], _Cipher, Config) ->
	Config.

%% @private
fips_rsa_pss_sign([
			{option, {<<"mod">>, ModVal}},
			{vector, {<<"n">>, N}, _},
			{vector, {<<"e">>, E}, _},
			{vector, {<<"d">>, D}, _}
			| Vectors
		], Config) ->
	ModulusSize = binary_to_integer(ModVal),
	RSAPrivateKey = #'RSAPrivateKey'{
		modulus = crypto:bytes_to_integer(N),
		privateExponent = crypto:bytes_to_integer(D),
		publicExponent = crypto:bytes_to_integer(E)
	},
	fips_rsa_pss_sign(Vectors, ModulusSize, RSAPrivateKey, Config);
fips_rsa_pss_sign([], _Config) ->
	ok.

%% @private
fips_rsa_pss_sign([
			{vector, {<<"SHAAlg">>, SHAAlg}, _},
			{vector, {<<"Msg">>, Msg}, _},
			{vector, {<<"S">>, S}, _},
			{vector, {<<"SaltVal">>, SaltVal}, _}
			| Vectors
		], ModulusSize, RSAPrivateKey, Config) ->
	HashFun = shaalg_to_hash_fun(SHAAlg),
	case jose_jwa_pkcs1:rsassa_pss_sign(HashFun, Msg, SaltVal, RSAPrivateKey) of
		{ok, S} ->
			ok;
		Other ->
			ct:fail({{jose_jwa_pkcs1, rsassa_pss_sign, [HashFun, Msg, SaltVal, RSAPrivateKey]}, {expected, {ok, S}}, {got, Other}})
	end,
	RSAPublicKey = rsa_private_to_public(RSAPrivateKey),
	SaltLen = byte_size(SaltVal),
	case jose_jwa_pkcs1:rsassa_pss_verify(HashFun, Msg, S, SaltLen, RSAPublicKey) of
		true ->
			fips_rsa_pss_sign(Vectors, ModulusSize, RSAPrivateKey, Config);
		false ->
			ct:fail({{jose_jwa_pkcs1, rsassa_pss_verify, [HashFun, Msg, S, SaltLen, RSAPublicKey]}, {expected, true}, {got, false}})
	end;
fips_rsa_pss_sign(Vectors, _ModulusSize, _RSAPrivateKey, Config) ->
	fips_rsa_pss_sign(Vectors, Config).

%% @private
fips_rsa_pss_verify([
			{option, {<<"mod">>, ModVal}},
			{vector, {<<"n">>, N}, _},
			{vector, {<<"p">>, P}, _},
			{vector, {<<"q">>, Q}, _}
			| Vectors
		], Config) ->
	ModulusSize = binary_to_integer(ModVal),
	RSAPrivateKey = #'RSAPrivateKey'{
		modulus = crypto:bytes_to_integer(N),
		prime1 = crypto:bytes_to_integer(P),
		prime2 = crypto:bytes_to_integer(Q)
	},
	fips_rsa_pss_verify(Vectors, ModulusSize, RSAPrivateKey, Config);
fips_rsa_pss_verify([], _Config) ->
	ok.

%% @private
fips_rsa_pss_verify([
			{vector, {<<"n">>, N}, _},
			{vector, {<<"p">>, P}, _},
			{vector, {<<"q">>, Q}, _}
			| Vectors
		], ModulusSize, Config) ->
	RSAPrivateKey = #'RSAPrivateKey'{
		modulus = crypto:bytes_to_integer(N),
		prime1 = crypto:bytes_to_integer(P),
		prime2 = crypto:bytes_to_integer(Q)
	},
	fips_rsa_pss_verify(Vectors, ModulusSize, RSAPrivateKey, Config);
fips_rsa_pss_verify(Vectors, _ModulusSize, Config) ->
	fips_rsa_pss_verify(Vectors, Config).

%% @private
fips_rsa_pss_verify([
			{vector, {<<"SHAAlg">>, SHAAlg}, _},
			{vector, {<<"e">>, E}, _},
			{vector, {<<"d">>, D}, _},
			{vector, {<<"Msg">>, Msg}, _},
			{vector, {<<"S">>, S}, _},
			{vector, {<<"SaltVal">>, SaltVal}, _},
			{vector, {<<"EM", _/binary>>, _}, _},
			{vector, {<<"Result">>, << R, _/binary >>}, _}
			| Vectors
		], ModulusSize, RSAPrivateKey0, Config) ->
	Expected = case R of
		$F ->
			false;
		$P ->
			true
	end,
	HashFun = shaalg_to_hash_fun(SHAAlg),
	RSAPrivateKey = RSAPrivateKey0#'RSAPrivateKey'{
		privateExponent = crypto:bytes_to_integer(D),
		publicExponent = crypto:bytes_to_integer(E)
	},
	RSAPublicKey = rsa_private_to_public(RSAPrivateKey),
	SaltLen = case SaltVal of
		<< 0 >> ->
			0;
		_ ->
			byte_size(SaltVal)
	end,
	case jose_jwa_pkcs1:rsassa_pss_verify(HashFun, Msg, S, SaltLen, RSAPublicKey) of
		Expected ->
			fips_rsa_pss_verify(Vectors, ModulusSize, RSAPrivateKey0, Config);
		Other ->
			ct:fail({{jose_jwa_pkcs1, rsassa_pss_verify, [HashFun, Msg, S, SaltLen, RSAPublicKey]}, {expected, Expected}, {got, Other}})
	end;
fips_rsa_pss_verify([
			{vector, {<<"SHAAlg">>, SHAAlg}, _},
			{vector, {<<"e">>, E}, _},
			{vector, {<<"d">>, D}, _},
			{vector, {<<"Msg">>, Msg}, _},
			{vector, {<<"S">>, S}, _},
			{vector, {<<"SaltVal">>, SaltVal}, _},
			{vector, {<<"Result">>, << R, _/binary >>}, _}
			| Vectors
		], ModulusSize, RSAPrivateKey0, Config) ->
	Expected = case R of
		$F ->
			false;
		$P ->
			true
	end,
	HashFun = shaalg_to_hash_fun(SHAAlg),
	RSAPrivateKey = RSAPrivateKey0#'RSAPrivateKey'{
		privateExponent = crypto:bytes_to_integer(D),
		publicExponent = crypto:bytes_to_integer(E)
	},
	RSAPublicKey = rsa_private_to_public(RSAPrivateKey),
	SaltLen = case SaltVal of
		<< 0 >> ->
			0;
		_ ->
			byte_size(SaltVal)
	end,
	case jose_jwa_pkcs1:rsassa_pss_verify(HashFun, Msg, S, SaltLen, RSAPublicKey) of
		Expected ->
			fips_rsa_pss_verify(Vectors, ModulusSize, RSAPrivateKey0, Config);
		Other ->
			ct:fail({{jose_jwa_pkcs1, rsassa_pss_verify, [HashFun, Msg, S, SaltLen, RSAPublicKey]}, {expected, Expected}, {got, Other}})
	end;
fips_rsa_pss_verify(Vectors, ModulusSize, _RSAPrivateKey, Config) ->
	fips_rsa_pss_verify(Vectors, ModulusSize, Config).

%% @private
pbkdf2([{Mac, Password, Salt, Iterations, DerivedKeyLen, DerivedKey} | Vectors], Config) ->
	case jose_jwa_pkcs5:pbkdf2(Mac, Password, Salt, Iterations, DerivedKeyLen) of
		{ok, DerivedKey} ->
			pbkdf2(Vectors, Config);
		Other ->
			ct:fail({{jose_jwa_pkcs5, pbkdf2, [Mac, Password, Salt, Iterations, DerivedKeyLen]}, {expected, {ok, DerivedKey}}, {got, Other}})
	end;
pbkdf2([], _Config) ->
	ok.

%% @private
rsa_private_to_public(#'RSAPrivateKey'{ modulus = Modulus, publicExponent = PublicExponent }) ->
	#'RSAPublicKey'{ modulus = Modulus, publicExponent = PublicExponent }.

%% @private
shaalg_to_hash_fun(<<"SHA1">>)   -> sha;
shaalg_to_hash_fun(<<"SHA224">>) -> sha224;
shaalg_to_hash_fun(<<"SHA256">>) -> sha256;
shaalg_to_hash_fun(<<"SHA384">>) -> sha384;
shaalg_to_hash_fun(<<"SHA512">>) -> sha512.
