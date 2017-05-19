%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2017, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  18 May 2017 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(jose_public_key).

-include("jose_public_key.hrl").

%% API
-export([der_decode/2]).
-export([der_encode/2]).
-export([pem_decode/1]).
-export([pem_encode/1]).
-export([pem_entry_decode/1]).
-export([pem_entry_decode/2]).
-export([pem_entry_encode/2]).
-export([pem_entry_encode/3]).

%%====================================================================
%% API functions
%%====================================================================

der_decode(ASN1Type, DER) when is_atom(ASN1Type) andalso is_binary(DER) ->
	public_key:der_decode(ASN1Type, DER).

der_encode(ASN1Type, Entity) when is_atom(ASN1Type) ->
	public_key:der_encode(ASN1Type, Entity).

pem_decode(PEMBinary) when is_binary(PEMBinary) ->
	public_key:pem_decode(PEMBinary).

pem_encode(PEMEntries) when is_list(PEMEntries) ->
	% public_key:pem_encode(PEMEntries).
	try
		public_key:pem_encode(PEMEntries)
	catch
		Class:Reason ->
			ST = erlang:get_stacktrace(),
			case pem_enc(PEMEntries) of
				{true, PEMBinary} ->
					PEMBinary;
				false ->
					erlang:raise(Class, Reason, ST)
			end
	end.

pem_entry_decode(PEMEntry) ->
	% public_key:pem_entry_decode(PEMEntry).
	Result =
		try
			public_key:pem_entry_decode(PEMEntry)
		catch
			Class:Reason ->
				ST = erlang:get_stacktrace(),
				case pem_entry_dec(PEMEntry) of
					{true, DecodedPEMEntry} ->
						DecodedPEMEntry;
					false ->
						erlang:raise(Class, Reason, ST)
				end
		end,
	case Result of
		PrivateKeyInfo=#'PrivateKeyInfo'{} ->
			i2k(PrivateKeyInfo);
		SubjectPublicKeyInfo=#'SubjectPublicKeyInfo'{} ->
			i2k(SubjectPublicKeyInfo);
		Other ->
			Other
	end.

pem_entry_decode(PEMEntry, Password) ->
	% public_key:pem_entry_decode(PEMEntry, Password).
	Result =
		try
			public_key:pem_entry_decode(PEMEntry, Password)
		catch
			Class:Reason ->
				ST = erlang:get_stacktrace(),
				case pem_entry_dec(PEMEntry) of
					{true, DecodedPEMEntry} ->
						DecodedPEMEntry;
					false ->
						erlang:raise(Class, Reason, ST)
				end
		end,
	case Result of
		PrivateKeyInfo=#'PrivateKeyInfo'{} ->
			i2k(PrivateKeyInfo);
		SubjectPublicKeyInfo=#'SubjectPublicKeyInfo'{} ->
			i2k(SubjectPublicKeyInfo);
		Other ->
			Other
	end.

pem_entry_encode(ASN1Type, Entity) ->
	% public_key:pem_entry_encode(ASN1Type, Entity).
	try
		public_key:pem_entry_encode(ASN1Type, Entity)
	catch
		Class:Reason ->
			ST = erlang:get_stacktrace(),
			case pem_entry_enc(ASN1Type, Entity) of
				{true, PEMEntry} ->
					PEMEntry;
				false ->
					erlang:raise(Class, Reason, ST)
			end
	end.

pem_entry_encode(ASN1Type, Entity, Password) ->
	% public_key:pem_entry_encode(ASN1Type, Entity, Password).
	try
		public_key:pem_entry_encode(ASN1Type, Entity, Password)
	catch
		Class:Reason ->
			ST = erlang:get_stacktrace(),
			case pem_entry_enc(ASN1Type, Entity, Password) of
				{true, PEMEntry} ->
					PEMEntry;
				false ->
					erlang:raise(Class, Reason, ST)
			end
	end.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
pem_enc(Entries) ->
	pem_enc(Entries, []).

%% @private
pem_enc([Entry={'PrivateKeyInfo', _, _} | Entries], Acc) ->
	Encoded =
		try
			public_key:pem_encode([Entry])
		catch
			_:_ ->
				pem_entry_enc(Entry)
		end,
	pem_enc(Entries, [Encoded | Acc]);
pem_enc([Entry | Entries], Acc) ->
	Encoded = public_key:pem_encode([Entry]),
	pem_enc(Entries, [Encoded | Acc]);
pem_enc([], Acc) ->
	{true, erlang:iolist_to_binary(lists:reverse(Acc))}.

%% @private
pem_entry_dec({ASN1Type='PrivateKeyInfo', Der, not_encrypted}) ->
	Entity = der_decode(ASN1Type, Der),
	{true, i2k(Entity)};
pem_entry_dec({ASN1Type='SubjectPublicKeyInfo', Der, not_encrypted}) ->
	Entity = der_decode(ASN1Type, Der),
	{true, i2k(Entity)};
pem_entry_dec(_) ->
	false.

%% @private
pem_entry_enc({'PrivateKeyInfo', Der, EncParams}) ->
	EncodedPEM = public_key:pem_encode([{'ECPrivateKey', Der, EncParams}]),
	erlang:iolist_to_binary(binary:split(EncodedPEM, <<" EC">>, [global, trim_all]));
pem_entry_enc(Entry) ->
	Entry.

%% @private
pem_entry_enc('EdDSA25519PrivateKey', K=#'jose_EdDSA25519PrivateKey'{}) ->
	EncodedPEMEntry = public_key:pem_entry_encode('PrivateKeyInfo', k2i(K)),
	{true, EncodedPEMEntry};
pem_entry_enc('EdDSA25519PublicKey', K=#'jose_EdDSA25519PublicKey'{}) ->
	EncodedPEMEntry = public_key:pem_entry_encode('SubjectPublicKeyInfo', k2i(K)),
	{true, EncodedPEMEntry};
pem_entry_enc('EdDSA448PrivateKey', K=#'jose_EdDSA448PrivateKey'{}) ->
	EncodedPEMEntry = public_key:pem_entry_encode('PrivateKeyInfo', k2i(K)),
	{true, EncodedPEMEntry};
pem_entry_enc('EdDSA448PublicKey', K=#'jose_EdDSA448PublicKey'{}) ->
	EncodedPEMEntry = public_key:pem_entry_encode('SubjectPublicKeyInfo', k2i(K)),
	{true, EncodedPEMEntry};
pem_entry_enc('X25519PrivateKey', K=#'jose_X25519PrivateKey'{}) ->
	EncodedPEMEntry = public_key:pem_entry_encode('PrivateKeyInfo', k2i(K)),
	{true, EncodedPEMEntry};
pem_entry_enc('X25519PublicKey', K=#'jose_X25519PublicKey'{}) ->
	EncodedPEMEntry = public_key:pem_entry_encode('SubjectPublicKeyInfo', k2i(K)),
	{true, EncodedPEMEntry};
pem_entry_enc('X448PrivateKey', K=#'jose_X448PrivateKey'{}) ->
	EncodedPEMEntry = public_key:pem_entry_encode('PrivateKeyInfo', k2i(K)),
	{true, EncodedPEMEntry};
pem_entry_enc('X448PublicKey', K=#'jose_X448PublicKey'{}) ->
	EncodedPEMEntry = public_key:pem_entry_encode('SubjectPublicKeyInfo', k2i(K)),
	{true, EncodedPEMEntry};
pem_entry_enc(_, _) ->
	false.

%% @private
pem_entry_enc('EdDSA25519PrivateKey', K=#'jose_EdDSA25519PrivateKey'{}, Password) ->
	EncodedPEMEntry = pem_entry_enc0('PrivateKeyInfo', k2i(K), Password),
	{true, EncodedPEMEntry};
pem_entry_enc('EdDSA25519PublicKey', K=#'jose_EdDSA25519PublicKey'{}, Password) ->
	EncodedPEMEntry = pem_entry_enc0('SubjectPublicKeyInfo', k2i(K), Password),
	{true, EncodedPEMEntry};
pem_entry_enc('EdDSA448PrivateKey', K=#'jose_EdDSA448PrivateKey'{}, Password) ->
	EncodedPEMEntry = pem_entry_enc0('PrivateKeyInfo', k2i(K), Password),
	{true, EncodedPEMEntry};
pem_entry_enc('EdDSA448PublicKey', K=#'jose_EdDSA448PublicKey'{}, Password) ->
	EncodedPEMEntry = pem_entry_enc0('SubjectPublicKeyInfo', k2i(K), Password),
	{true, EncodedPEMEntry};
pem_entry_enc('X25519PrivateKey', K=#'jose_X25519PrivateKey'{}, Password) ->
	EncodedPEMEntry = pem_entry_enc0('PrivateKeyInfo', k2i(K), Password),
	{true, EncodedPEMEntry};
pem_entry_enc('X25519PublicKey', K=#'jose_X25519PublicKey'{}, Password) ->
	EncodedPEMEntry = pem_entry_enc0('SubjectPublicKeyInfo', k2i(K), Password),
	{true, EncodedPEMEntry};
pem_entry_enc('X448PrivateKey', K=#'jose_X448PrivateKey'{}, Password) ->
	EncodedPEMEntry = pem_entry_enc0('PrivateKeyInfo', k2i(K), Password),
	{true, EncodedPEMEntry};
pem_entry_enc('X448PublicKey', K=#'jose_X448PublicKey'{}, Password) ->
	EncodedPEMEntry = pem_entry_enc0('SubjectPublicKeyInfo', k2i(K), Password),
	{true, EncodedPEMEntry};
pem_entry_enc(_, _, _) ->
	false.

%% @private
pem_entry_enc0(ASN1Type, Entry, Cipher) ->
	try
		public_key:pem_entry_encode(ASN1Type, Entry, Cipher)
	catch
		Class:Reason ->
			ST = erlang:get_stacktrace(),
			case pem_entry_enc1(ASN1Type, Entry, Cipher) of
				{true, Encoded} ->
					Encoded;
				false ->
					erlang:raise(Class, Reason, ST)
			end
	end.

%% @private
pem_entry_enc1(ASN1Type, Entry, {CipherInfo={C, _}, Password}) when C == "AES-128-CBC" ->
	Der = der_encode(ASN1Type, Entry),
	DecryptDer = pem_cipher(Der, CipherInfo, Password),
	{true, {ASN1Type, DecryptDer, CipherInfo}};
pem_entry_enc1(_, _, _) ->
	false.

%% @private
pem_cipher(Data, {Cipher = "AES-128-CBC", IV}, Password) ->
	<< Salt:8/binary, _/binary >> = IV,
	{Key, _} = password_to_key_and_iv(Password, Cipher, Salt),
	crypto:block_encrypt(aes_cbc128, Key, IV, jose_jwa_pkcs7:pad(Data)).

%% @private
ceiling(Float) -> 
	erlang:round(Float + 0.5).

%% @private
derived_key_length(_, Len) when is_integer(Len) ->
	Len;
derived_key_length(Cipher, _) when (Cipher == "AES-128-CBC") ->
	16.

%% @private
password_to_key_and_iv(Password, Cipher, Salt) ->
	KeyLen = derived_key_length(Cipher, undefined),
	<< Key:KeyLen/binary, _/binary >> =
		pem_encrypt(<<>>, Password, Salt, ceiling(KeyLen div 16), <<>>, md5),
	%% Old PEM encryption does not use standard encryption method
	%% pbdkdf1 and uses then salt as IV
	{Key, Salt}.

% %% @private
% pbe_pad(Data) ->
% 	N = 8 - (erlang:byte_size(Data) rem 8), 
% 	Pad = binary:copy(<< N >>, N),
% 	<<Data/binary, Pad/binary>>.

%% @private
pem_encrypt(_, _, _, 0, Acc, _) ->
	Acc;
pem_encrypt(Prev, Password, Salt, Count, Acc, Hash) ->
	Result = crypto:hash(Hash, [Prev, Password, Salt]),
	pem_encrypt(Result, Password, Salt, Count-1 , <<Acc/binary, Result/binary>>, Hash).

%% @private
i2k(#'PrivateKeyInfo'{
	privateKeyAlgorithm =
		#'PrivateKeyInfo_privateKeyAlgorithm'{
			algorithm = ?'jose_id-EdDSA25519'
		},
	privateKey =
		<< 4, 32:8/integer, PrivateKey:32/binary >>
}) ->
	PublicKey = jose_curve25519:eddsa_secret_to_public(PrivateKey),
	#'jose_EdDSA25519PrivateKey'{
		publicKey = #'jose_EdDSA25519PublicKey'{ publicKey = PublicKey },
		privateKey = PrivateKey
	};
i2k(#'SubjectPublicKeyInfo'{
	algorithm =
		#'AlgorithmIdentifier'{
			algorithm = ?'jose_id-EdDSA25519'
		},
	subjectPublicKey = << PublicKey:32/binary >>
}) ->
	#'jose_EdDSA25519PublicKey'{ publicKey = PublicKey };
i2k(#'PrivateKeyInfo'{
	privateKeyAlgorithm =
		#'PrivateKeyInfo_privateKeyAlgorithm'{
			algorithm = ?'jose_id-EdDSA448'
		},
	privateKey =
		<< 4, 57:8/integer, PrivateKey:57/binary >>
}) ->
	PublicKey = jose_curve448:eddsa_secret_to_public(PrivateKey),
	#'jose_EdDSA448PrivateKey'{
		publicKey = #'jose_EdDSA448PublicKey'{ publicKey = PublicKey },
		privateKey = PrivateKey
	};
i2k(#'SubjectPublicKeyInfo'{
	algorithm =
		#'AlgorithmIdentifier'{
			algorithm = ?'jose_id-EdDSA448'
		},
	subjectPublicKey = << PublicKey:57/binary >>
}) ->
	#'jose_EdDSA448PublicKey'{ publicKey = PublicKey };
i2k(#'PrivateKeyInfo'{
	privateKeyAlgorithm =
		#'PrivateKeyInfo_privateKeyAlgorithm'{
			algorithm = ?'jose_id-X25519'
		},
	privateKey =
		<< 4, 32:8/integer, PrivateKey:32/binary >>
}) ->
	PublicKey = jose_curve25519:x25519_secret_to_public(PrivateKey),
	#'jose_X25519PrivateKey'{
		publicKey = #'jose_X25519PublicKey'{ publicKey = PublicKey },
		privateKey = PrivateKey
	};
i2k(#'SubjectPublicKeyInfo'{
	algorithm =
		#'AlgorithmIdentifier'{
			algorithm = ?'jose_id-X25519'
		},
	subjectPublicKey = << PublicKey:32/binary >>
}) ->
	#'jose_X25519PublicKey'{ publicKey = PublicKey };
i2k(#'PrivateKeyInfo'{
	privateKeyAlgorithm =
		#'PrivateKeyInfo_privateKeyAlgorithm'{
			algorithm = ?'jose_id-X448'
		},
	privateKey =
		<< 4, 56:8/integer, PrivateKey:56/binary >>
}) ->
	PublicKey = jose_curve448:x448_secret_to_public(PrivateKey),
	#'jose_X448PrivateKey'{
		publicKey = #'jose_X448PublicKey'{ publicKey = PublicKey },
		privateKey = PrivateKey
	};
i2k(#'SubjectPublicKeyInfo'{
	algorithm =
		#'AlgorithmIdentifier'{
			algorithm = ?'jose_id-X448'
		},
	subjectPublicKey = << PublicKey:56/binary >>
}) ->
	#'jose_X448PublicKey'{ publicKey = PublicKey };
i2k(Info) ->
	Info.

%% @private
k2i(#'jose_EdDSA25519PrivateKey'{privateKey=PrivateKey}) ->
	#'PrivateKeyInfo'{
		version = v1,
		privateKeyAlgorithm =
			#'PrivateKeyInfo_privateKeyAlgorithm'{
				algorithm = ?'jose_id-EdDSA25519',
				parameters = asn1_NOVALUE
			},
		privateKey =
			<< 4, 32:8/integer, PrivateKey:32/binary >>,
		attributes = asn1_NOVALUE
	};
k2i(#'jose_EdDSA25519PublicKey'{publicKey=PublicKey}) ->
	#'SubjectPublicKeyInfo'{
		algorithm =
			#'AlgorithmIdentifier'{
				algorithm = ?'jose_id-EdDSA25519',
				parameters = asn1_NOVALUE
			},
		subjectPublicKey = << PublicKey:32/binary >>
	};
k2i(#'jose_EdDSA448PrivateKey'{privateKey=PrivateKey}) ->
	#'PrivateKeyInfo'{
		version = v1,
		privateKeyAlgorithm =
			#'PrivateKeyInfo_privateKeyAlgorithm'{
				algorithm = ?'jose_id-EdDSA448',
				parameters = asn1_NOVALUE
			},
		privateKey =
			<< 4, 57:8/integer, PrivateKey:57/binary >>,
		attributes = asn1_NOVALUE
	};
k2i(#'jose_EdDSA448PublicKey'{publicKey=PublicKey}) ->
	#'SubjectPublicKeyInfo'{
		algorithm =
			#'AlgorithmIdentifier'{
				algorithm = ?'jose_id-EdDSA448',
				parameters = asn1_NOVALUE
			},
		subjectPublicKey = << PublicKey:57/binary >>
	};
k2i(#'jose_X25519PrivateKey'{privateKey=PrivateKey}) ->
	#'PrivateKeyInfo'{
		version = v1,
		privateKeyAlgorithm =
			#'PrivateKeyInfo_privateKeyAlgorithm'{
				algorithm = ?'jose_id-X25519',
				parameters = asn1_NOVALUE
			},
		privateKey =
			<< 4, 32:8/integer, PrivateKey:32/binary >>,
		attributes = asn1_NOVALUE
	};
k2i(#'jose_X25519PublicKey'{publicKey=PublicKey}) ->
	#'SubjectPublicKeyInfo'{
		algorithm =
			#'AlgorithmIdentifier'{
				algorithm = ?'jose_id-X25519',
				parameters = asn1_NOVALUE
			},
		subjectPublicKey = << PublicKey:32/binary >>
	};
k2i(#'jose_X448PrivateKey'{privateKey=PrivateKey}) ->
	#'PrivateKeyInfo'{
		version = v1,
		privateKeyAlgorithm =
			#'PrivateKeyInfo_privateKeyAlgorithm'{
				algorithm = ?'jose_id-X448',
				parameters = asn1_NOVALUE
			},
		privateKey =
			<< 4, 56:8/integer, PrivateKey:56/binary >>,
		attributes = asn1_NOVALUE
	};
k2i(#'jose_X448PublicKey'{publicKey=PublicKey}) ->
	#'SubjectPublicKeyInfo'{
		algorithm =
			#'AlgorithmIdentifier'{
				algorithm = ?'jose_id-X448',
				parameters = asn1_NOVALUE
			},
		subjectPublicKey = << PublicKey:56/binary >>
	}.
