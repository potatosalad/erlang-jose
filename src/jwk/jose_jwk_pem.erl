%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <potatosaladx@gmail.com>
%%% @copyright 2014-2015, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  24 Jul 2015 by Andrew Bennett <potatosaladx@gmail.com>
%%%-------------------------------------------------------------------
-module(jose_jwk_pem).

-include_lib("public_key/include/public_key.hrl").

%% API
-export([from_binary/1]).
-export([from_binary/2]).
-export([from_certificate/1]).
-export([from_public_key_info/1]).
-export([to_binary/3]).

%%====================================================================
%% API functions
%%====================================================================

from_binary(PEMBinary) when is_binary(PEMBinary) ->
	case jose_public_key:pem_decode(PEMBinary) of
		[CertificatePEMEntry={'Certificate', _, not_encrypted}] ->
			from_certificate(CertificatePEMEntry);
		[PEMEntry] ->
			jose_jwk_kty:from_key(jose_public_key:pem_entry_decode(PEMEntry));
		PEMDecodeError ->
			PEMDecodeError
	end.

from_binary(Password, EncryptedPEMBinary) when is_binary(EncryptedPEMBinary) ->
	case jose_public_key:pem_decode(EncryptedPEMBinary) of
		[EncryptedPEMEntry] ->
			PasswordString = unicode:characters_to_list(Password),
			jose_jwk_kty:from_key(jose_public_key:pem_entry_decode(EncryptedPEMEntry, PasswordString));
		PEMDecodeError ->
			PEMDecodeError
	end.

from_certificate(CertificateBinary) when is_binary(CertificateBinary) ->
	case jose_public_key:pem_decode(CertificateBinary) of
		[CertificatePEMEntry={'Certificate', _, not_encrypted}] ->
			from_certificate(CertificatePEMEntry);
		PEMDecodeError ->
			{error, {pem_decode, PEMDecodeError}}
	end;
from_certificate(CertificatePEMEntry={'Certificate', _, not_encrypted}) ->
	case jose_public_key:pem_entry_decode(CertificatePEMEntry) of
		Certificate=#'Certificate'{} ->
			from_certificate(Certificate);
		PEMEntryDecodeError ->
			{error, {pem_entry_decode, PEMEntryDecodeError}}
	end;
from_certificate(#'Certificate'{tbsCertificate=#'TBSCertificate'{subjectPublicKeyInfo=#'SubjectPublicKeyInfo'{}=SubjectPublicKeyInfo}}) ->
	from_public_key_info(SubjectPublicKeyInfo).

from_public_key_info(#'SubjectPublicKeyInfo'{algorithm=#'AlgorithmIdentifier'{}}=SubjectPublicKeyInfo) ->
	from_public_key_info(jose_public_key:pem_entry_encode('SubjectPublicKeyInfo', SubjectPublicKeyInfo));
from_public_key_info(PEMEntry={'SubjectPublicKeyInfo', DER, not_encrypted}) when is_binary(DER) ->
	jose_jwk_kty:from_key(jose_public_key:pem_entry_decode(PEMEntry)).

to_binary(Password, _KeyType, Key) ->
	CipherInfo = {"AES-256-CBC", #'PBES2-params'{
		keyDerivationFunc = #'PBES2-params_keyDerivationFunc'{
			algorithm = ?'id-PBKDF2',
			parameters = #'PBKDF2-params'{
				salt = {specified, crypto:strong_rand_bytes(8)},
				iterationCount = 2048,
				keyLength = asn1_NOVALUE,
				prf = #'PBKDF2-params_prf'{
					algorithm = ?'id-hmacWithSHA256',
					parameters = {asn1_OPENTYPE, <<5, 0>>}
				}
			}
		},
		encryptionScheme = #'PBES2-params_encryptionScheme'{
			algorithm = ?'id-aes256-CBC',
			parameters = {asn1_OPENTYPE, <<4, 16, (crypto:strong_rand_bytes(16))/binary>>}
		}
	}},
	PasswordString = binary_to_list(iolist_to_binary(Password)),
	PEMEntry = jose_public_key:pem_entry_encode('PrivateKeyInfo', Key, {CipherInfo, PasswordString}),
	jose_public_key:pem_encode([PEMEntry]).
	% DER = jose_public_key:der_encode(KeyType, Key),

	% cipher(Der, {Cipher, KeyDevParams}, Password)->
	% [{'PrivateKeyInfo',
    %  <<220,36,244,78,180,97,107,89,92,125,42,119,137,215,58,78,
    %    166,90,34,175,221,201,79,180,190,215,246,255,22,216,151,
    %    210,136,111,184,65,60,90,18,172,22,12,123,22,125,164,
    %    148,167,248,250,216,144,144,28,187,155,108,240,122,152,
    %    95,210,115,36,179,27,118,53,173,20,159,255,52,165,225,
    %    10,199,92,173,76,235,85,23,36,242,141,62,155,147,122,
    %    131,157,6,113,187,45,228,107,199,187,176,124,98,42,171,
    %    110,209,21,210,180,162,52,196,10,17,93,224,116,7,125,
    %    243,199,27,236,144,166,191,135,11,62,29,92,183,230,173,
    %    122,167,0,192,132,239,113,155,246>>,
    %  {"AES-256-CBC",
    %   #'PBES2-params'{
    %       keyDerivationFunc =
    %           #'PBES2-params_keyDerivationFunc'{
    %               algorithm = {1,2,840,113549,1,5,12},
    %               parameters =
    %                   #'PBKDF2-params'{
    %                       salt = {specified,<<119,229,135,189,166,161,171,173>>},
    %                       iterationCount = 2048,keyLength = asn1_NOVALUE,
    %                       prf =
    %                           #'PBKDF2-params_prf'{
    %                               algorithm = {1,2,840,113549,2,9},
    %                               parameters = {asn1_OPENTYPE,<<5,0>>}}}},
    %       encryptionScheme =
    %           #'PBES2-params_encryptionScheme'{
    %               algorithm = {2,16,840,1,101,3,4,1,42},
    %               parameters =
    %                   {asn1_OPENTYPE,
    %                       <<4,16,166,68,10,177,33,212,87,37,211,187,184,64,
    %                         229,111,144,210>>}}}}}]
	% CipherInfo = {"AES-256-CBC", crypto:strong_rand_bytes(16)},
	% % CipherInfo = {"DES-EDE3-CBC", crypto:strong_rand_bytes(8)},
	% PasswordString = binary_to_list(iolist_to_binary(Password)),
	% PEMEntry = jose_public_key:pem_entry_encode(KeyType, Key, {CipherInfo, PasswordString}),
	% jose_public_key:pem_encode([PEMEntry]).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------
