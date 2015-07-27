%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2015, Andrew Bennett
%%% @doc AES Key Wrap
%%% See RFC 5297: https://tools.ietf.org/html/rfc5297
%%% @end
%%% Created :  22 Jul 2015 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(jose_jwa_aes_kw).

%% API
-export([wrap/2]).
-export([wrap/3]).
-export([unwrap/2]).
-export([unwrap/3]).

-define(BIT64, 1/unsigned-big-integer-unit:64).
-define(DEFAULT_IV, << 16#A6A6A6A6A6A6A6A6:?BIT64 >>).

%%====================================================================
%% API functions
%%====================================================================

wrap(UnwrappedKey, KEK) ->
	wrap(UnwrappedKey, KEK, ?DEFAULT_IV).

wrap(UnwrappedKey, KEK, IV) ->
	Buffer = << IV/binary, UnwrappedKey/binary >>,
	BlockCount = (byte_size(Buffer) div 8) - 1,
	do_wrap(Buffer, 0, BlockCount, KEK).

unwrap(WrappedKey, KEK) ->
	unwrap(WrappedKey, KEK, ?DEFAULT_IV).

unwrap(WrappedKey, KEK, IV) ->
	BlockCount = (byte_size(WrappedKey) div 8) - 1,
	IVSize = byte_size(IV),
	case do_unwrap(WrappedKey, 5, BlockCount, KEK) of
		<< IV:IVSize/binary, UnwrappedKey/binary >> ->
			UnwrappedKey;
		_ ->
			erlang:error({badarg, [WrappedKey, KEK, IV]})
	end.

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
do_wrap(Buffer, 6, _BlockCount, _KEK) ->
	Buffer;
do_wrap(Buffer, J, BlockCount, KEK) ->
	do_wrap(do_wrap(Buffer, J, 1, BlockCount, KEK), J + 1, BlockCount, KEK).

%% @private
do_wrap(Buffer, _J, I, BlockCount, _KEK) when I > BlockCount ->
	Buffer;
do_wrap(<< A0:8/binary, Rest/binary >>, J, I, BlockCount, KEK) ->
	HeadSize = (I - 1) * 8,
	<< Head:HeadSize/binary, B0:8/binary, Tail/binary >> = Rest,
	Round = (BlockCount * J) + I,
	Data = << A0/binary, B0/binary >>,
	<< A1:?BIT64, B1/binary >> = crypto:block_encrypt(aes_ecb, KEK, Data),
	A2 = A1 bxor Round,
	do_wrap(<< A2:?BIT64, Head/binary, B1/binary, Tail/binary >>, J, I + 1, BlockCount, KEK).

%% @private
do_unwrap(Buffer, J, _BlockCount, _KEK) when J < 0 ->
	Buffer;
do_unwrap(Buffer, J, BlockCount, KEK) ->
	do_unwrap(do_unwrap(Buffer, J, BlockCount, BlockCount, KEK), J - 1, BlockCount, KEK).

%% @private
do_unwrap(Buffer, _J, I, _BlockCount, _KEK) when I < 1 ->
	Buffer;
do_unwrap(<< A0:?BIT64, Rest/binary >>, J, I, BlockCount, KEK) ->
	HeadSize = (I - 1) * 8,
	<< Head:HeadSize/binary, B0:8/binary, Tail/binary >> = Rest,
	Round = (BlockCount * J) + I,
	A1 = A0 bxor Round,
	Data = << A1:?BIT64, B0/binary >>,
	<< A2:8/binary, B1/binary >> = crypto:block_decrypt(aes_ecb, KEK, Data),
	do_unwrap(<< A2/binary, Head/binary, B1/binary, Tail/binary >>, J, I - 1, BlockCount, KEK).
