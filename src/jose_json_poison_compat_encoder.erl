%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
%%%-------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright 2014-2015, Andrew Bennett
%%% @doc
%%%
%%% @end
%%% Created :  14 Aug 2015 by Andrew Bennett <andrew@pixid.com>
%%%-------------------------------------------------------------------
-module(jose_json_poison_compat_encoder).
-behaviour(jose_json).

%% jose_json callbacks
-export([decode/1]).
-export([encode/1]).

%%====================================================================
%% jose_json callbacks
%%====================================================================

decode(Binary) ->
	'Elixir.Poison':'decode!'(Binary).

encode(Term) ->
	'Elixir.IO':'iodata_to_binary'(encode_iodata(Term)).

%%%-------------------------------------------------------------------
%%% Internal functions
%%%-------------------------------------------------------------------

%% @private
encode_iodata(HashDict = #{ '__struct__' := 'Elixir.HashDict' }) ->
	encode_hash_dict_iodata(HashDict);
encode_iodata(HashSet = #{ '__struct__' := 'Elixir.HashSet' }) ->
	encode_iodata('Elixir.Enum':'flat_map'(HashSet, fun identity_list/1));
encode_iodata(Range = #{ '__struct__' := 'Elixir.Range' }) ->
	encode_iodata('Elixir.Enum':'flat_map'(Range, fun identity_list/1));
encode_iodata(Stream = #{ '__struct__' := 'Elixir.Stream' }) ->
	encode_iodata('Elixir.Enum':'flat_map'(Stream, fun identity_list/1));
encode_iodata(Struct = #{ '__struct__' := ElixirType }) ->
	case is_struct_supported(ElixirType) of
		false ->
			encode_iodata('Elixir.Map':'from_struct'(Struct));
		true ->
			'Elixir.Poison':'encode_to_iodata!'(Struct)
	end;
encode_iodata(Map) when is_map(Map) andalso map_size(Map) < 1 ->
	<<"{}">>;
encode_iodata(Map) when is_map(Map) ->
	encode_map_iodata(Map);
encode_iodata(List) when is_list(List) ->
	encode_list_iodata(List);
encode_iodata(Term) ->
	'Elixir.Poison':'encode_to_iodata!'(Term).

%% @private
encode_hash_dict_iodata(HashDict = #{ '__struct__' := 'Elixir.HashDict' }) ->
	encode_map_iodata(maps:from_list('Elixir.HashDict':'to_list'(HashDict))).

%% @private
encode_list_iodata(List) when is_list(List) ->
	[encode_iodata(Term) || Term <- List].

%% @private
encode_map_iodata(Map) when is_map(Map) ->
	Folder = fun(Key, Acc) ->
		[$,, 'Elixir.Poison.Encoder.BitString':'encode'(encode_name(Key), []), $:,
			encode(maps:get(Key, Map)) | Acc]
	end,
	[${, tl(lists:foldr(Folder, [], maps:keys(Map))), $}].

%% @private
encode_name(Value) when is_binary(Value) ->
	Value;
encode_name(Value) when is_atom(Value) ->
	'Elixir.Atom':'to_string'(Value);
encode_name(Value) ->
	'Elixir.Kernel':'raise'('Elixir.Poison.EncodeError', [
		{value, Value},
		{message, << "expected string or atom key, got: ", ('Elixir.Kernel':'inspect'(Value))/binary >>}
	]).

%% @private
identity_list(Identity) -> [Identity].

%% @private
is_struct_supported(ElixirType) ->
	case atom_to_binary(ElixirType, unicode) of
		<< "Elixir.", Type/binary >> ->
			try binary_to_existing_atom(<< "Elixir.Poison.Encoder.", Type/binary >>, unicode) of
				EncoderType ->
					case code:ensure_loaded(EncoderType) of
						{module, EncoderType} ->
							true;
						_ ->
							false
					end
			catch
				_:_ ->
					false
			end;
		_ ->
			false
	end.
