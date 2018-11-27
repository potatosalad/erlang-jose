%% -*- mode: erlang; tab-width: 4; indent-tabs-mode: 1; st-rulers: [70] -*-
%% vim: ts=4 sw=4 ft=erlang noet
-module(jose_jwa_pkcs7_props).

-include_lib("proper/include/proper.hrl").

% -compile(export_all).

prop_pad_and_unpad() ->
	?FORALL(Binary,
		binary(),
		begin
			PaddedBinary = jose_jwa_pkcs7:pad(Binary),
			Binary =:= jose_jwa_pkcs7:unpad(PaddedBinary)
		end).
