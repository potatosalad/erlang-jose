%%% Copyright (c) Andrew Bennett
%%%
%%% This source code is licensed under the MIT license found in the
%%% LICENSE.md file in the root directory of this source tree.
%%%
%%% % @format
-module(jose_jwa_pkcs7_props).

-include_lib("proper/include/proper.hrl").

% -compile(export_all).

prop_pad_and_unpad() ->
    ?FORALL(
        Binary,
        binary(),
        begin
            PaddedBinary = jose_jwa_pkcs7:pad(Binary),
            Binary =:= jose_jwa_pkcs7:unpad(PaddedBinary)
        end
    ).
