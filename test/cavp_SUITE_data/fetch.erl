%%% Copyright (c) Andrew Bennett
%%%
%%% This source code is licensed under the MIT license found in the
%%% LICENSE.md file in the root directory of this source tree.
%%%
%%% % @format
%%%-----------------------------------------------------------------------------
%%% @author Andrew Bennett <andrew@pixid.com>
%%% @copyright (c) Andrew Bennett
%%% @doc Based on core_http_get.erl
%%% See [https://github.com/ninenines/erlang.mk/blob/0eb54a71605a955df14c5df793ebe676c86259f9/core/core.mk]
%%% @end
%%% Created :  13 Aug 2015 by Andrew Bennett <andrew@pixid.com>
%%%-----------------------------------------------------------------------------
-module(fetch).

%% API
-export([fetch/2]).

%%%=============================================================================
%%% API functions
%%%=============================================================================

fetch(URL = "ftp" ++ _, OutputFile) ->
    ssl:start(),
    inets:start(),
    <<"ftp://", HostPath/binary>> = list_to_binary(URL),
    [Host | Paths] = binary:split(HostPath, <<$/>>, [global]),
    [File | RevPath] = lists:reverse(Paths),
    Path = lists:reverse(RevPath),
    HostString = binary_to_list(Host),
    FileString = binary_to_list(File),
    PathString = lists:flatten([[binary_to_list(P), $/] || P <- Path]),
    case ftp:open(HostString) of
        {ok, Pid} ->
            case ftp:user(Pid, "anonymous", "") of
                ok ->
                    case ftp:type(Pid, binary) of
                        ok ->
                            case ftp:cd(Pid, PathString) of
                                ok ->
                                    case ftp:recv_bin(Pid, FileString) of
                                        {ok, Body} ->
                                            _ = (catch ftp:close(Pid)),
                                            file:write_file(OutputFile, Body);
                                        RecvError ->
                                            _ = (catch ftp:close(Pid)),
                                            RecvError
                                    end;
                                CdError ->
                                    _ = (catch ftp:close(Pid)),
                                    CdError
                            end;
                        TypeError ->
                            _ = (catch ftp:close(Pid)),
                            TypeError
                    end;
                UserError ->
                    _ = (catch ftp:close(Pid)),
                    UserError
            end;
        OpenError ->
            OpenError
    end;
fetch(URL = "http" ++ _, File) ->
    ssl:start(),
    inets:start(),
    case httpc:request(get, {URL, []}, [{autoredirect, true}], []) of
        {ok, {{_, 200, _}, _, Body}} ->
            file:write_file(File, Body);
        Error ->
            Error
    end.

%%%-----------------------------------------------------------------------------
%%% Internal functions
%%%-----------------------------------------------------------------------------
