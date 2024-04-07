%%% % @format
-module(jose_ct).

-include_lib("common_test/include/ct.hrl").

%% API
-export([start/2]).
-export([stop/1]).
-export([progress_start/0]).
-export([progress_stop/1]).

%% Internal API
-export([init/1]).

%% Macros
-define(RED, "\e[0;31m").
-define(GREEN, "\e[0;32m").
-define(YELLOW, "\e[0;33m").
-define(WHITE, "\e[0;37m").
-define(CYAN, "\e[0;36m").
-define(RESET, "\e[0m").
% timer:seconds(1)
-define(TIME, 1000).

start(Group, Config) ->
    Now = os:timestamp(),
    io:format(user, "~s[  ] ~s :: ~s~s", [?WHITE, format_utc_timestamp(Now), Group, ?RESET]),
    {ok, Progress} = progress_start(),
    [{jose_ct, {Progress, Now}} | Config].

stop(Config) ->
    Now = os:timestamp(),
    {Progress, Old} = ?config(jose_ct, Config),
    ok = progress_stop(Progress),
    Diff = timer:now_diff(Now, Old),
    io:format(user, "~s[OK] ~s :: ~s elapsed~s~n", [
        ?GREEN, format_utc_timestamp(Now), format_elapsed_time(Diff), ?RESET
    ]),
    ok.

progress_start() ->
    Ref = erlang:make_ref(),
    {ok, Pid} = proc_lib:start(?MODULE, init, [{self(), Ref}]),
    {ok, {Ref, Pid}}.

progress_stop({Ref, Pid}) ->
    Pid ! {stop, self(), Ref},
    receive
        Ref ->
            ok
    after 1000 ->
        ok
    end.

%% @private
format_elapsed_time(USec) ->
    Micro = USec rem 1000000,
    Second = ((USec - Micro) div 1000000) rem 60,
    Minute = ((USec - (Second * 1000000)) div 6000000) rem 60,
    Hour = ((USec - (Minute * 6000000)) div 360000000) rem 24,
    io_lib:format("~2..0w:~2..0w:~2..0w.~6..0w", [Hour, Minute, Second, Micro]).

%% @private
format_utc_timestamp(TS = {_, _, Micro}) ->
    {{Year, Month, Day}, {Hour, Minute, Second}} = calendar:now_to_universal_time(TS),
    io_lib:format("~4..0w-~2..0w-~2..0w ~2..0w:~2..0w:~2..0w.~6..0w", [Year, Month, Day, Hour, Minute, Second, Micro]).

%% @private
init({Parent, Ref}) ->
    process_flag(trap_exit, true),
    ok = proc_lib:init_ack(Parent, {ok, self()}),
    {ok, TRef} = timer:send_interval(?TIME, {tick, Ref}),
    loop(Ref, TRef).

%% @private
loop(Ref, TRef) ->
    receive
        {tick, Ref} ->
            io:format(user, "~s.~s", [?WHITE, ?RESET]),
            loop(Ref, TRef);
        {stop, Parent, Ref} when is_pid(Parent) ->
            io:format(user, "~n", []),
            catch timer:cancel(TRef),
            Parent ! Ref,
            exit(normal);
        Info ->
            io:format(user, "~n~s[~s] received unhandled message:~n~p~s~n", [?RED, ?MODULE, Info, ?RESET]),
            loop(Ref, TRef)
    end.
