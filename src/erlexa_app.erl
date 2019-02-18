-module(erlexa_app).

-behaviour(application).

%% Application callbacks
-export([
    start/2,
    stop/1
]).

%%====================================================================
%% API
%%====================================================================

start(_StartType, _StartArgs) ->
    ok=application_utils:ensure_started(asn1),
    ok=application_utils:ensure_started(inets),
    ok=application_utils:ensure_started(crypto),
    ok=application_utils:ensure_started(public_key),
    ok=application_utils:ensure_started(ssl),
    ok=application_utils:ensure_started(ibrowse),
    erlexa_sup:start_link().

%%--------------------------------------------------------------------
stop(_State) ->
    ok.

%%====================================================================
%% Internal functions
%%====================================================================
