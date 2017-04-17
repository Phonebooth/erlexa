-module(erlexa_sup).

-behaviour(supervisor).

%% API
-export([start_link/0]).

%% Supervisor callbacks
-export([init/1]).

-define(SERVER, ?MODULE).
-define(CERT_CACHE_TTL, 86400). % 24 hours

%%====================================================================
%% API functions
%%====================================================================

start_link() ->
    supervisor:start_link({local, ?SERVER}, ?MODULE, []).

%%====================================================================
%% Supervisor callbacks
%%====================================================================

init([]) ->
    ChildSpecs = [
        #{
            id => cert_cache,
            start => {cache, start_link, [cert_cache,
                [{n, 1}, {ttl, ?CERT_CACHE_TTL}]]},
            restart => permanent,
            type => worker
        }
    ],
    {ok, {{one_for_one, 10, 10}, ChildSpecs}}.

%%====================================================================
%% Internal functions
%%====================================================================
