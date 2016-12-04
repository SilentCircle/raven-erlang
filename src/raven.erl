-module(raven).
-include("raven.hrl").
-export([
	start/0,
	stop/0,
	capture/2,
	user_agent/0
]).

-define(SENTRY_VERSION, "2.0").
-define(JSONE_OPTS, [native_utf8, {object_key_type, scalar}]).

-record(cfg, {
	uri :: string(),
	public_key :: string(),
	private_key :: string(),
	project :: string(),
	ipfamily :: atom()
}).

-type cfg_rec() :: #cfg{}.

-spec start() -> ok | {error, term()}.
start() ->
	application:ensure_all_started(?APP).

-spec stop() -> ok | {error, term()}.
stop() ->
	application:stop(?APP).

-spec capture(string() | binary(), [parameter()]) -> ok.
-type parameter() ::
	{stacktrace, [stackframe()]} |
	{exception, {exit | error | throw, term()}} |
	{atom(), binary() | integer()}.
-type stackframe() ::
	{module(), atom(), non_neg_integer() | [term()]} |
	{module(), atom(), non_neg_integer() | [term()], [{atom(), term()}]}.
capture(Message, Params) when is_list(Message) ->
	capture(unicode:characters_to_binary(Message), Params);
capture(Message, Params0) ->
	Cfg = get_config(),
	Params1 = [{tags, get_tags()} | Params0],
	Document = {[
		{event_id, event_id_i()},
		{project, unicode:characters_to_binary(Cfg#cfg.project)},
		{platform, erlang},
		{server_name, node()},
		{timestamp, timestamp_i()},
		{message, term_to_json_i(Message)} |
		lists:map(fun
			({stacktrace, Value}) ->
				{'sentry.interfaces.Stacktrace', {[
					{frames,lists:reverse([frame_to_json_i(Frame) || Frame <- Value])}
				]}};
			({exception, {Type, Value}}) ->
				{'sentry.interfaces.Exception', {[
					{type, Type},
					{value, term_to_json_i(Value)}
				]}};
			({tags, Tags}) ->
				{tags, {[{Key, term_to_json_i(Value)} || {Key, Value} <- Tags]}};
			({extra, Tags}) ->
				{extra, {[{Key, term_to_json_i(Value)} || {Key, Value} <- Tags]}};
			({Key, Value}) ->
				{Key, term_to_json_i(Value)}
		end, Params1)
	]},
	Timestamp = integer_to_list(unix_timestamp_i()),
	Body = base64:encode(zlib:compress(jsone:encode(Document, ?JSONE_OPTS))),
	UA = user_agent(),
	Headers = [
		{"X-Sentry-Auth",
		["Sentry sentry_version=", ?SENTRY_VERSION,
		 ",sentry_client=", UA,
		 ",sentry_timestamp=", Timestamp,
		 ",sentry_key=", Cfg#cfg.public_key]},
		{"User-Agent", UA}
	],
	ok = httpc:set_options([{ipfamily, Cfg#cfg.ipfamily}]),
	httpc:request(post,
		{Cfg#cfg.uri ++ "/api/store/", Headers, "application/octet-stream", Body},
		[],
		[{body_format, binary}, {sync, false}, {receiver, fun(_) -> ok end}]
	),
	ok.

-spec user_agent() -> iolist().
user_agent() ->
	{ok, Vsn} = application:get_key(?APP, vsn),
	["raven-erlang/", Vsn].

%% @private
-spec get_config() -> cfg_rec().
get_config() ->
	get_config(?APP).

-spec get_config(App :: atom()) -> cfg_rec().
get_config(App) ->
	{ok, IpFamily} = application:get_env(App, ipfamily),
	case application:get_env(App, dsn) of
		{ok, Dsn} ->
			{match, [_, Protocol, PublicKey, SecretKey, Uri, Project]} =
				re:run(Dsn, "^(https?://)(.+):(.+)@(.+)/(.+)$", [{capture, all, list}]),
			#cfg{uri = Protocol ++ Uri,
			     public_key = PublicKey,
			     private_key = SecretKey,
			     project = Project,
			     ipfamily = IpFamily};
		undefined ->
			{ok, Uri} = application:get_env(App, uri),
			{ok, PublicKey} = application:get_env(App, public_key),
			{ok, PrivateKey} = application:get_env(App, private_key),
			{ok, Project} = application:get_env(App, project),
			#cfg{uri = Uri,
			     public_key = PublicKey,
			     private_key = PrivateKey,
			     project = Project,
			     ipfamily = IpFamily}
	end.

get_tags() ->
	application:get_env(?APP, tags, []).

%% Thanks to Michael Truog, from whom this technique was lifted
%% (with my modifications. Since this is not being used for true cryptographic
%% purposes, but only for event IDs, substituting rand_bytes for
%% strong_rand_bytes should not be a big deal. If it is, this can easily
%% be changed.
event_id_i() ->
    <<Rand1:48, _:4, Rand2:12, _:2, Rand3:62>> = crypto:rand_bytes(16),
    binary_to_hex_binary(<<Rand1:48,
                           0:1, 1:1, 0:1, 0:1,  % version 4 bits
                           Rand2:12,
                           1:1, 0:1,            % RFC 4122 variant bits
                           Rand3:62>>).

timestamp_i() ->
	{{Y,Mo,D}, {H,M,S}} = calendar:now_to_universal_time(erlang:timestamp()),
    YH = Y div 100, YL = Y rem 100,
    <<(i2d_h(YH)),(i2d_l(YH)),(i2d_h(YL)),(i2d_l(YL)),
      $-,(i2d_h(Mo)),(i2d_l(Mo)),
      $-,(i2d_h(D)),(i2d_l(D)),
      $T,(i2d_h(H)),(i2d_l(H)),
      $:,(i2d_h(M)),(i2d_l(M)),
      $:,(i2d_h(S)),(i2d_l(S))>>.

-ifdef(new_time).
unix_timestamp_i() ->
    erlang:system_time(seconds).
-else.
unix_timestamp_i() ->
	{Mega, Sec, Micro} = os:timestamp(),
	Mega * 1000000 * 1000000 + Sec * 1000000 + Micro.
-endif.

frame_to_json_i({Module, Function, Arguments}) ->
	frame_to_json_i({Module, Function, Arguments, []});
frame_to_json_i({Module, Function, Arguments, Location}) ->
	Arity = case is_list(Arguments) of
		true -> length(Arguments);
		false -> Arguments
	end,
	Line = case lists:keyfind(line, 1, Location) of
		false -> -1;
		{line, L} -> L
	end,
	{
		case is_list(Arguments) of
			true -> [{vars, [iolist_to_binary(io_lib:format("~w", [Argument])) || Argument <- Arguments]}];
			false -> []
		end ++ [
			{module, Module},
			{function, <<(atom_to_binary(Function, utf8))/binary, "/", (list_to_binary(integer_to_list(Arity)))/binary>>},
			{lineno, Line},
			{filename, case lists:keyfind(file, 1, Location) of
				false -> <<(atom_to_binary(Module, utf8))/binary, ".erl">>;
				{file, File} -> list_to_binary(File)
			end}
		]
	}.

term_to_json_i(Term) when is_binary(Term); is_atom(Term) ->
	Term;
term_to_json_i(Term) ->
	iolist_to_binary(io_lib:format("~120p", [Term])).

binary_to_hex_binary(<<B/binary>>) when bit_size(B) band 2#11 =:= 0 ->
    list_to_binary([int_to_hex(I) || <<I:4>> <= B]).

i2d_h(N) -> int_to_dec(N div 10).
i2d_l(N) -> int_to_dec(N rem 10).

int_to_hex(0)  -> $0;
int_to_hex(1)  -> $1;
int_to_hex(2)  -> $2;
int_to_hex(3)  -> $3;
int_to_hex(4)  -> $4;
int_to_hex(5)  -> $5;
int_to_hex(6)  -> $6;
int_to_hex(7)  -> $7;
int_to_hex(8)  -> $8;
int_to_hex(9)  -> $9;
int_to_hex(10) -> $a;
int_to_hex(11) -> $b;
int_to_hex(12) -> $c;
int_to_hex(13) -> $d;
int_to_hex(14) -> $e;
int_to_hex(15) -> $f.

int_to_dec(0)  -> $0;
int_to_dec(1)  -> $1;
int_to_dec(2)  -> $2;
int_to_dec(3)  -> $3;
int_to_dec(4)  -> $4;
int_to_dec(5)  -> $5;
int_to_dec(6)  -> $6;
int_to_dec(7)  -> $7;
int_to_dec(8)  -> $8;
int_to_dec(9)  -> $9.

-compile({inline,
          [
           {int_to_hex,1},
           {int_to_dec,1},
           {binary_to_hex_binary,1},
           {i2d_h,1},
           {i2d_l,1}
          ]}).

