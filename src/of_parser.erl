%% @copyright Geoff Cant
%% @author Geoff Cant <nem@erlang.geek.nz>
%% @version {@vsn}, {@date} {@time}
%% @doc OpenFlow stream parser
%% @end
-module(of_parser).

-define(MIN_PKT_SIZE, 8).

-record(buf, {data = <<>>}).

-opaque parser() :: #buf{}.
-spec new() -> parser().
-spec push(Pkt::binary(), parser()) ->
                  {ok, [of_proto:of_msg()], parser()} |
                  {{error, Reason::any()}, [of_proto:of_msg()], parser()}.

-export([new/0, push/2]).

new() ->
    #buf{data = <<>>}.


push(Pkt, #buf{data = <<>>}) when is_binary(Pkt) ->
    parse(#buf{data = Pkt});
push(Pkt, #buf{data = Old}) when is_binary(Pkt) ->
    NewData = iolist_to_binary([Old, Pkt]),
    parse(#buf{data = NewData}).

%% /* Header on all OpenFlow packets. */
%% struct ofp_header {
%% ￼uint8_t version;
%% uint8_t type;
%% uint16_t length;
%% uint32_t xid;
%% /* OFP_VERSION. */
%% /* One of the OFPT_ constants. */
%% /* Length including this ofp_header. */
%% /* Transaction id associated with this packet.
%%    Replies use the same id as was in the request
%%    to facilitate pairing. */
%% };
%% OFP_ASSERT(sizeof(struct ofp_header) == 8);

parse(Buf = #buf{}) ->
    parse(Buf, []).

parse(Buf = #buf{data = Data}, Acc) when byte_size(Data) < ?MIN_PKT_SIZE ->
    {{incomplete, ?MIN_PKT_SIZE - byte_size(Data)}, lists:reverse(Acc), Buf};
parse(Buf = #buf{data = << Exp:1, Version:7, Type, Length:16/unsigned,
                           XID:32/unsigned, Rest/binary>>},
      Acc) ->
    PktLen = Length - ?MIN_PKT_SIZE,
    case byte_size(Rest) of
        N when N >= PktLen ->
            <<Pkt:PktLen, Tail/binary>> = Rest,
            case parse_pkt(Exp, Version, Type, XID, Pkt) of
                {ok, Msg} ->
                    parse(Buf#buf{data = Tail}, [Msg | Acc]);
                {error,_} = Err ->
                    {Err, Acc, Buf#buf{data = Tail}}
            end;
        N when N < PktLen ->
            {{incomplete, PktLen - N}, Acc, Buf}
    end.

parse_pkt(_Exp, Version, Type, XID, Pkt) ->
    of_proto:decode(Version, Type, XID, Pkt).
