#!/usr/bin/env escript
%% coding: utf-8
%%! -noshell

main([Helper]) ->
    case list_to_integer(erlang:system_info(otp_release)) >= 29 of
        true -> ok;
        false -> erlang:error({otp_29_required, erlang:system_info(otp_release)})
    end,
    Base = filename:join([os:getenv("TMPDIR", "/tmp"),
                          "serde-etf-interop-" ++ os:getpid()]),
    OtpPath = Base ++ "-otp.bin",
    ZigPath = Base ++ "-zig.bin",
    try
        Terms = otp_terms(),
        ok = file:write_file(OtpPath, encode_corpus(Terms)),
        ok = run_helper(Helper, OtpPath, ZigPath),
        {ok, ZigCorpus} = file:read_file(ZigPath),
        ZigTerms = decode_corpus(ZigCorpus),
        Expected = [true, null, <<"zig">>, -2147483649, 1 bsl 100,
                    [<<"tuple">>, 42], #{<<"name">> => <<"Ada">>, <<"age">> => 37},
                    [1, 2 | tail]],
        Expected = ZigTerms,
        io:format("ETF interop OK: OTP->Zig ~B terms, Zig->OTP ~B terms~n",
                  [length(Terms), length(ZigTerms)])
    after
        file:delete(OtpPath),
        file:delete(ZigPath)
    end;
main(_) ->
    erlang:error("usage: etf_interop.escript <zig-helper>").

otp_terms() ->
    [0, 255, 256, -2147483648, -2147483649, 1 bsl 100,
     3.141592653589793, hello, 'héllo', <<>>, <<1,2,3>>, <<5:3>>,
     {}, {tuple, 42}, [], [1,2,3], [1,2 | tail],
     #{atom_key => 1, {tuple, key} => <<"value">>},
     self(), make_ref(), fun erlang:length/1, fun(X) -> X + 1 end].

encode_corpus(Terms) ->
    iolist_to_binary([begin
        Bin = term_to_binary(Term),
        <<(byte_size(Bin)):32/big, Bin/binary>>
    end || Term <- Terms]).

decode_corpus(Bin) ->
    decode_corpus(Bin, []).

decode_corpus(<<>>, Acc) ->
    lists:reverse(Acc);
decode_corpus(<<Len:32/big, TermBin:Len/binary, Rest/binary>>, Acc) ->
    Term = binary_to_term(TermBin),
    decode_corpus(Rest, [Term | Acc]);
decode_corpus(_, _) ->
    erlang:error(truncated_zig_corpus).

run_helper(Helper, OtpPath, ZigPath) ->
    Port = open_port({spawn_executable, Helper},
                     [{args, [OtpPath, ZigPath]}, binary, use_stdio,
                      stderr_to_stdout, exit_status]),
    collect_port(Port, []).

collect_port(Port, Output) ->
    receive
        {Port, {data, Data}} -> collect_port(Port, [Data | Output]);
        {Port, {exit_status, 0}} -> ok;
        {Port, {exit_status, Status}} ->
            erlang:error({zig_helper_failed, Status,
                          iolist_to_binary(lists:reverse(Output))})
    end.
