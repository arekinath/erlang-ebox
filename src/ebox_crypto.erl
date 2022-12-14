%%
%% ebox
%% pivy box/ebox parsing for Erlang
%%
%% Copyright 2021 The University of Queensland
%% Author: Alex Wilson <alex@uq.edu.au>
%%
%% Redistribution and use in source and binary forms, with or without
%% modification, are permitted provided that the following conditions
%% are met:
%% 1. Redistributions of source code must retain the above copyright
%%    notice, this list of conditions and the following disclaimer.
%% 2. Redistributions in binary form must reproduce the above copyright
%%    notice, this list of conditions and the following disclaimer in the
%%    documentation and/or other materials provided with the distribution.
%%
%% THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
%% IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
%% OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
%% IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
%% INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
%% NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
%% DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
%% THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
%% (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
%% THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
%%

-module(ebox_crypto).

-include_lib("public_key/include/public_key.hrl").

-export([
    cipher_info/1,
    one_time/4,
    compress/1,
    decompress/1
    ]).

atomize_curve(?'secp256r1') -> secp256r1;
atomize_curve(?'secp384r1') -> secp384r1;
atomize_curve(?'secp521r1') -> secp521r1.

-spec compress(ebox:pubkey()) -> ebox:pubkey().
compress(K = {#'ECPoint'{point = <<16#02, _/binary>>}, _}) -> K;
compress(K = {#'ECPoint'{point = <<16#03, _/binary>>}, _}) -> K;
compress({#'ECPoint'{point = P0}, {namedCurve, Curve}}) when is_atom(Curve) ->
    P1 = ec_conv_nif:compress(Curve, P0),
    {#'ECPoint'{point = P1}, {namedCurve, Curve}};
compress({Pt, {namedCurve, Oid}}) ->
    compress({Pt, {namedCurve, atomize_curve(Oid)}}).

-spec decompress(ebox:pubkey()) -> ebox:pubkey().
decompress(K = {#'ECPoint'{point = <<16#04, _/binary>>}, _}) -> K;
decompress({#'ECPoint'{point = P0}, {namedCurve, Curve}}) when is_atom(Curve) ->
    P1 = ec_conv_nif:decompress(Curve, P0),
    {#'ECPoint'{point = P1}, {namedCurve, Curve}};
decompress({Pt, {namedCurve, Oid}}) ->
    decompress({Pt, {namedCurve, atomize_curve(Oid)}}).

cipher_info('chacha20-poly1305') ->
    #{block_size => 8, key_len => 64, iv_len => 0, auth_len => 16};
cipher_info('aes128-gcm') ->
    #{block_size => 16, key_len => 16, iv_len => 12, auth_len => 16};
cipher_info('aes256-gcm') ->
    #{block_size => 16, key_len => 32, iv_len => 12, auth_len => 16}.

one_time(Cipher, Key, Data, true) ->
    one_time(Cipher, Key, Data, #{encrypt => true});
one_time(Cipher, Key, Data, false) ->
    one_time(Cipher, Key, Data, #{encrypt => false});
one_time(Cipher, Key, Data, Opts) when is_list(Opts) ->
    one_time(Cipher, Key, Data, maps:from_list(Opts));
one_time('aes128-gcm', Key, Data, #{encrypt := true, iv := IV}) ->
    {EncData, Ctag} = crypto:crypto_one_time_aead(aes_128_gcm, Key, IV, Data, <<>>, true),
    <<EncData/binary, Ctag/binary>>;
one_time('aes128-gcm', Key, Data, #{encrypt := false, iv := IV}) ->
    <<EncData:(byte_size(Data) - 16)/binary, Ctag:16/binary>> = Data,
    Res = crypto:crypto_one_time_aead(aes_128_gcm, Key, IV, EncData, <<>>, Ctag, false),
    case Res of
        error -> error(bad_mac);
        _ -> Res
    end;
one_time('aes128-gcm', _Key, _Data, Opts = #{encrypt := _}) ->
    error({badarg, {missing_iv, Opts}});
one_time('aes256-gcm', Key, Data, #{encrypt := true, iv := IV}) ->
    {EncData, Ctag} = crypto:crypto_one_time_aead(aes_256_gcm, Key, IV, Data, <<>>, true),
    <<EncData/binary, Ctag/binary>>;
one_time('aes256-gcm', Key, Data, #{encrypt := false, iv := IV}) ->
    <<EncData:(byte_size(Data) - 16)/binary, Ctag:16/binary>> = Data,
    Res = crypto:crypto_one_time_aead(aes_256_gcm, Key, IV, EncData, <<>>, Ctag, false),
    case Res of
        error -> error(bad_mac);
        _ -> Res
    end;
one_time('aes256-gcm', _Key, _Data, Opts = #{encrypt := _}) ->
    error({badarg, {missing_iv, Opts}});
one_time('chacha20-poly1305', Key, Data, Opts = #{encrypt := true}) ->
    Seq = maps:get(seq, Opts, 0),
    <<K2:32/binary, _K1:32/binary>> = Key,

    IV = <<1:8/little-unit:8, Seq:8/unit:8>>,
    EncData = crypto:crypto_one_time(chacha20, K2, IV, Data, true),

    PolyKey = crypto:crypto_one_time(chacha20, K2, <<0:8/unit:8, Seq:8/unit:8>>,
        <<0:32/unit:8>>, true),
    Ctag = crypto:mac(poly1305, PolyKey, EncData),
    <<EncData/binary, Ctag/binary>>;
one_time('chacha20-poly1305', Key, Data, Opts = #{encrypt := false}) ->
    Seq = maps:get(seq, Opts, 0),
    <<K2:32/binary, _K1:32/binary>> = Key,
    <<EncData:(byte_size(Data) - 16)/binary, Ctag:16/binary>> = Data,

    IV = <<1:8/little-unit:8, Seq:8/unit:8>>,
    PlainData = crypto:crypto_one_time(chacha20, K2, IV, EncData, false),

    PolyKey = crypto:crypto_one_time(chacha20, K2, <<0:8/unit:8, Seq:8/unit:8>>,
        <<0:32/unit:8>>, true),
    OurCtag = crypto:mac(poly1305, PolyKey, EncData),

    TheirHash = crypto:hash(sha512, Ctag),
    OurHash = crypto:hash(sha512, OurCtag),
    if
        (TheirHash =:= OurHash) -> PlainData;
        true -> error(bad_mac)
    end.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

basic_chacha_encrypt_test() ->
    Key = base64:decode(<<"si4+xc3NPBrHVFBWnUebmBGvs3N6a6XhoGCCeQAbPrWD3FbUGCQpO6gP4XSbloFIydqeKq93uPALjJEIFlHS0Q==">>),
    Plain = <<"hi\n">>,
    Cipher = one_time('chacha20-poly1305', Key, Plain, #{encrypt => true}),
    ?assertMatch(<<"elw+TTiIP7TCByLdUiN6kjFMDA==">>, base64:encode(Cipher)).

basic_chacha_decrypt_test() ->
    Key = base64:decode(<<"si4+xc3NPBrHVFBWnUebmBGvs3N6a6XhoGCCeQAbPrWD3FbUGCQpO6gP4XSbloFIydqeKq93uPALjJEIFlHS0Q==">>),
    Cipher = base64:decode(<<"elw+Y3XG9f5miJkHlW+QLaR02NKQTlTD">>),
    Plain = one_time('chacha20-poly1305', Key, Cipher, #{encrypt => false}),
    ?assertMatch(<<"hi\n", 5, 5, 5, 5, 5>>, Plain).

invalid_chacha_decrypt_test() ->
    Key = base64:decode(<<"si4+xc3NPBrHVFBWnUebmBGvs3N6a6XhoGCCeQAbPrWD3FbUGCQpO6gP4XSbloFIydqeKq93uPALjJEIFlHS0Q==">>),
    Cipher = base64:decode(<<"elw+Y3XG9f5eiJkalW+QLaR02NKQTlTD">>),
    ?assertError(bad_mac,
        one_time('chacha20-poly1305', Key, Cipher, #{encrypt => false})).

basic_aes_encrypt_test() ->
    Key = base64:decode(<<"OnLlzSMvzgBLzT6+AoEI+A==">>),
    IV = base64:decode(<<"GMOlgYXD5madK2U+">>),
    Pad = binary:copy(<<13>>, 13),
    Plain = <<"hi\n", Pad/binary>>,
    Cipher = one_time('aes128-gcm', Key, Plain, #{encrypt => true, iv => IV}),
    ?assertMatch(<<"94P4MU2MSoitPuyUeuPOuh+Wo5ZgKgSG2ju6SOojI0o=">>, base64:encode(Cipher)).

basic_aes_decrypt_test() ->
    Key = base64:decode(<<"OnLlzSMvzgBLzT6+AoEI+A==">>),
    IV = base64:decode(<<"GMOlgYXD5madK2U+">>),
    Cipher = base64:decode(<<"94P4MU2MSoitPuyUeuPOuh+Wo5ZgKgSG2ju6SOojI0o=">>),
    Plain = one_time('aes128-gcm', Key, Cipher, #{encrypt => false, iv => IV}),
    ?assertMatch(<<"hi\n", 13, _/binary>>, Plain).

-endif.
