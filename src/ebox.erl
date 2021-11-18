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

-module(ebox).

-include("ebox.hrl").

-type ebox() :: #ebox{}.

-type box() :: #ebox_box{}.

-type config() :: #ebox_config{}.

-type part() :: #ebox_part{}.

-type tpl() :: #ebox_tpl{}.

-type pubkey() :: #'RSAPublicKey'{} | {#'ECPoint'{}, {namedCurve, crypto:ec_named_curve()}}.
%% A cryptographic public key.

-type tpl_config() :: #ebox_tpl_primary_config{} | #ebox_tpl_recovery_config{}.
%% One possible configuration which can be used to unlock the ebox.

-type tpl_part() :: #ebox_tpl_part{}.
%% An individual "part" of a primary or recovery configuration, representing
%% one device/piece.

-type slot() :: symbolic_slot() | numeric_slot().
%% PIV key reference / slot identifier.

-type symbolic_slot() :: piv_auth | piv_sign | piv_card_auth | piv_key_mgmt |
    {retired, integer()}.
%% Slot symbolic identifier

-type numeric_slot() :: integer().
%% Slot number, e.g. <code>16#9A</code>

-type guid() :: binary().
%% GUID in raw binary form (16 bytes).

-type cipher() :: 'chacha20-poly1305' | 'aes128-gcm' | 'aes256-gcm'.
-type kdf() :: 'sha256' | 'sha384' | 'sha512'.

-type recovery_box() :: #ebox_recovery_box{}.

-export_type([
    tpl_config/0, pubkey/0, tpl_part/0, slot/0,
    guid/0, tpl/0, ebox/0, config/0, part/0, box/0, cipher/0, kdf/0,
    recovery_box/0
    ]).

-export([
    decode/1
    ]).

-define(EBOX_TEMPLATE, 16#01).
-define(EBOX_KEY, 16#02).
-define(EBOX_STREAM, 16#03).

-define(EBOX_PRIMARY, 16#01).
-define(EBOX_RECOVERY, 16#02).

slot_to_sym(Slot) ->
    case Slot of
        16#9a -> piv_auth;
        16#9c -> piv_sign;
        16#9e -> piv_card_auth;
        16#9d -> piv_key_mgmt;
        _ -> Slot
    end.

curve_to_tup(Curve) ->
    case Curve of
        <<"nistp256">> -> {namedCurve, secp256r1};
        <<"nistp384">> -> {namedCurve, secp384r1};
        <<"nistp521">> -> {namedCurve, secp521r1}
    end.

cipher_to_atom(Cipher) ->
    case Cipher of
        <<"chacha20-poly1305">> -> 'chacha20-poly1305';
        <<"aes128-gcm">> -> 'aes128-gcm';
        <<"aes256-gcm">> -> 'aes256-gcm'
    end.

decode(B = <<16#B0, 16#C5, Version, _Rest0/binary>>)
                                    when (Version >= 1) and (Version =< 2) ->
    {Box, <<>>} = decode_box(B),
    Box;
decode(<<16#EB, 16#0C, Version, ?EBOX_TEMPLATE, NConfigs, Rest0/binary>>) ->
    {Configs, <<>>} = n_decode(Version,
        NConfigs, fun decode_tpl_config/2, Rest0),
    #ebox_tpl{
        version = Version,
        configs = Configs
    };
decode(<<16#EB, 16#0C, Version, ?EBOX_KEY, Rest0/binary>>) ->
    <<RCipherLen, RCipher:RCipherLen/binary,
      RIVLen, RIV:RIVLen/binary,
      REncLen, REnc:REncLen/binary, Rest1/binary>> = Rest0,
    RecovBox = #ebox_recovery_box{
        cipher = cipher_to_atom(RCipher),
        iv = RIV,
        ciphertext = REnc
    },
    {Ephems, Rest2} = if
        (Version >= 2) ->
            <<EphemCount, RR0/binary>> = Rest1,
            n_decode(Version, EphemCount, fun decode_ephem_key/2, RR0);
        true ->
            {[], Rest1}
    end,
    <<NConfigs, Rest3/binary>> = Rest2,
    {Configs, <<>>} = n_decode(Version, NConfigs, fun decode_config/2, Rest3),
    Tpl = #ebox_tpl{
        version = 1,
        configs = [Tpl || #ebox_config{template = Tpl} <- Configs]
    },
    #ebox{
        version = Version,
        template = Tpl,
        configs = Configs,
        ephemeral_keys = Ephems,
        recovery_box = RecovBox
    };
decode(<<16#EB, 16#0C, Version, ?EBOX_STREAM, Rest0/binary>>) ->
    #ebox{}.

decode_box(<<16#B0, 16#C5, Version, Rest0/binary>>) ->
    <<GuidSlotValid, GuidLen, Guid:GuidLen/binary, Slot, Rest1/binary>> = Rest0,
    <<CipherLen, Cipher:CipherLen/binary, KDFLen, KDF:KDFLen/binary, Rest2/binary>> = Rest1,
    <<NonceLen, Nonce:NonceLen/binary, CurveLen, Curve:CurveLen/binary, Rest3/binary>> = Rest2,
    <<PubKeyLen, PubKey:PubKeyLen/binary, EphKeyLen, EphKey:EphKeyLen/binary, Rest4/binary>> = Rest3,
    <<IVLen, IV:IVLen/binary, EncLen:32/big, Enc:EncLen/binary, Rest5/binary>> = Rest4,
    CipherAtom = cipher_to_atom(Cipher),
    KDFAtom = case KDF of
        <<"sha256">> -> 'sha256';
        <<"sha384">> -> 'sha384';
        <<"sha512">> -> 'sha512'
    end,
    CurveTup = curve_to_tup(Curve),
    EphKeyRec = {#'ECPoint'{point = EphKey}, CurveTup},
    PubKeyRec = {#'ECPoint'{point = PubKey}, CurveTup},
    SlotAtom = slot_to_sym(Slot),
    B0 = #ebox_box{
        version = Version,
        guid = none,
        slot = none,
        ephemeral_key = EphKeyRec,
        unlock_key = PubKeyRec,
        cipher = CipherAtom,
        kdf = KDFAtom,
        nonce = Nonce,
        iv = IV,
        ciphertext = Enc
    },
    B1 = case GuidSlotValid of
        1 -> B0#ebox_box{guid = Guid, slot = SlotAtom};
        0 -> B0
    end,
    {B1, Rest5}.

-spec n_decode(integer(), integer(),
        fun((integer(), binary()) -> {any(), binary()}), binary())
    -> {[any()], binary()}.
n_decode(V, N, Fun, Rest0) ->
    lists:foldl(fun (NN, {SoFar, Rest1}) ->
        {Rec0, Rest2} = Fun(V, Rest1),
        Rec1 = case Rec0 of
            P = #ebox_part{} -> P#ebox_part{id = NN};
            _ -> Rec0
        end,
        {[Rec1 | SoFar], Rest2}
    end, {[], Rest0}, lists:seq(1, N)).

decode_ephem_key(_V, <<CurveLen, Curve:CurveLen/binary,
                   PointLen, Point:PointLen/binary, Rest0/binary>>) ->
    CurveTup = curve_to_tup(Curve),
    PubKey = {#'ECPoint'{point = Point}, CurveTup},
    {PubKey, Rest0}.

decode_tpl_config(V, <<?EBOX_PRIMARY, N, M, Rest0/binary>>) ->
    {Parts, Rest1} = n_decode(V, M, fun decode_tpl_part/2, Rest0),
    N = M,
    {#ebox_tpl_primary_config{
        parts = Parts
    }, Rest1};
decode_tpl_config(V, <<?EBOX_RECOVERY, N, M, Rest0/binary>>) ->
    {Parts, Rest1} = n_decode(V, M, fun decode_tpl_part/2, Rest0),
    true = (N =< M),
    {#ebox_tpl_recovery_config{
        parts = Parts,
        required = N
    }, Rest1}.

decode_config(V, <<?EBOX_PRIMARY, N, M, Rest0/binary>>) ->
    {Nonce, Rest1} = if
        (V >= 3) ->
            <<0, RR1/binary>> = Rest0,
            {<<>>, RR1};
        true ->
            {<<>>, Rest0}
    end,
    {Parts, Rest2} = n_decode(V, M, fun decode_part/2, Rest1),
    N = M,
    {#ebox_config{
        template = #ebox_tpl_primary_config{
            parts = [Tpl || #ebox_part{template = Tpl} <- Parts]
        },
        parts = Parts,
        nonce = Nonce
    }, Rest2};
decode_config(V, <<?EBOX_RECOVERY, N, M, Rest0/binary>>) ->
    {Nonce, Rest1} = if
        (V >= 3) ->
            <<NoLen, No:NoLen/binary, RR1/binary>> = Rest0,
            {No, RR1};
        true ->
            {<<>>, Rest0}
    end,
    {Parts, Rest2} = n_decode(V, M, fun decode_part/2, Rest1),
    true = (N =< M),
    {#ebox_config{
        template = #ebox_tpl_recovery_config{
            parts = [Tpl || #ebox_part{template = Tpl} <- Parts],
            required = N
        },
        parts = Parts,
        nonce = Nonce
    }, Rest2}.

-define(EBOX_PART_END, 0).
-define(EBOX_PART_PUBKEY, 1).
-define(EBOX_PART_NAME, 2).
-define(EBOX_PART_CAK, 3).
-define(EBOX_PART_GUID, 4).
-define(EBOX_PART_BOX, 5).
-define(EBOX_PART_SLOT, 6).

decode_part(V, Rest0) ->
    {R, Rest1} = decode_part_tag(V,
        #ebox_part{template = #ebox_tpl_part{}}, Rest0),
    case R of
        #ebox_part{box = undefined} ->
            error(box_required);
        #ebox_part{template = #ebox_tpl_part{pubkey = undefined}} ->
            error(pubkey_required);
        #ebox_part{template = #ebox_tpl_part{guid = undefined}} ->
            error(guid_required);
        _ ->
            {R, Rest1}
    end.

decode_part_tag(_V, R0 = #ebox_part{}, <<?EBOX_PART_END, Rest/binary>>) ->
    {R0, Rest};
decode_part_tag(_V, R0 = #ebox_part{template = T0 = #ebox_tpl_part{extra = Extra0}},
                    <<1:1, Type:7, Len, Data:Len/binary, Rest/binary>>) ->
    T1 = T0#ebox_tpl_part{extra = [{Type, Data} | Extra0]},
    R1 = R0#ebox_part{template = T1},
    decode_part_tag(R1, Rest);
decode_part_tag(_V, R0 = #ebox_part{template = T0 = #ebox_tpl_part{}},
                    <<?EBOX_PART_NAME, Len, Name:Len/binary, Rest/binary>>) ->
    T1 = T0#ebox_tpl_part{name = Name},
    R1 = R0#ebox_part{template = T1},
    decode_part_tag(R1, Rest);
decode_part_tag(_V, R0 = #ebox_part{template = T0 = #ebox_tpl_part{}},
                    <<?EBOX_PART_GUID, Len, Guid:Len/binary, Rest/binary>>) ->
    T1 = T0#ebox_tpl_part{guid = Guid},
    R1 = R0#ebox_part{template = T1},
    decode_part_tag(R1, Rest);
decode_part_tag(_V, R0 = #ebox_part{template = T0 = #ebox_tpl_part{}},
                                    <<?EBOX_PART_SLOT, Slot, Rest/binary>>) ->
    SymSlot = slot_to_sym(Slot),
    T1 = T0#ebox_tpl_part{slot = SymSlot},
    R1 = R0#ebox_part{template = T1},
    decode_part_tag(R1, Rest);
decode_part_tag(_V, R0 = #ebox_part{template = T0 = #ebox_tpl_part{}},
                        <<?EBOX_PART_PUBKEY, CurveLen, Curve:CurveLen/binary,
                          PubKeyLen, PubKey:PubKeyLen/binary, Rest/binary>>) ->
    CurveTup = curve_to_tup(Curve),
    PubKeyRec = {#'ECPoint'{point = PubKey}, CurveTup},
    T1 = T0#ebox_tpl_part{pubkey = PubKeyRec},
    R1 = R0#ebox_part{template = T1},
    decode_part_tag(R1, Rest);
decode_part_tag(_V, R0 = #ebox_part{template = T0 = #ebox_tpl_part{}},
            <<?EBOX_PART_CAK, Len:32/big, Data:Len/binary, Rest/binary>>) ->
    Key = decode_sshkey(Data),
    T1 = T0#ebox_tpl_part{cak = Key},
    R1 = R0#ebox_part{template = T1},
    decode_part_tag(R1, Rest);
decode_part_tag(V, R0 = #ebox_part{},
                            <<?EBOX_PART_BOX, Rest0/binary>>) when (V < 2) ->
    Box = #ebox_box{} = decode(Rest0),

decode_tpl_part(Rest0) ->
    {R, Rest1} = decode_tpl_part_tag(#ebox_tpl_part{}, Rest0),
    case R of
        #ebox_tpl_part{pubkey = undefined} ->
            error(pubkey_required);
        #ebox_tpl_part{guid = undefined} ->
            error(guid_required);
        _ ->
            {R, Rest1}
    end.

decode_tpl_part_tag(R0 = #ebox_tpl_part{}, <<?EBOX_PART_END, Rest/binary>>) ->
    {R0, Rest};
decode_tpl_part_tag(R0 = #ebox_tpl_part{extra = Extra0},
                    <<1:1, Type:7, Len, Data:Len/binary, Rest/binary>>) ->
    R1 = R0#ebox_tpl_part{extra = [{Type, Data} | Extra0]},
    decode_tpl_part_tag(R1, Rest);
decode_tpl_part_tag(R0 = #ebox_tpl_part{},
                    <<?EBOX_PART_NAME, Len, Name:Len/binary, Rest/binary>>) ->
    R1 = R0#ebox_tpl_part{name = Name},
    decode_tpl_part_tag(R1, Rest);
decode_tpl_part_tag(R0 = #ebox_tpl_part{},
                    <<?EBOX_PART_GUID, Len, Guid:Len/binary, Rest/binary>>) ->
    R1 = R0#ebox_tpl_part{guid = Guid},
    decode_tpl_part_tag(R1, Rest);
decode_tpl_part_tag(R0 = #ebox_tpl_part{},
                                    <<?EBOX_PART_SLOT, Slot, Rest/binary>>) ->
    SymSlot = slot_to_sym(Slot),
    R1 = R0#ebox_tpl_part{slot = SymSlot},
    decode_tpl_part_tag(R1, Rest);
decode_tpl_part_tag(R0 = #ebox_tpl_part{},
                        <<?EBOX_PART_PUBKEY, CurveLen, Curve:CurveLen/binary,
                          PubKeyLen, PubKey:PubKeyLen/binary, Rest/binary>>) ->
    CurveTup = curve_to_tup(Curve),
    PubKeyRec = {#'ECPoint'{point = PubKey}, CurveTup},
    R1 = R0#ebox_tpl_part{pubkey = PubKeyRec},
    decode_tpl_part_tag(R1, Rest);
decode_tpl_part_tag(R0 = #ebox_tpl_part{},
            <<?EBOX_PART_CAK, Len:32/big, Data:Len/binary, Rest/binary>>) ->
    Key = decode_sshkey(Data),
    R1 = R0#ebox_tpl_part{cak = Key},
    decode_tpl_part_tag(R1, Rest).

decode_sshkey(<<NameLen:32/big, Name:NameLen/binary, Rest0/binary>>) ->
    decode_sshkey(Name, Rest0).

decode_sshkey(RSAType,
        <<ELen:32/big, E:ELen/big-unit:8, NLen:32/big, N:NLen/big-unit:8>>)
                                when (RSAType =:= <<"ssh-rsa">>) or
                                     (RSAType =:= <<"rsa-sha2-256">>) or
                                     (RSAType =:= <<"rsa-sha2-512">>) ->
    #'RSAPublicKey'{
        modulus = N,
        publicExponent = E
    };
decode_sshkey(ECType = <<"ecdsa-sha2-",_/binary>>,
                            <<CurveLen:32/big, Curve:CurveLen/binary,
                              PointLen:32/big, Point:PointLen/binary>>) ->
    CurveTup = curve_to_tup(Curve),
    {#'ECPoint'{point = Point}, CurveTup}.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

basic_decode_test() ->
    Data = base64:decode(<<
        "sMUCARBWKiDkLtDlgTxTDtf+db6SngphZXMxMjgtZ2NtBnNoYTUxMhDkzofO3HUQ7W2SzAGd9F8e"
        "CG5pc3RwMjU2IQIo2upIX755FeKUNSBlX8wE4ZJOWPJa6wGi7AU0TPDVyiEDrqzhRu7lkeGo5xSz"
        "/Ev8Sf2BBSjyeF9DkQzFsQMRgUQMGMOlgYXD5madK2U+AAAAIPeD+DFNjEqIrT7slHrjzroflqOW"
        "YCoEhto7ukjqIyNK">>),
    Rec = decode(Data),
    ?assertMatch(#ebox_box{version = 2, slot = piv_card_auth,
        cipher = 'aes128-gcm', kdf = sha512}, Rec).

tpl_decode_test() ->
    Data = base64:decode(<<
        "6wwBAQEBAQEBCG5pc3RwMjU2IQKAh5PqEWlFRP3IftPx41ttVM53AbUoIIUYfO7Ue"
        "3svQgQQ+FLhLiqaWLf9iKd+03O4RgIJZGF2byB5azVhAwAAAGgAAAATZWNkc2Etc2"
        "hhMi1uaXN0cDI1NgAAAAhuaXN0cDI1NgAAAEEEnCdFUQqwMQuUzjV/UurGOzWcz2o"
        "8Cz+AiF5kcpe1SutIEG8vpcfsYl3dVEw4Us5+ARpFoUrmPVFpgxuEwoeK/wA=">>),
    Rec = decode(Data),
    ?assertMatch(#ebox_tpl{version = 1, configs = Configs}, Rec),
    #ebox_tpl{configs = Configs} = Rec,
    ?assertMatch([#ebox_tpl_primary_config{parts = Parts}], Configs),
    [#ebox_tpl_primary_config{parts = Parts}] = Configs,
    ?assertMatch([#ebox_tpl_part{name = <<"davo yk5a">>}], Parts),
    [#ebox_tpl_part{pubkey = PubKey}] = Parts,
    [PemEntry] = public_key:pem_decode(<<
        "-----BEGIN PUBLIC KEY-----\n"
        "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEgIeT6hFpRUT9yH7T8eNbbVTOdwG1\n"
        "KCCFGHzu1Ht7L0LQVmNj965p7lWI1kty/HFX1x7p+SFrvw8lOD2Cv4VeqA==\n"
        "-----END PUBLIC KEY-----\n">>),
    {PubPoint, Curve} = PubKey,
    OtherPubKey = public_key:pem_entry_decode(PemEntry),
    {OtherPoint, OtherCurve} = OtherPubKey,
    ?assertMatch(PubPoint, ebox_crypto:compress(OtherPoint)),
    TempKey = public_key:generate_key(Curve),
    DHA = public_key:compute_key(element(1,OtherPubKey), TempKey),
    DHB = public_key:compute_key(PubPoint, TempKey),
    ?assertMatch(DHA, DHB).


-endif.
