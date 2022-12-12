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

-type part_id() :: integer().

-type recovery_box() :: #ebox_recovery_box{}.

-export_type([
    tpl_config/0, pubkey/0, tpl_part/0, slot/0,
    guid/0, tpl/0, ebox/0, config/0, part/0, box/0, cipher/0, kdf/0,
    recovery_box/0, part_id/0
    ]).

-export([
    decode/1,
    decrypt_box/2,
    decrypt/3,
    encode/1,
    encrypt_box/1,
    decode_challenge/1,
    response_box/2
    ]).

-define(EBOX_TEMPLATE, 16#01).
-define(EBOX_KEY, 16#02).
-define(EBOX_STREAM, 16#03).

-define(EBOX_PRIMARY, 16#01).
-define(EBOX_RECOVERY, 16#02).

slot_to_sym(0) -> none;
slot_to_sym(16#9a) -> piv_auth;
slot_to_sym(16#9c) -> piv_sign;
slot_to_sym(16#9e) -> piv_card_auth;
slot_to_sym(16#9d) -> piv_key_mgmt;
slot_to_sym(Slot) when is_integer(Slot) -> Slot.

sym_to_slot(none) -> 0;
sym_to_slot(piv_auth) -> 16#9a;
sym_to_slot(piv_sign) -> 16#9c;
sym_to_slot(piv_card_auth) -> 16#9e;
sym_to_slot(piv_key_mgmt) -> 16#9d;
sym_to_slot(Slot) when is_integer(Slot) -> Slot.

curve_to_tup(<<"nistp256">>) -> {namedCurve, secp256r1};
curve_to_tup(<<"nistp384">>) -> {namedCurve, secp384r1};
curve_to_tup(<<"nistp521">>) -> {namedCurve, secp521r1}.

tup_to_curve({namedCurve, secp256r1}) -> <<"nistp256">>;
tup_to_curve({namedCurve, ?'secp256r1'}) -> <<"nistp256">>;
tup_to_curve({namedCurve, secp384r1}) -> <<"nistp384">>;
tup_to_curve({namedCurve, ?'secp384r1'}) -> <<"nistp384">>;
tup_to_curve({namedCurve, secp521r1}) -> <<"nistp521">>;
tup_to_curve({namedCurve, ?'secp521r1'}) -> <<"nistp521">>.

kdf_to_atom(<<"sha256">>) -> sha256;
kdf_to_atom(<<"sha384">>) -> sha384;
kdf_to_atom(<<"sha512">>) -> sha512.

cipher_to_atom(<<"chacha20-poly1305">>) -> 'chacha20-poly1305';
cipher_to_atom(<<"aes128-gcm">>) -> 'aes128-gcm';
cipher_to_atom(<<"aes256-gcm">>) -> 'aes256-gcm'.

atom_to_kdf(sha256) -> <<"sha256">>;
atom_to_kdf(sha384) -> <<"sha384">>;
atom_to_kdf(sha512) -> <<"sha512">>.

atom_to_cipher('chacha20-poly1305') -> <<"chacha20-poly1305">>;
atom_to_cipher('aes128-gcm') -> <<"aes128-gcm">>;
atom_to_cipher('aes256-gcm') -> <<"aes256-gcm">>.

encode(#ebox_box{version = Version, guid = Guid, slot = Slot,
                 ephemeral_key = {#'ECPoint'{point = EphemPt}, EphemCurve},
                 unlock_key = {#'ECPoint'{point = UnlockPt}, UnlockCurve},
                 cipher = CipherAtom, kdf = KDFAtom, nonce = Nonce,
                 iv = IV, ciphertext = Enc}) ->
    VerNum = case Version of
        latest -> 2;
        _ -> Version
    end,
    Cipher = atom_to_cipher(CipherAtom),
    KDF = atom_to_kdf(KDFAtom),
    SlotNum = sym_to_slot(Slot),
    Curve = tup_to_curve(EphemCurve),
    Curve = tup_to_curve(UnlockCurve),
    GuidBin = case Guid of
        none -> <<0:128>>;
        _ -> Guid
    end,
    GuidSlotValid = case {Guid, Slot} of
        {none, none} -> 0;
        _ -> 1
    end,
    <<16#B0, 16#C5, VerNum, GuidSlotValid,
      (byte_size(GuidBin)), GuidBin/binary, SlotNum,
      (byte_size(Cipher)), Cipher/binary, (byte_size(KDF)), KDF/binary,
      (byte_size(Nonce)), Nonce/binary, (byte_size(Curve)), Curve/binary,
      (byte_size(UnlockPt)), UnlockPt/binary,
      (byte_size(EphemPt)), EphemPt/binary,
      (byte_size(IV)), IV/binary,
      (byte_size(Enc)):32/big, Enc/binary>>.

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
    {Configs, <<>>} = n_decode(Version, NConfigs, Ephems, fun decode_config/3,
        Rest3),
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
decode(<<16#EB, 16#0C, _Version, ?EBOX_STREAM, _Rest0/binary>>) ->
    #ebox{}.

-spec decode_box(binary()) -> {box(), binary()}.
decode_box(<<16#B0, 16#C5, Version, Rest0/binary>>) ->
    <<GuidSlotValid, GuidLen, Guid:GuidLen/binary, Slot, Rest1/binary>> = Rest0,
    <<CipherLen, Cipher:CipherLen/binary, KDFLen, KDF:KDFLen/binary, Rest2/binary>> = Rest1,
    <<NonceLen, Nonce:NonceLen/binary, CurveLen, Curve:CurveLen/binary, Rest3/binary>> = Rest2,
    <<PubKeyLen, PubKey:PubKeyLen/binary, EphKeyLen, EphKey:EphKeyLen/binary, Rest4/binary>> = Rest3,
    <<IVLen, IV:IVLen/binary, EncLen:32/big, Enc:EncLen/binary, Rest5/binary>> = Rest4,
    CipherAtom = cipher_to_atom(Cipher),
    KDFAtom = kdf_to_atom(KDF),
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

kdf(DH, #ebox_box{kdf = KDF, nonce = Nonce, cipher = Cipher}) ->
    H0 = crypto:hash_init(KDF),
    H1 = crypto:hash_update(H0, DH),
    H2 = crypto:hash_update(H1, Nonce),
    SharedSecret = crypto:hash_final(H2),
    #{key_len := KeyLen} = ebox_crypto:cipher_info(Cipher),
    binary:part(SharedSecret, {0, KeyLen}).

unpad(Padded) ->
    <<PadN>> = binary:part(Padded, {byte_size(Padded) - 1, 1}),
    Plaintext = binary:part(Padded, {0, byte_size(Padded) - PadN}),
    Pad = binary:part(Padded, {byte_size(Padded) - PadN, PadN}),
    ExpectPad = binary:copy(<<PadN>>, PadN),
    case Pad of
        ExpectPad ->
            {ok, Plaintext};
        _ ->
            {error, bad_padding}
    end.

pad(Data, BlockSz) ->
    PadN = BlockSz - (byte_size(Data) rem BlockSz),
    Pad = binary:copy(<<PadN>>, PadN),
    <<Data/binary, Pad/binary>>.

-spec encrypt_box(box()) -> box().
encrypt_box(B0 = #ebox_box{ciphertext = undefined, unlock_key = UnlockKey}) ->
    #ebox_box{cipher = Cipher, plaintext = Plain} = B0,
    #{block_size := BlockSz, iv_len := IVLen} = ebox_crypto:cipher_info(Cipher),
    {UnlockPt, UnlockCurve} = UnlockKey,
    EphemPriv = public_key:generate_key(UnlockCurve),
    #'ECPrivateKey'{publicKey = EphemPt} = EphemPriv,
    Nonce = crypto:strong_rand_bytes(16),
    IV = crypto:strong_rand_bytes(IVLen),
    EphemPoint = ebox_crypto:compress(#'ECPoint'{point = EphemPt}),

    B1 = B0#ebox_box{ephemeral_key = {EphemPoint, UnlockCurve},
                     nonce = Nonce,
                     iv = IV},

    Padded = pad(Plain, BlockSz),
    DH = public_key:compute_key(UnlockPt, EphemPriv),
    Key = kdf(DH, B1),

    Enc = ebox_crypto:one_time(Cipher, Key, Padded, #{encrypt => true,
        iv => IV}),
    B1#ebox_box{ciphertext = Enc}.

-spec decrypt_box(box(), ebox_key:key()) -> {ok, box()} | {error, term()}.
decrypt_box(B0 = #ebox_box{plaintext = undefined}, EboxKey) ->
    #ebox_box{unlock_key = {UnlockPub, UnlockCurveT},
              ephemeral_key = EphemKey,
              cipher = Cipher} = B0,
    {KeyMod, KeyData} = EboxKey,
    {ok, {OurPub, OurCurveT}} = KeyMod:get_public(KeyData),
    UnlockCurve = tup_to_curve(UnlockCurveT),
    OurCurve = tup_to_curve(OurCurveT),
    OurPoint = ebox_crypto:compress(OurPub),
    UnlockPoint = ebox_crypto:compress(UnlockPub),
    case {UnlockCurve, UnlockPoint} of
        {OurCurve, OurPoint} ->
            case KeyMod:compute_key(EphemKey, KeyData) of
                {ok, DH} ->
                    #ebox_box{iv = IV, ciphertext = Ciphertext} = B0,
                    Key = kdf(DH, B0),
                    R = (catch ebox_crypto:one_time(Cipher, Key,
                        Ciphertext, #{encrypt => false, iv => IV})),
                    case R of
                        {'EXIT', Why} ->
                            {error, Why};
                        Padded ->
                            case unpad(Padded) of
                                {ok, Plaintext} ->
                                    {ok, B0#ebox_box{plaintext = Plaintext}};
                                Err ->
                                    Err
                            end
                    end;
                Err ->
                    Err
            end;
        {OurCurve, _} ->
            {error, pubkey_mismatch};
        _ ->
            {error, curve_mismatch}
    end.

-type part_map() :: #{part_id() => binary()}.

decode_recov_data(<<16#01, Len, Token:Len/binary, Rest/binary>>) ->
    maps:merge(#{token => Token}, decode_recov_data(Rest));
decode_recov_data(<<16#02, Len, Key:Len/binary, Rest/binary>>) ->
    maps:merge(#{key => Key}, decode_recov_data(Rest));
decode_recov_data(<<>>) -> #{}.

-spec decrypt(box(), config(), part_map()) -> {ok, ebox()} | {error, term()}.
decrypt(Ebox0, #ebox_config{template = #ebox_tpl_primary_config{}}, PartMap) ->
    {_PartId, Key, _} = maps:next(maps:iterator(PartMap)),
    {ok, Ebox0#ebox{key = Key}};
decrypt(Ebox0, C = #ebox_config{template = T = #ebox_tpl_recovery_config{}}, PartMap) ->
    #ebox_tpl_recovery_config{required = N, parts = P} = T,
    #ebox_config{nonce = Nonce} = C,
    M = length(P),
    Given = maps:size(PartMap),
    if
        (Given >= N) ->
            ConfigKey = sss_nif:combine_keyshares(maps:values(PartMap), M),
            RecovKey = crypto:exor(ConfigKey, Nonce),
            #ebox{recovery_box = RB0} = Ebox0,
            #ebox_recovery_box{cipher = Cipher, iv = IV,
                               ciphertext = Enc} = RB0,
            R = (catch ebox_crypto:one_time(Cipher, RecovKey, Enc,
                #{encrypt => false, iv => IV})),
            case R of
                {'EXIT', Why} ->
                    {error, Why};
                Padded ->
                    case unpad(Padded) of
                        {ok, Plain} ->
                            RD = decode_recov_data(Plain),
                            #{key := Key} = RD,
                            Token = maps:get(token, RD, undefined),
                            RB1 = RB0#ebox_recovery_box{plaintext = Plain},
                            Ebox1 = Ebox0#ebox{key = Key,
                                               recovery_box = RB1,
                                               recovery_token = Token},
                            {ok, Ebox1};
                        Err ->
                            Err
                    end
            end;
        true ->
            {error, insufficient_parts}
    end.

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

-spec n_decode(integer(), integer(), term(),
        fun((integer(), term(), binary()) -> {any(), binary()}), binary())
    -> {[any()], binary()}.
n_decode(V, N, Extra, Fun, Rest0) ->
    lists:foldl(fun (NN, {SoFar, Rest1}) ->
        {Rec0, Rest2} = Fun(V, Extra, Rest1),
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

decode_config(V, Ephems, <<?EBOX_PRIMARY, N, M, Rest0/binary>>) ->
    {Nonce, Rest1} = if
        (V >= 3) ->
            <<0, RR1/binary>> = Rest0,
            {<<>>, RR1};
        true ->
            {<<>>, Rest0}
    end,
    {Parts, Rest2} = n_decode(V, M, Ephems, fun decode_part/3, Rest1),
    N = M,
    {#ebox_config{
        template = #ebox_tpl_primary_config{
            parts = [Tpl || #ebox_part{template = Tpl} <- Parts]
        },
        parts = Parts,
        nonce = Nonce
    }, Rest2};
decode_config(V, Ephems, <<?EBOX_RECOVERY, N, M, Rest0/binary>>) ->
    {Nonce, Rest1} = if
        (V >= 3) ->
            <<NoLen, No:NoLen/binary, RR1/binary>> = Rest0,
            {No, RR1};
        true ->
            {<<>>, Rest0}
    end,
    {Parts, Rest2} = n_decode(V, M, Ephems, fun decode_part/3, Rest1),
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

decode_part(V, Ephems, Rest0) ->
    {R0, Rest1} = decode_part_tag(V,
        #ebox_part{template = #ebox_tpl_part{}}, Rest0),
    case R0 of
        #ebox_part{box = undefined} ->
            error(box_required);
        _ ->
            #ebox_part{box = B0, template = Tpl0} = R0,
            #ebox_box{unlock_key = {UnlockPoint, UnlockCurve}} = B0,
            [EphemPt] = [XPoint || {XPoint, XCurve} <- Ephems,
                                 XCurve =:= UnlockCurve],
            #ebox_tpl_part{guid = Guid, slot = Slot} = Tpl0,
            Tpl1 = Tpl0#ebox_tpl_part{pubkey = {UnlockPoint, UnlockCurve}},
            B1 = B0#ebox_box{guid = Guid, slot = Slot,
                             ephemeral_key = {EphemPt, UnlockCurve}},
            R1 = R0#ebox_part{box = B1, template = Tpl1},
            {R1, Rest1}
    end.

decode_part_tag(_V, R0 = #ebox_part{}, <<?EBOX_PART_END, Rest/binary>>) ->
    {R0, Rest};
decode_part_tag(V, R0 = #ebox_part{template = T0 = #ebox_tpl_part{extra = Extra0}},
                    <<1:1, Type:7, Len, Data:Len/binary, Rest/binary>>) ->
    T1 = T0#ebox_tpl_part{extra = [{Type, Data} | Extra0]},
    R1 = R0#ebox_part{template = T1},
    decode_part_tag(V, R1, Rest);
decode_part_tag(V, R0 = #ebox_part{template = T0 = #ebox_tpl_part{}},
                    <<?EBOX_PART_NAME, Len, Name:Len/binary, Rest/binary>>) ->
    T1 = T0#ebox_tpl_part{name = Name},
    R1 = R0#ebox_part{template = T1},
    decode_part_tag(V, R1, Rest);
decode_part_tag(V, R0 = #ebox_part{template = T0 = #ebox_tpl_part{}},
                    <<?EBOX_PART_GUID, Len, Guid:Len/binary, Rest/binary>>) ->
    T1 = T0#ebox_tpl_part{guid = Guid},
    R1 = R0#ebox_part{template = T1},
    decode_part_tag(V, R1, Rest);
decode_part_tag(V, R0 = #ebox_part{template = T0 = #ebox_tpl_part{}},
                                    <<?EBOX_PART_SLOT, Slot, Rest/binary>>) ->
    SymSlot = slot_to_sym(Slot),
    T1 = T0#ebox_tpl_part{slot = SymSlot},
    R1 = R0#ebox_part{template = T1},
    decode_part_tag(V, R1, Rest);
decode_part_tag(V, R0 = #ebox_part{template = T0 = #ebox_tpl_part{}},
                        <<?EBOX_PART_PUBKEY, CurveLen, Curve:CurveLen/binary,
                          PubKeyLen, PubKey:PubKeyLen/binary, Rest/binary>>) ->
    CurveTup = curve_to_tup(Curve),
    PubKeyRec = {#'ECPoint'{point = PubKey}, CurveTup},
    T1 = T0#ebox_tpl_part{pubkey = PubKeyRec},
    R1 = R0#ebox_part{template = T1},
    decode_part_tag(V, R1, Rest);
decode_part_tag(V, R0 = #ebox_part{template = T0 = #ebox_tpl_part{}},
            <<?EBOX_PART_CAK, Len:32/big, Data:Len/binary, Rest/binary>>) ->
    Key = decode_sshkey(Data),
    T1 = T0#ebox_tpl_part{cak = Key},
    R1 = R0#ebox_part{template = T1},
    decode_part_tag(V, R1, Rest);
decode_part_tag(V, R0 = #ebox_part{},
                            <<?EBOX_PART_BOX, Rest0/binary>>) when (V < 2) ->
    {Box, Rest1} = decode_box(Rest0),
    R1 = R0#ebox_part{box = Box},
    decode_part_tag(V, R1, Rest1);
decode_part_tag(V, R0 = #ebox_part{},
                            <<?EBOX_PART_BOX, Rest0/binary>>) ->
    <<CipherLen, Cipher:CipherLen/binary, KDFLen, KDF:KDFLen/binary,
      NonceLen, Nonce:NonceLen/binary, CurveLen, Curve:CurveLen/binary,
      PubKeyLen, PubKey:PubKeyLen/binary, IVLen, IV:IVLen/binary,
      EncLen:32/big, Enc:EncLen/binary, Rest1/binary>> = Rest0,
    CurveTup = curve_to_tup(Curve),
    KDFAtom = kdf_to_atom(KDF),
    Box = #ebox_box{
        version = 2,
        guid = none,
        slot = none,
        unlock_key = {#'ECPoint'{point = PubKey}, CurveTup},
        cipher = cipher_to_atom(Cipher),
        kdf = KDFAtom,
        nonce = Nonce,
        iv = IV,
        ciphertext = Enc
    },
    R1 = R0#ebox_part{box = Box},
    decode_part_tag(V, R1, Rest1).

decode_tpl_part(V, Rest0) ->
    {R, Rest1} = decode_tpl_part_tag(V, #ebox_tpl_part{}, Rest0),
    case R of
        #ebox_tpl_part{pubkey = undefined} ->
            error(pubkey_required);
        #ebox_tpl_part{guid = undefined} ->
            error(guid_required);
        _ ->
            {R, Rest1}
    end.

decode_tpl_part_tag(_V, R0 = #ebox_tpl_part{}, <<?EBOX_PART_END, Rest/binary>>) ->
    {R0, Rest};
decode_tpl_part_tag(V, R0 = #ebox_tpl_part{extra = Extra0},
                    <<1:1, Type:7, Len, Data:Len/binary, Rest/binary>>) ->
    R1 = R0#ebox_tpl_part{extra = [{Type, Data} | Extra0]},
    decode_tpl_part_tag(V, R1, Rest);
decode_tpl_part_tag(V, R0 = #ebox_tpl_part{},
                    <<?EBOX_PART_NAME, Len, Name:Len/binary, Rest/binary>>) ->
    R1 = R0#ebox_tpl_part{name = Name},
    decode_tpl_part_tag(V, R1, Rest);
decode_tpl_part_tag(V, R0 = #ebox_tpl_part{},
                    <<?EBOX_PART_GUID, Len, Guid:Len/binary, Rest/binary>>) ->
    R1 = R0#ebox_tpl_part{guid = Guid},
    decode_tpl_part_tag(V, R1, Rest);
decode_tpl_part_tag(V, R0 = #ebox_tpl_part{},
                                    <<?EBOX_PART_SLOT, Slot, Rest/binary>>) ->
    SymSlot = slot_to_sym(Slot),
    R1 = R0#ebox_tpl_part{slot = SymSlot},
    decode_tpl_part_tag(V, R1, Rest);
decode_tpl_part_tag(V, R0 = #ebox_tpl_part{},
                        <<?EBOX_PART_PUBKEY, CurveLen, Curve:CurveLen/binary,
                          PubKeyLen, PubKey:PubKeyLen/binary, Rest/binary>>) ->
    CurveTup = curve_to_tup(Curve),
    PubKeyRec = {#'ECPoint'{point = PubKey}, CurveTup},
    R1 = R0#ebox_tpl_part{pubkey = PubKeyRec},
    decode_tpl_part_tag(V, R1, Rest);
decode_tpl_part_tag(V, R0 = #ebox_tpl_part{},
            <<?EBOX_PART_CAK, Len:32/big, Data:Len/binary, Rest/binary>>) ->
    Key = decode_sshkey(Data),
    R1 = R0#ebox_tpl_part{cak = Key},
    decode_tpl_part_tag(V, R1, Rest).

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
decode_sshkey(<<"ecdsa-sha2-",_/binary>>,
              <<CurveLen:32/big, Curve:CurveLen/binary,
                PointLen:32/big, Point:PointLen/binary>>) ->
    CurveTup = curve_to_tup(Curve),
    {#'ECPoint'{point = Point}, CurveTup}.

chal_word(N) ->
    List = {"abandoned","abilities","academic","accent",
    "adaptation","adventure","aerial","affair","against","aircraft","afternoon",
    "alcohol","aquarium","asbestos","auburn","availability","analyze",
    "appearance","athletics","awarded","awesome","babies","balanced",
    "battlefield","banana","beaches","because","bicycle","blocked","boards",
    "border","breakfast","bubble","burning","cabinet","ceiling","chains",
    "circle","citizen","claimed","cloud","collaboration","coaches","comparison",
    "cradle","cuisine","connected","cooking","creativity","cylinder",
    "dangerous","deadly","dedicated","demanding","deputy","diagram","diversity",
    "doctor","dragon","duplicate","dynamic","eagle","earthquake","eclipse",
    "economics","education","effect","either","elderly","empire","email",
    "enable","engines","equality","equipment","escape","eternal","eventually",
    "evaluate","exceptional","expanded","extraordinary","fabric","fantastic",
    "feature","fiction","flashing","focused","forest","fraction","frontier",
    "fusion","family","gambling","gender","giants","glance","golden","grade",
    "guarantee","habitat","headed","hidden","hobbies","humanity","hunter",
    "hybrid","iceland","identical","ignore","illegal","images","inappropriate",
    "intermediate","involvement","ireland","impact","inspiration","island",
    "itself","jacket","jewellery","journalism","judge","jumping","kansas",
    "keeping","keyword","kidney","knight","korean","kuwait","labeled",
    "language","launch","leadership","leaving","letters","liabilities",
    "lifestyle","logical","loaded","luggage","lyrics","maintenance",
    "manufacture","meaning","mineral","mobile","motivated","multimedia",
    "murder","mysterious","namely","nearby","niagara","nobody","nuclear",
    "narrative","navigator","oakland","obesity","occasion","offense",
    "oklahoma","oldest","omissions","ongoing","opened","oracle","others",
    "ourselves","overall","owners","oxford","pacific","peaceful","phantom",
    "picture","placed","pocket","practical","psychiatry","position","powder",
    "public","python","puzzle","qualification","quarter","rabbit","racing",
    "reached","rhythm","rational","recall","relocation","rotation","sacred",
    "scales","seafood","seeking","shades","segments","sequence","skating",
    "sleeping","smaller","snapshot","soccer","spaces","square","stability",
    "settlement","slideshow","syndicate","tables","teacher","template","things",
    "ticket","towards","traditional","tsunami","tucson","twelve","typical",
    "uganda","ukraine","ultimate","unable","upcoming","urgent","useful",
    "utilities","vacancies","vector","victim","vocabulary","vulnerability",
    "wagner","wealth","whatever","wichita","women","wrapped","wyoming",
    "yesterday","yearly","yields","yorkshire","yugoslavia","zambia","zealand",
    "zimbabwe","zone"},
    element(N + 1, List).

-define(CTAG_HOSTNAME,  1).
-define(CTAG_CTIME,     2).
-define(CTAG_DESC,      3).
-define(CTAG_WORDS,     4).

decode_challenge_tag(<<?CTAG_HOSTNAME, Len, Hostname:Len/binary, Rest/binary>>) ->
    maps:merge(#{hostname => Hostname}, decode_challenge_tag(Rest));
decode_challenge_tag(<<?CTAG_CTIME, Len, CTime:Len/big-unit:8, Rest/binary>>) ->
    maps:merge(#{created => CTime}, decode_challenge_tag(Rest));
decode_challenge_tag(<<?CTAG_DESC, Len, Desc:Len/binary, Rest/binary>>) ->
    maps:merge(#{description => Desc}, decode_challenge_tag(Rest));
decode_challenge_tag(<<?CTAG_WORDS, Len, WordsBin:Len/binary, Rest/binary>>) ->
    Words = [chal_word(N) || <<N>> <= WordsBin],
    maps:merge(#{words => Words}, decode_challenge_tag(Rest));
decode_challenge_tag(_) -> #{}.

chal_type_to_atom(1) -> recovery;
chal_type_to_atom(2) -> verify_audit.

decode_challenge(#ebox_box{unlock_key = {UnlockPt, Curve},
                           guid = Guid, slot = Slot,
                           cipher = Cipher, kdf = KDF,
                           plaintext = Data}) ->
    <<Version, Type, Id, DestPtLen, DestPt:DestPtLen/binary,
      EphemPtLen, EphemPt:EphemPtLen/binary,
      NonceLen, Nonce:NonceLen/binary,
      IVLen, IV:IVLen/binary,
      EncLen, Enc:EncLen/binary,
      TagsBin/binary>> = Data,
    Tags = decode_challenge_tag(TagsBin),
    DestKey = {#'ECPoint'{point = DestPt}, Curve},
    KeyBox = #ebox_box{
        guid = Guid, slot = Slot,
        ephemeral_key = {#'ECPoint'{point = EphemPt}, Curve},
        unlock_key = {UnlockPt, Curve},
        cipher = Cipher,
        kdf = KDF,
        nonce = Nonce,
        iv = IV,
        ciphertext = Enc
    },
    #ebox_challenge{
        version = Version,
        type = chal_type_to_atom(Type),
        id = Id,
        description = maps:get(description, Tags, undefined),
        hostname = maps:get(hostname, Tags, undefined),
        created = maps:get(created, Tags, undefined),
        words = maps:get(words, Tags, undefined),
        destkey = DestKey,
        keybox = KeyBox
    }.

-define(RTAG_ID,        1).
-define(RTAG_KEYPIECE,  2).

response_box(#ebox_challenge{id = Id, destkey = DestKey},
             #ebox_box{cipher = Cipher, kdf = KDF, plaintext = KeyPiece}) ->
    Data = <<?RTAG_ID, Id,
             ?RTAG_KEYPIECE, (byte_size(KeyPiece)), KeyPiece/binary>>,
    B0 = #ebox_box{
        cipher = Cipher,
        kdf = KDF,
        unlock_key = DestKey,
        plaintext = Data
    },
    encrypt_box(B0).

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

round_trip_test() ->
    Data = base64:decode(<<
        "sMUCARBWKiDkLtDlgTxTDtf+db6SngphZXMxMjgtZ2NtBnNoYTUxMhDkzofO3HUQ7W2SzAGd9F8e"
        "CG5pc3RwMjU2IQIo2upIX755FeKUNSBlX8wE4ZJOWPJa6wGi7AU0TPDVyiEDrqzhRu7lkeGo5xSz"
        "/Ev8Sf2BBSjyeF9DkQzFsQMRgUQMGMOlgYXD5madK2U+AAAAIPeD+DFNjEqIrT7slHrjzroflqOW"
        "YCoEhto7ukjqIyNK">>),
    Rec = decode(Data),
    Data2 = encode(Rec),
    ?assertMatch(Data, Data2).

tpl_decode_test() ->
    Data = base64:decode(<<
        "6wwBAQEBAQEBCG5pc3RwMjU2IQKAh5PqEWlFRP3IftPx41ttVM53AbUoIIUYfO7Ue"
        "3svQgQQ+FLhLiqaWLf9iKd+03O4RgIJZGF2byB5azVhAwAAAGgAAAATZWNkc2Etc2"
        "hhMi1uaXN0cDI1NgAAAAhuaXN0cDI1NgAAAEEEnCdFUQqwMQuUzjV/UurGOzWcz2o"
        "8Cz+AiF5kcpe1SutIEG8vpcfsYl3dVEw4Us5+ARpFoUrmPVFpgxuEwoeK/wA=">>),
    Rec = decode(Data),
    ?assertMatch(#ebox_tpl{version = 1, configs = _}, Rec),
    #ebox_tpl{configs = Configs} = Rec,
    ?assertMatch([#ebox_tpl_primary_config{parts = _}], Configs),
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
    {OtherPoint, _OtherCurve} = OtherPubKey,
    ?assertMatch(PubPoint, ebox_crypto:compress(OtherPoint)),
    TempKey = public_key:generate_key(Curve),
    DHA = public_key:compute_key(element(1,OtherPubKey), TempKey),
    DHB = public_key:compute_key(PubPoint, TempKey),
    ?assertMatch(DHA, DHB).

decrypt_box_test() ->
    Data = base64:decode(<<
        "sMUCAAAAEWNoYWNoYTIwLXBvbHkxMzA1BnNoYTUxMhC30h3EX8NYrs3tguTV30Q2CG5pc3RwMjU2"
        "IQNYCOQj68B+IHhz3m3foWRT+YmpXfwYjEfM5k6EHWfPsSEDwLstPYwYoa76ChPJeJZVlSrwkBMt"
        "CiNL6SHxJpHrCJUAAAAAGCNLlEgC4xlA1xkVRdtnUFD6i0R9dDZesw==">>),
    Rec0 = decode(Data),
    [PemEntry] = public_key:pem_decode(<<
        "-----BEGIN EC PRIVATE KEY-----\n"
        "MHcCAQEEIE9ftEd28CfsVJ3/7ltKgXrgpLzj5Ccb71xsywNSzsbloAoGCCqGSM49\n"
        "AwEHoUQDQgAEWAjkI+vAfiB4c95t36FkU/mJqV38GIxHzOZOhB1nz7G6yL8YO+hi\n"
        "XmgAkUOx8hG332rqMqK3sDaoNw0HpAZJ2w==\n"
        "-----END EC PRIVATE KEY-----\n">>),
    PrivKey = public_key:pem_entry_decode(PemEntry),
    Rec1 = decrypt_box(Rec0, {ebox_key_stdlib, PrivKey}),
    ?assertMatch({ok, #ebox_box{plaintext = <<"hello\n">>}}, Rec1).

decrypt_primary_test() ->
    Data = base64:decode(<<
        "6wwDAgphZXMyNTYtZ2NtDIRjpC65tyNuLbzZmiCZHo1LuTmxB6tsYblV88Yi3Z5Cm"
        "19Zw01DlvcRJAQ/gwEIbmlzdHAzODQxAhveeDL+bSA6WRa1iB4KukoN4fUT9ONfcC"
        "0qD2APkwuxpoBVLsP1wzVnOAZecVZ67AEBAQEABBAAAAAAAAAAAAAAAAAAAAAAAgd"
        "0ZXN0a2V5BRFjaGFjaGEyMC1wb2x5MTMwNQZzaGE1MTIQNILe0stAzXz45lOmZGnW"
        "kQhuaXN0cDM4NDEClexz9jRax2zcBJS9YzyHp2FsBcmlp5s2z/YnM+d/zX1qZN3Wf"
        "44aIryUH6YBoVKIAAAAABjPZOL/jK+luGp1k2IjJwPnIejZIsu9GCcA">>),
    Ebox0 = decode(Data),
    {ok, Pem} = file:read_file("test/testkey.pem"),
    [PemEntry] = public_key:pem_decode(Pem),
    PrivKey = public_key:pem_entry_decode(PemEntry),
    #ebox{configs = [Config]} = Ebox0,
    #ebox_config{parts = [Part]} = Config,
    #ebox_part{box = B0, id = Id} = Part,
    {ok, B1} = decrypt_box(B0, {ebox_key_stdlib, PrivKey}),
    #ebox_box{plaintext = Plain} = B1,
    PartPlains = #{Id => Plain},
    Out = decrypt(Ebox0, Config, PartPlains),
    ?assertMatch({ok, #ebox{key = <<"hello\n">>}}, Out).

decrypt_recovery_test() ->
    Data = base64:decode(<<
        "6wwDAgphZXMyNTYtZ2NtDCyR72zT1Pg2w3eV+yAv9E/9ffjVeR5UMlFZq6bGqNpZr"
        "jituUP4sMFwBxnpcQIIbmlzdHAyNTYhAiEQJcJBj2KvUZbQWRXZSIRk9R3MmcWQBE"
        "hHJOoZyYInCG5pc3RwMzg0MQN4pdhUC/Uv1eVjd7ulDOOSLvtukfANjXMs+uiKEIC"
        "NY90VIyvpUoMCAKA0NhLQT+oBAgICIPla0K2sheVg64HvJx6nK/30lB15ggwE5t8s"
        "rWC0BBrIBBAAAAAAAAAAAAAAAAAAAAAAAgd0ZXN0a2V5BRFjaGFjaGEyMC1wb2x5M"
        "TMwNQZzaGE1MTIQWt0UFx0TmHWLuKrVfQ0sRAhuaXN0cDM4NDEClexz9jRax2zcBJ"
        "S9YzyHp2FsBcmlp5s2z/YnM+d/zX1qZN3Wf44aIryUH6YBoVKIAAAAADiU1EjBC/z"
        "T6Se8prHaax+4LxwDGVX97Tw194F02s8HZOqNnlmnzaBtcMIUohiWLgSc+y7SVM6M"
        "sQAEEAAAAAAAAAAAAAAAAAAAAAACCHRlc3RrZXkyBRFjaGFjaGEyMC1wb2x5MTMwN"
        "QZzaGE1MTIQI43HxUlIjIPf16LGzpX5CAhuaXN0cDI1NiECaGxisO2yvD2cvrwwnb"
        "yr1Qx+LbwMBHGptudSF9xS0HMAAAAAODT3NghzOzXppteqp/kTyb2iUFHvsUyX4p4"
        "PEQpHTJ7ds1+I1hwAVwackIJTUfZQP3ojsg51sjpOAA==">>),
    Ebox0 = decode(Data),
    {ok, Pem0} = file:read_file("test/testkey2.pem"),
    [PemEntry0] = public_key:pem_decode(Pem0),
    PrivKey0 = public_key:pem_entry_decode(PemEntry0),
    {ok, Pem1} = file:read_file("test/testkey.pem"),
    [PemEntry1] = public_key:pem_decode(Pem1),
    PrivKey1 = public_key:pem_entry_decode(PemEntry1),
    ?assertMatch(#ebox{configs = [_]}, Ebox0),
    #ebox{configs = [Config]} = Ebox0,
    ?assertMatch(#ebox_config{parts = [_, _]}, Config),
    #ebox_config{parts = [Part0, Part1]} = Config,
    #ebox_part{box = B0, id = Id0} = Part0,
    #ebox_part{box = B1, id = Id1} = Part1,
    ?assertMatch(#ebox_part{template = #ebox_tpl_part{name = <<"testkey2">>}},
        Part0),
    ?assertMatch(#ebox_part{template = #ebox_tpl_part{name = <<"testkey">>}},
        Part1),
    {ok, #ebox_box{plaintext = Plain0}} = decrypt_box(B0, {ebox_key_stdlib, PrivKey0}),
    {ok, #ebox_box{plaintext = Plain1}} = decrypt_box(B1, {ebox_key_stdlib, PrivKey1}),
    PartMap0 = #{Id0 => Plain0},
    ?assertMatch({error, _}, decrypt(Ebox0, Config, PartMap0)),
    PartMap1 = PartMap0#{Id1 => Plain1},
    R = decrypt(Ebox0, Config, PartMap1),
    ?assertMatch({ok, #ebox{key = <<"world\n">>, recovery_token = undefined}}, R).

encrypt_box_test() ->
    {ok, Pem} = file:read_file("test/testkey.pem"),
    [PemEntry] = public_key:pem_decode(Pem),
    PrivKey = public_key:pem_entry_decode(PemEntry),
    #'ECPrivateKey'{parameters = C = {namedCurve, _},
                    publicKey = PubKeyPt} = PrivKey,
    PubKey = {#'ECPoint'{point=PubKeyPt}, C},
    B0 = #ebox_box{
        plaintext = <<"hello world">>,
        unlock_key = PubKey
    },
    B1 = encrypt_box(B0),
    Data = encode(B1),
    B2 = decode(Data),
    ?assertMatch({ok, #ebox_box{plaintext = <<"hello world">>}},
        decrypt_box(B2, {ebox_key_stdlib, PrivKey})).

decode_chal_test() ->
    Data = base64:decode(<<
        "sMUCARAAAAAAAAAAAAAAAAAAAAAAnRFjaGFjaGEyMC1wb2x5MTMwNQZzaGE1MTIQt"
        "oqfhAOuAff39W7gWYydCghuaXN0cDM4NDEClexz9jRax2zcBJS9YzyHp2FsBcmlp5"
        "s2z/YnM+d/zX1qZN3Wf44aIryUH6YBoVKIMQOv/ie26CgdbPLYpmTGs/cB2bSucwY"
        "5byE6Am/aSxEMkj5MyrFLOuEAKxswNdfLoCgAAAABGP/dE6iBWGOGyXo9mGQyUsSA"
        "iBZPcC4jw4dlBXle1eeNunRZdQaORFuZp1EiGykiZsYx4HV6e5YZWUXWDepIPSR5u"
        "aqfzS11gH7WY85LcomrevwgnZ4rRmZ13IlqvV2hBQHfjf/ZgZPKVZw957IZpX6Rpt"
        "3FTm9qUV49/z9l+ISNesPtjQNgfx6hTT9Ms1J086HKnprqIgbqyGvY8WGJeuNDCmb"
        "Njhoaj74w/uk5iq3unpkTlIOCQIdv8b6tAsDkBTjwKpMeEZfx6Vay06bG7u8gZSQT"
        "7tl0ole9TcL8n73JqcOyFH67g6Y9LLc0RA8Zs88QubnZB2NSQbs3cVk7PFOiLGAEx"
        "NSCiwIR0R0pYplDRIpPNRumZVU=">>),
    B0 = decode(Data),
    {ok, Pem} = file:read_file("test/testkey.pem"),
    [PemEntry] = public_key:pem_decode(Pem),
    PrivKey = public_key:pem_entry_decode(PemEntry),
    {ok, B1} = decrypt_box(B0, {ebox_key_stdlib, PrivKey}),
    Chal = decode_challenge(B1),
    ?assertMatch(#ebox_challenge{type = recovery,
                                 id = 1,
                                 hostname = <<"mabel">>}, Chal),
    #ebox_challenge{keybox = KB0} = Chal,
    {ok, KB1} = decrypt_box(KB0, {ebox_key_stdlib, PrivKey}),
    Resp = response_box(Chal, KB1),
    ?assertMatch(#ebox_box{}, Resp).

-endif.
