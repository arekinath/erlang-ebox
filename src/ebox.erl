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

-export_type([
	tpl_config/0, tpl_config_type/0, pubkey/0, tpl_part/0, slot/0,
	guid/0, tpl/0, ebox/0, config/0, part/0, box/0, cipher/0, kdf/0
	]).

-export([]).

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").



-endif.
