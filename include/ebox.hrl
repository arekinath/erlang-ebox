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

-include_lib("public_key/include/public_key.hrl").

-record(ebox_tpl, {
    version :: latest | integer(),
    configs :: [ebox:tpl_config()]
    }).

-record(ebox_tpl_primary_config, {
    parts :: [ebox:tpl_part()]
    }).

-record(ebox_tpl_recovery_config, {
    required :: integer(),
    parts :: [ebox:tpl_part()]
    }).

-record(ebox_tpl_part, {
    name :: undefined | binary(),
    pubkey :: ebox:pubkey(),
    cak :: undefined | ebox:pubkey(),
    slot :: undefined | ebox:slot(),
    guid :: ebox:guid(),
    extra = [] :: [{integer(), binary()}]
    }).

-record(ebox, {
    version :: latest | integer(),
    template :: ebox:tpl(),
    configs :: [ebox:config()],
    ephemeral_keys :: [ebox:pubkey()],
    recovery_box :: ebox:recovery_box(),
    key :: undefined | binary(),
    recovery_token :: undefined | binary()
    }).

-record(ebox_config, {
    template :: ebox:tpl_config(),
    parts :: [ebox:part()],
    nonce :: binary()
    }).

-record(ebox_part, {
    template :: ebox:tpl_part(),
    id :: ebox:part_id(),
    box :: ebox:box()
    }).

-record(ebox_box, {
    version = latest :: latest | integer(),
    guid = none :: none | ebox:guid(),
    slot = none :: none | ebox:slot(),
    ephemeral_key :: undefined | ebox:pubkey(),
    unlock_key :: ebox:pubkey(),
    cipher = 'chacha20-poly1305' :: ebox:cipher(),
    kdf = 'sha512' :: ebox:kdf(),
    nonce :: undefined | binary(),
    iv :: undefined | binary(),
    ciphertext :: undefined | binary(),
    plaintext :: undefined | binary()
    }).

-record(ebox_recovery_box, {
    cipher :: ebox:cipher(),
    iv :: binary(),
    ciphertext :: binary(),
    plaintext :: undefined | binary()
    }).

-record(ebox_challenge, {
    version :: latest | integer(),
    type :: recovery | verify_audit,
    id :: integer(),
    description :: undefined | string(),
    hostname :: undefined | string(),
    created :: undefined | integer(),
    words :: undefined | [string()],
    destkey :: ebox:pubkey(),
    keybox :: ebox:box()
    }).
