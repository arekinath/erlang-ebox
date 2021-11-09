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

-record(ebox_tpl, {
	version :: integer(),
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
	name :: binary(),
	pubkey :: ebox:pubkey(),
	cak :: ebox:pubkey(),
	slot :: ebox:slot(),
	guid :: ebox:guid()
	}).

-record(ebox, {
	version :: integer(),
	template :: ebox:tpl(),
	configs :: [ebox:config()],
	ephemeral_keys :: [ebox:pubkey()],
	recovery_box :: ebox:recovery_box()
	}).

-record(ebox_config, {
	template :: ebox:tpl_config(),
	parts :: [ebox:part()],
	nonce :: binary()
	}).

-record(ebox_part, {
	template :: ebox:tpl_part(),
	id :: integer(),
	box :: ebox:box()
	}).

-record(ebox_box, {
	version :: integer(),
	guid :: none | ebox:guid(),
	slot :: ebox:slot(),
	ephemeral_key :: ebox:pubkey(),
	unlock_key :: ebox:pubkey(),
	cipher :: ebox:cipher(),
	kdf :: ebox:kdf(),
	nonce :: binary(),
	iv :: binary(),
	ciphertext :: binary()
	}).
