/*
%%
%% EC compression support for ebox
%%
%% Copyright 2022 Alex Wilson <alex@uq.edu.au>, The University of Queensland
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
*/

#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>

#include <erl_nif.h>
#include <openssl/obj_mac.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

static ERL_NIF_TERM
compress_common(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[],
    point_conversion_form_t form)
{
	ErlNifBinary in, out;
	EC_POINT *pt;
	EC_GROUP *grp;
	int nid;
	int rc;
	char atom[32];
	size_t len;

	if (argc != 2)
		return (enif_make_badarg(env));

	if (!enif_get_atom(env, argv[0], atom, sizeof (atom), ERL_NIF_LATIN1))
		return (enif_make_badarg(env));

	if (!enif_inspect_iolist_as_binary(env, argv[1], &in))
		return (enif_make_badarg(env));

	if (strcmp(atom, "secp256r1") == 0)
		nid = NID_X9_62_prime256v1;
	else if (strcmp(atom, "secp384r1") == 0)
		nid = NID_secp384r1;
	else if (strcmp(atom, "secp521r1") == 0)
		nid = NID_secp521r1;
	else
		return (enif_make_badarg(env));
	grp = EC_GROUP_new_by_curve_name(nid);
	if (grp == NULL) {
		return (enif_raise_exception(env,
		    enif_make_tuple2(env, enif_make_atom(env, "bad_curve"),
		    argv[0])));
	}

	pt = EC_POINT_new(grp);
	rc = EC_POINT_oct2point(grp, pt, in.data, in.size, NULL);
	if (!rc) {
		EC_POINT_free(pt);
		EC_GROUP_free(grp);
		return (enif_raise_exception(env,
		    enif_make_atom(env, "oct2point")));
	}

	len = EC_POINT_point2oct(grp, pt, form, NULL,
	    0, NULL);
	enif_alloc_binary(len, &out);

	EC_POINT_point2oct(grp, pt, form, out.data,
	    out.size, NULL);

	EC_POINT_free(pt);
	EC_GROUP_free(grp);

	return (enif_make_binary(env, &out));
}

static ERL_NIF_TERM
compress(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	return (compress_common(env, argc, argv,
	    POINT_CONVERSION_COMPRESSED));
}

static ERL_NIF_TERM
decompress(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[])
{
	return (compress_common(env, argc, argv,
	    POINT_CONVERSION_UNCOMPRESSED));
}

static int
nif_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM info)
{
	return (0);
}

static void
nif_unload(ErlNifEnv *env, void *priv_data)
{
}

static ErlNifFunc nif_funcs[] = {
	{ "compress",	2, compress },
	{ "decompress",	2, decompress }
};

ERL_NIF_INIT(ec_conv_nif, nif_funcs, nif_load, NULL, NULL,
    nif_unload);
