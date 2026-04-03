/**
 * liboqs Elixir NIF Bindings
 *
 * Wraps OQS_SIG API for post-quantum digital signature algorithms:
 * - ML-DSA-44/65/87 (FIPS 204, Dilithium)
 * - SLH-DSA-SHA2-128f/128s/192f/192s/256f/256s (FIPS 205, SPHINCS+)
 *
 * NIF functions:
 *   keygen(algorithm_name) -> {:ok, %{public_key: bin, private_key: bin}} | {:error, reason}
 *   sign(algorithm_name, private_key, message) -> {:ok, signature} | {:error, reason}
 *   verify(algorithm_name, public_key, signature, message) -> :ok | {:error, :invalid_signature}
 */

#include <erl_nif.h>
#include <string.h>
#include <oqs/oqs.h>

/* Atoms */
static ERL_NIF_TERM atom_ok;
static ERL_NIF_TERM atom_error;
static ERL_NIF_TERM atom_public_key;
static ERL_NIF_TERM atom_private_key;
static ERL_NIF_TERM atom_invalid_signature;
static ERL_NIF_TERM atom_unsupported_algorithm;
static ERL_NIF_TERM atom_keygen_failed;
static ERL_NIF_TERM atom_sign_failed;
static ERL_NIF_TERM atom_bad_argument;

static ERL_NIF_TERM make_atom(ErlNifEnv *env, const char *name) {
    ERL_NIF_TERM atom;
    if (enif_make_existing_atom(env, name, &atom, ERL_NIF_LATIN1)) {
        return atom;
    }
    return enif_make_atom(env, name);
}

/* Map user-friendly names to liboqs internal names */
static const char *resolve_algo_name(const char *name) {
    /* ML-DSA names match directly */
    if (strncmp(name, "ML-DSA-", 7) == 0) return name;

    /* SLH-DSA: map friendly names to liboqs PURE names */
    if (strcmp(name, "SLH-DSA-SHA2-128f") == 0) return "SLH_DSA_PURE_SHA2_128F";
    if (strcmp(name, "SLH-DSA-SHA2-128s") == 0) return "SLH_DSA_PURE_SHA2_128S";
    if (strcmp(name, "SLH-DSA-SHA2-192f") == 0) return "SLH_DSA_PURE_SHA2_192F";
    if (strcmp(name, "SLH-DSA-SHA2-192s") == 0) return "SLH_DSA_PURE_SHA2_192S";
    if (strcmp(name, "SLH-DSA-SHA2-256f") == 0) return "SLH_DSA_PURE_SHA2_256F";
    if (strcmp(name, "SLH-DSA-SHA2-256s") == 0) return "SLH_DSA_PURE_SHA2_256S";

    /* Pass through anything else (allows direct liboqs names too) */
    return name;
}

/* Helper: extract algorithm name from Elixir binary */
static int get_algo_name(ErlNifEnv *env, ERL_NIF_TERM term, char *buf, size_t buf_size) {
    ErlNifBinary bin;
    if (!enif_inspect_binary(env, term, &bin)) {
        return 0;
    }
    if (bin.size >= buf_size) {
        return 0;
    }
    memcpy(buf, bin.data, bin.size);
    buf[bin.size] = '\0';
    return 1;
}

/**
 * keygen(algorithm_name) -> {:ok, %{public_key: binary, private_key: binary}} | {:error, reason}
 */
static ERL_NIF_TERM nif_keygen(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    char algo_name[128];

    if (argc != 1 || !get_algo_name(env, argv[0], algo_name, sizeof(algo_name))) {
        return enif_make_tuple2(env, atom_error, atom_bad_argument);
    }

    OQS_SIG *sig = OQS_SIG_new(resolve_algo_name(algo_name));
    if (sig == NULL) {
        return enif_make_tuple2(env, atom_error, atom_unsupported_algorithm);
    }

    /* Allocate key buffers */
    ERL_NIF_TERM pk_term, sk_term;
    unsigned char *pk_buf = enif_make_new_binary(env, sig->length_public_key, &pk_term);
    unsigned char *sk_buf = enif_make_new_binary(env, sig->length_secret_key, &sk_term);

    if (pk_buf == NULL || sk_buf == NULL) {
        OQS_SIG_free(sig);
        return enif_make_tuple2(env, atom_error, atom_keygen_failed);
    }

    /* Generate keypair */
    OQS_STATUS rc = OQS_SIG_keypair(sig, pk_buf, sk_buf);
    OQS_SIG_free(sig);

    if (rc != OQS_SUCCESS) {
        return enif_make_tuple2(env, atom_error, atom_keygen_failed);
    }

    /* Build result map: %{public_key: pk, private_key: sk} */
    ERL_NIF_TERM keys[2] = {atom_public_key, atom_private_key};
    ERL_NIF_TERM values[2] = {pk_term, sk_term};
    ERL_NIF_TERM result_map;
    enif_make_map_from_arrays(env, keys, values, 2, &result_map);

    return enif_make_tuple2(env, atom_ok, result_map);
}

/**
 * sign(algorithm_name, private_key, message) -> {:ok, signature} | {:error, reason}
 */
static ERL_NIF_TERM nif_sign(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    char algo_name[128];
    ErlNifBinary sk_bin, msg_bin;

    if (argc != 3 ||
        !get_algo_name(env, argv[0], algo_name, sizeof(algo_name)) ||
        !enif_inspect_binary(env, argv[1], &sk_bin) ||
        !enif_inspect_binary(env, argv[2], &msg_bin)) {
        return enif_make_tuple2(env, atom_error, atom_bad_argument);
    }

    OQS_SIG *sig = OQS_SIG_new(resolve_algo_name(algo_name));
    if (sig == NULL) {
        return enif_make_tuple2(env, atom_error, atom_unsupported_algorithm);
    }

    /* Validate private key size */
    if (sk_bin.size != sig->length_secret_key) {
        OQS_SIG_free(sig);
        return enif_make_tuple2(env, atom_error, atom_bad_argument);
    }

    /* Allocate signature buffer */
    ERL_NIF_TERM sig_term;
    unsigned char *sig_buf = enif_make_new_binary(env, sig->length_signature, &sig_term);
    size_t sig_len = 0;

    if (sig_buf == NULL) {
        OQS_SIG_free(sig);
        return enif_make_tuple2(env, atom_error, atom_sign_failed);
    }

    /* Sign */
    OQS_STATUS rc = OQS_SIG_sign(sig, sig_buf, &sig_len, msg_bin.data, msg_bin.size, sk_bin.data);
    OQS_SIG_free(sig);

    if (rc != OQS_SUCCESS) {
        return enif_make_tuple2(env, atom_error, atom_sign_failed);
    }

    /* If actual signature is shorter than max, create a properly-sized binary */
    if (sig_len < sig->length_signature) {
        ERL_NIF_TERM trimmed;
        unsigned char *trimmed_buf = enif_make_new_binary(env, sig_len, &trimmed);
        memcpy(trimmed_buf, sig_buf, sig_len);
        return enif_make_tuple2(env, atom_ok, trimmed);
    }

    return enif_make_tuple2(env, atom_ok, sig_term);
}

/**
 * verify(algorithm_name, public_key, signature, message) -> :ok | {:error, :invalid_signature}
 */
static ERL_NIF_TERM nif_verify(ErlNifEnv *env, int argc, const ERL_NIF_TERM argv[]) {
    char algo_name[128];
    ErlNifBinary pk_bin, sig_bin, msg_bin;

    if (argc != 4 ||
        !get_algo_name(env, argv[0], algo_name, sizeof(algo_name)) ||
        !enif_inspect_binary(env, argv[1], &pk_bin) ||
        !enif_inspect_binary(env, argv[2], &sig_bin) ||
        !enif_inspect_binary(env, argv[3], &msg_bin)) {
        return enif_make_tuple2(env, atom_error, atom_bad_argument);
    }

    OQS_SIG *sig = OQS_SIG_new(resolve_algo_name(algo_name));
    if (sig == NULL) {
        return enif_make_tuple2(env, atom_error, atom_unsupported_algorithm);
    }

    /* Validate public key size */
    if (pk_bin.size != sig->length_public_key) {
        OQS_SIG_free(sig);
        return enif_make_tuple2(env, atom_error, atom_bad_argument);
    }

    /* Verify */
    OQS_STATUS rc = OQS_SIG_verify(sig, msg_bin.data, msg_bin.size, sig_bin.data, sig_bin.size, pk_bin.data);
    OQS_SIG_free(sig);

    if (rc == OQS_SUCCESS) {
        return atom_ok;
    }

    return enif_make_tuple2(env, atom_error, atom_invalid_signature);
}

/* NIF initialization */
static int on_load(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info) {
    (void)priv_data;
    (void)load_info;

    atom_ok = make_atom(env, "ok");
    atom_error = make_atom(env, "error");
    atom_public_key = make_atom(env, "public_key");
    atom_private_key = make_atom(env, "private_key");
    atom_invalid_signature = make_atom(env, "invalid_signature");
    atom_unsupported_algorithm = make_atom(env, "unsupported_algorithm");
    atom_keygen_failed = make_atom(env, "keygen_failed");
    atom_sign_failed = make_atom(env, "sign_failed");
    atom_bad_argument = make_atom(env, "bad_argument");

    return 0;
}

/* NIF function table */
static ErlNifFunc nif_funcs[] = {
    {"keygen",  1, nif_keygen,  0},
    {"sign",    3, nif_sign,    0},
    {"verify",  4, nif_verify,  0}
};

ERL_NIF_INIT(Elixir.PkiOqsNif, nif_funcs, on_load, NULL, NULL, NULL)
