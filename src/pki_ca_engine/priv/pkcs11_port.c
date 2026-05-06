/*
 * pkcs11_port.c — Erlang Port binary wrapping PKCS#11 via dlopen.
 *
 * Protocol: 4-byte big-endian length prefix + JSON payload on stdin/stdout.
 *
 * Commands (JSON):
 *   {"cmd":"init","library":"/path/to.so","slot":0,"pin":"1234","id":N}
 *   {"cmd":"sign","label":"key-label","data":"base64...","mechanism":"CKM_ECDSA","id":N}
 *   {"cmd":"get_public_key","label":"key-label","id":N}
 *   {"cmd":"generate_key","label":"key-label","algorithm":"ECC-P256|RSA-2048|RSA-4096","id":N}
 *   {"cmd":"ping","id":N}
 *   {"cmd":"shutdown"}
 *
 * The "id" field is echoed back in every response for request correlation.
 * Omitting "id" from the command is allowed; the response will also omit it.
 *
 * Responses (JSON):
 *   {"ok":true,...,"id":N}
 *   {"error":"message","id":N}
 *
 * generate_key response fields:
 *   ECC: {"ok":true,"key_type":"ec","public_key":"<b64>","key_id":"<16hex>","id":N}
 *   RSA: {"ok":true,"key_type":"rsa","modulus":"<b64>","public_exponent":"<b64>","key_id":"<16hex>","id":N}
 *   key_id is the hex of the random CKA_ID set on both key objects; private key is
 *   CKA_EXTRACTABLE=FALSE and never leaves the token.
 *
 * PQC mechanism mapping:
 *   CKM_ECDSA          = 0x00001041  (ECDSA / EC keys)
 *   CKM_RSA_PKCS       = 0x00000001  (RSA PKCS#1 v1.5)
 *   CKM_VENDOR_DEFINED = 0x80000000  (base for vendor-specific)
 *     KAZ-SIGN: CKM_VENDOR_DEFINED + 0x00010001
 *     ML-DSA:   CKM_VENDOR_DEFINED + 0x00010002  (NIST PQC, vendor mapping)
 *
 * Crash safety: this process is managed by Pkcs11Port GenServer.
 * If it crashes, the GenServer restarts it with exponential backoff.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include "cJSON.h"

/* explicit_bzero — defeat dead-store elimination on PIN buffers.
 * Available on Linux glibc >= 2.25 / musl and macOS >= 10.12.
 * Fall back to a volatile-indirected memset on toolchains that lack it
 * (e.g. macOS 26 SDK where the symbol exists in libSystem but has no
 * header prototype under -std=c11 -D_POSIX_C_SOURCE). */
#ifndef explicit_bzero
static void * (* const volatile __explicit_bzero_memset)(void *, int, size_t) = memset;
#define explicit_bzero(p, n) __explicit_bzero_memset((p), 0, (n))
#endif

/* PKCS#11 headers — we define the minimal subset we need */
#define CK_PTR *
#define CK_DEFINE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION(returnType, name) returnType name
#define CK_DECLARE_FUNCTION_POINTER(returnType, name) returnType (* name)
#define CK_CALLBACK_FUNCTION(returnType, name) returnType (* name)
#define NULL_PTR NULL

typedef unsigned long CK_ULONG;
typedef unsigned long CK_RV;
typedef unsigned long CK_SESSION_HANDLE;
typedef unsigned long CK_SLOT_ID;
typedef unsigned long CK_MECHANISM_TYPE;
typedef unsigned long CK_OBJECT_HANDLE;
typedef unsigned long CK_ATTRIBUTE_TYPE;
typedef unsigned long CK_FLAGS;
typedef unsigned char CK_BYTE;
typedef CK_BYTE CK_PTR CK_BYTE_PTR;
typedef void CK_PTR CK_VOID_PTR;
typedef CK_ULONG CK_PTR CK_ULONG_PTR;
typedef unsigned long CK_BBOOL;
typedef unsigned long CK_OBJECT_CLASS;

/* Minimal PKCS#11 constants */
#define CKR_OK                  0x00000000
#define CKF_SERIAL_SESSION      0x00000004
#define CKF_RW_SESSION          0x00000002
#define CKU_USER                1
#define CKA_CLASS               0x00000000
#define CKA_LABEL               0x00000003
#define CKA_ID                  0x00000102
#define CKA_VALUE               0x00000011
#define CKO_PRIVATE_KEY         0x00000003
#define CKO_PUBLIC_KEY          0x00000002
#define CKM_RSA_PKCS_KEY_PAIR_GEN  0x00000000UL
#define CKM_EC_KEY_PAIR_GEN        0x00001040UL
#define CKM_ECDSA               0x00001041UL
#define CKM_RSA_PKCS            0x00000001UL
#define CKM_VENDOR_DEFINED      0x80000000UL
#define CK_TRUE                 1
#define CK_FALSE                0
/* CKA_ attribute types */
#define CKA_TOKEN               0x00000001UL
#define CKA_PRIVATE_BOOL        0x00000002UL  /* boolean "private" attr, not CKO_PRIVATE_KEY */
#define CKA_SENSITIVE           0x00000103UL
#define CKA_ENCRYPT             0x00000104UL
#define CKA_SIGN                0x00000108UL
#define CKA_VERIFY              0x0000010AUL
#define CKA_EXTRACTABLE         0x00000162UL
#define CKA_MODULUS             0x00000120UL
#define CKA_MODULUS_BITS        0x00000121UL
#define CKA_PUBLIC_EXPONENT     0x00000122UL
#define CKA_EC_PARAMS           0x00000180UL  /* DER-encoded curve OID */
#define CKA_EC_POINT            0x00000181UL  /* DER-encoded EC public key point */

/* Vendor-specific PQC mechanism IDs */
#define CKM_KAZ_SIGN            (CKM_VENDOR_DEFINED + 0x00010001UL)
#define CKM_ML_DSA              (CKM_VENDOR_DEFINED + 0x00010002UL)

typedef struct {
    CK_ATTRIBUTE_TYPE type;
    CK_VOID_PTR pValue;
    CK_ULONG ulValueLen;
} CK_ATTRIBUTE;

typedef struct {
    CK_MECHANISM_TYPE mechanism;
    CK_VOID_PTR pParameter;
    CK_ULONG ulParameterLen;
} CK_MECHANISM;

/* Function list — we load these from the .so */
typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;
typedef CK_FUNCTION_LIST CK_PTR CK_FUNCTION_LIST_PTR;
typedef CK_FUNCTION_LIST_PTR CK_PTR CK_FUNCTION_LIST_PTR_PTR;

typedef CK_RV (*CK_C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR);

struct CK_FUNCTION_LIST {
    void *version; /* CK_VERSION — we skip it */
    CK_RV (*C_Initialize)(CK_VOID_PTR);
    CK_RV (*C_Finalize)(CK_VOID_PTR);
    void *C_GetInfo;
    CK_RV (*C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR);
    void *C_GetSlotList;
    void *C_GetSlotInfo;
    void *C_GetTokenInfo;
    void *C_GetMechanismList;
    void *C_GetMechanismInfo;
    void *C_InitToken;
    void *C_InitPIN;
    void *C_SetPIN;
    CK_RV (*C_OpenSession)(CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, void*, CK_SESSION_HANDLE*);
    CK_RV (*C_CloseSession)(CK_SESSION_HANDLE);
    void *C_CloseAllSessions;
    void *C_GetSessionInfo;
    void *C_GetOperationState;
    void *C_SetOperationState;
    CK_RV (*C_Login)(CK_SESSION_HANDLE, CK_ULONG, CK_BYTE_PTR, CK_ULONG);
    void *C_Logout;
    void *C_CreateObject;
    void *C_CopyObject;
    void *C_DestroyObject;
    void *C_GetObjectSize;
    CK_RV (*C_GetAttributeValue)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
    void *C_SetAttributeValue;
    CK_RV (*C_FindObjectsInit)(CK_SESSION_HANDLE, CK_ATTRIBUTE*, CK_ULONG);
    CK_RV (*C_FindObjects)(CK_SESSION_HANDLE, CK_OBJECT_HANDLE*, CK_ULONG, CK_ULONG*);
    CK_RV (*C_FindObjectsFinal)(CK_SESSION_HANDLE);
    void *C_EncryptInit;
    void *C_Encrypt;
    void *C_EncryptUpdate;
    void *C_EncryptFinal;
    void *C_DecryptInit;
    void *C_Decrypt;
    void *C_DecryptUpdate;
    void *C_DecryptFinal;
    void *C_DigestInit;
    void *C_Digest;
    void *C_DigestUpdate;
    void *C_DigestKey;
    void *C_DigestFinal;
    CK_RV (*C_SignInit)(CK_SESSION_HANDLE, CK_MECHANISM*, CK_OBJECT_HANDLE);
    CK_RV (*C_Sign)(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR, CK_ULONG*);
    /* slots 45-58: unused, kept as void* to preserve ABI offsets */
    void *C_SignUpdate;
    void *C_SignFinal;
    void *C_SignRecoverInit;
    void *C_SignRecover;
    void *C_VerifyInit;
    void *C_Verify;
    void *C_VerifyUpdate;
    void *C_VerifyFinal;
    void *C_VerifyRecoverInit;
    void *C_VerifyRecover;
    void *C_DigestEncryptUpdate;
    void *C_DecryptDigestUpdate;
    void *C_SignEncryptUpdate;
    void *C_DecryptVerifyUpdate;
    void *C_GenerateKey;
    CK_RV (*C_GenerateKeyPair)(CK_SESSION_HANDLE, CK_MECHANISM*,
                               CK_ATTRIBUTE*, CK_ULONG,
                               CK_ATTRIBUTE*, CK_ULONG,
                               CK_OBJECT_HANDLE*, CK_OBJECT_HANDLE*);
};

/* Base64 encode/decode — minimal inline implementation */
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *base64_encode(const unsigned char *data, size_t len, size_t *out_len) {
    size_t olen = 4 * ((len + 2) / 3);
    char *out = malloc(olen + 1);
    if (!out) return NULL;

    size_t i, j;
    for (i = 0, j = 0; i < len; ) {
        uint32_t a = i < len ? data[i++] : 0;
        uint32_t b = i < len ? data[i++] : 0;
        uint32_t c = i < len ? data[i++] : 0;
        uint32_t triple = (a << 16) | (b << 8) | c;
        out[j++] = b64_table[(triple >> 18) & 0x3F];
        out[j++] = b64_table[(triple >> 12) & 0x3F];
        out[j++] = (i > len + 1) ? '=' : b64_table[(triple >> 6) & 0x3F];
        out[j++] = (i > len) ? '=' : b64_table[triple & 0x3F];
    }
    out[j] = '\0';
    *out_len = j;
    return out;
}

static int b64_decode_char(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

static unsigned char *base64_decode(const char *data, size_t len, size_t *out_len) {
    if (len % 4 != 0) return NULL;
    size_t olen = len / 4 * 3;
    if (len > 0 && data[len-1] == '=') olen--;
    if (len > 1 && data[len-2] == '=') olen--;

    unsigned char *out = malloc(olen);
    if (!out) return NULL;

    size_t i, j;
    for (i = 0, j = 0; i < len; ) {
        int a = b64_decode_char(data[i++]);
        int b = b64_decode_char(data[i++]);
        int c = (data[i] == '=') ? 0 : b64_decode_char(data[i]); i++;
        int d = (data[i] == '=') ? 0 : b64_decode_char(data[i]); i++;
        uint32_t triple = ((uint32_t)a << 18) | ((uint32_t)b << 12) | ((uint32_t)c << 6) | (uint32_t)d;
        if (j < olen) out[j++] = (triple >> 16) & 0xFF;
        if (j < olen) out[j++] = (triple >> 8) & 0xFF;
        if (j < olen) out[j++] = triple & 0xFF;
    }
    *out_len = olen;
    return out;
}

/* DER-encoded curve OIDs for CKA_EC_PARAMS */
static const CK_BYTE ec_oid_p256[] = {
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07  /* 1.2.840.10045.3.1.7 */
};
static const CK_BYTE ec_oid_p384[] = {
    0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22                     /* 1.3.132.0.34 */
};
/* RSA public exponent: 65537 = 0x010001 */
static const CK_BYTE rsa_pub_exp[] = {0x01, 0x00, 0x01};

/* Fill buf with n random bytes from /dev/urandom. Returns 0 on success. */
static int read_random_bytes(CK_BYTE *buf, size_t n) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) return -1;
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r <= 0) { close(fd); return -1; }
        got += (size_t)r;
    }
    close(fd);
    return 0;
}

/* Global state */
static void *pkcs11_lib = NULL;
static CK_FUNCTION_LIST_PTR fn = NULL;
static CK_SESSION_HANDLE session = 0;
static int initialized = 0;

/* Read exactly n bytes from fd */
static int read_exact(int fd, unsigned char *buf, size_t n) {
    size_t got = 0;
    while (got < n) {
        ssize_t r = read(fd, buf + got, n - got);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

/* Write exactly n bytes to fd */
static int write_exact(int fd, const unsigned char *buf, size_t n) {
    size_t sent = 0;
    while (sent < n) {
        ssize_t w = write(fd, buf + sent, n - sent);
        if (w <= 0) return -1;
        sent += (size_t)w;
    }
    return 0;
}

/* Read a length-prefixed message from stdin */
static char *read_message(size_t *len) {
    unsigned char hdr[4];
    if (read_exact(STDIN_FILENO, hdr, 4) != 0) return NULL;
    uint32_t msg_len = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) |
                       ((uint32_t)hdr[2] << 8) | (uint32_t)hdr[3];
    if (msg_len > 10 * 1024 * 1024) return NULL; /* 10MB max */
    char *buf = malloc(msg_len + 1);
    if (!buf) return NULL;
    if (read_exact(STDIN_FILENO, (unsigned char *)buf, msg_len) != 0) { free(buf); return NULL; }
    buf[msg_len] = '\0';
    *len = msg_len;
    return buf;
}

/* Write a length-prefixed message to stdout */
static int write_message(const char *msg, size_t len) {
    unsigned char hdr[4];
    hdr[0] = (len >> 24) & 0xFF;
    hdr[1] = (len >> 16) & 0xFF;
    hdr[2] = (len >> 8) & 0xFF;
    hdr[3] = len & 0xFF;
    if (write_exact(STDOUT_FILENO, hdr, 4) != 0) return -1;
    if (write_exact(STDOUT_FILENO, (const unsigned char *)msg, len) != 0) return -1;
    return 0;
}

/* id >= 0 means the request had an id field; echo it back */
static void send_error_r(const char *msg, long id) {
    char buf[1024];
    int n;
    if (id >= 0)
        n = snprintf(buf, sizeof(buf), "{\"error\":\"%s\",\"id\":%ld}", msg, id);
    else
        n = snprintf(buf, sizeof(buf), "{\"error\":\"%s\"}", msg);
    write_message(buf, (size_t)n);
}

static void send_ok_r(const char *extra, long id) {
    size_t extra_len = extra ? strlen(extra) : 0;
    size_t buf_sz = extra_len + 64; /* headroom for ok/id boilerplate */
    char *buf = malloc(buf_sz);
    if (!buf) { send_error_r("alloc failed", id); return; }
    int n;
    if (id >= 0 && extra)
        n = snprintf(buf, buf_sz, "{\"ok\":true,%s,\"id\":%ld}", extra, id);
    else if (id >= 0)
        n = snprintf(buf, buf_sz, "{\"ok\":true,\"id\":%ld}", id);
    else if (extra)
        n = snprintf(buf, buf_sz, "{\"ok\":true,%s}", extra);
    else
        n = snprintf(buf, buf_sz, "{\"ok\":true}");
    write_message(buf, (size_t)n);
    free(buf);
}

/* find_key_by_label — unchanged from original */
static CK_RV find_key_by_label(const char *label, CK_OBJECT_CLASS obj_class, CK_OBJECT_HANDLE *handle) {
    CK_ATTRIBUTE tmpl[2];
    tmpl[0].type = CKA_CLASS;
    tmpl[0].pValue = &obj_class;
    tmpl[0].ulValueLen = sizeof(obj_class);
    tmpl[1].type = CKA_LABEL;
    tmpl[1].pValue = (void *)label;
    tmpl[1].ulValueLen = strlen(label);

    CK_RV rv = fn->C_FindObjectsInit(session, tmpl, 2);
    if (rv != CKR_OK) return rv;

    CK_ULONG count = 0;
    rv = fn->C_FindObjects(session, handle, 1, &count);
    fn->C_FindObjectsFinal(session);
    if (rv != CKR_OK) return rv;
    if (count == 0) return 0xFFFFFFFF; /* not found */
    return CKR_OK;
}

/* Returns 0 on success, -1 for unknown mechanism (fail-closed; no ECDSA default) */
static int parse_mechanism(const char *mech_str, CK_MECHANISM_TYPE *out) {
    if (strcmp(mech_str, "CKM_RSA_PKCS") == 0)       { *out = CKM_RSA_PKCS; return 0; }
    if (strcmp(mech_str, "CKM_ECDSA") == 0)            { *out = CKM_ECDSA; return 0; }
    if (strcmp(mech_str, "CKM_KAZ_SIGN") == 0)         { *out = CKM_KAZ_SIGN; return 0; }
    if (strcmp(mech_str, "CKM_ML_DSA") == 0)           { *out = CKM_ML_DSA; return 0; }
    if (strcmp(mech_str, "CKM_VENDOR_DEFINED") == 0)   { *out = CKM_VENDOR_DEFINED; return 0; }
    return -1;
}

static void handle_init(cJSON *root, long id) {
    cJSON *lib_item  = cJSON_GetObjectItemCaseSensitive(root, "library");
    cJSON *slot_item = cJSON_GetObjectItemCaseSensitive(root, "slot");
    cJSON *pin_item  = cJSON_GetObjectItemCaseSensitive(root, "pin");

    if (!cJSON_IsString(lib_item))  { send_error_r("missing library", id); return; }
    if (!cJSON_IsString(pin_item))  { send_error_r("missing pin", id); return; }
    if (!cJSON_IsNumber(slot_item) && !cJSON_IsString(slot_item)) {
        send_error_r("missing slot", id); return;
    }

    const char *library = lib_item->valuestring;
    CK_SLOT_ID slot = (CK_SLOT_ID)(cJSON_IsNumber(slot_item)
        ? (long)slot_item->valuedouble
        : atol(slot_item->valuestring));

    /* Copy PIN to a local buffer and zero the cJSON copy immediately */
    char pin[256];
    strncpy(pin, pin_item->valuestring, sizeof(pin) - 1);
    pin[sizeof(pin) - 1] = '\0';
    explicit_bzero(pin_item->valuestring, strlen(pin_item->valuestring));

    pkcs11_lib = dlopen(library, RTLD_NOW);
    if (!pkcs11_lib) {
        char err[1024];
        snprintf(err, sizeof(err), "dlopen failed: %s", dlerror());
        explicit_bzero(pin, sizeof(pin));
        send_error_r(err, id);
        return;
    }

    CK_C_GetFunctionList getFn = (CK_C_GetFunctionList)dlsym(pkcs11_lib, "C_GetFunctionList");
    if (!getFn) { explicit_bzero(pin, sizeof(pin)); send_error_r("C_GetFunctionList not found", id); return; }

    CK_RV rv = getFn(&fn);
    if (rv != CKR_OK) { explicit_bzero(pin, sizeof(pin)); send_error_r("C_GetFunctionList failed", id); return; }

    rv = fn->C_Initialize(NULL);
    if (rv != CKR_OK) { explicit_bzero(pin, sizeof(pin)); send_error_r("C_Initialize failed", id); return; }

    rv = fn->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    if (rv != CKR_OK) { explicit_bzero(pin, sizeof(pin)); send_error_r("C_OpenSession failed", id); return; }

    rv = fn->C_Login(session, CKU_USER, (CK_BYTE_PTR)pin, strlen(pin));
    explicit_bzero(pin, sizeof(pin));
    if (rv != CKR_OK) { send_error_r("C_Login failed", id); return; }

    initialized = 1;
    send_ok_r(NULL, id);
}

static void handle_sign(cJSON *root, long id) {
    if (!initialized) { send_error_r("not initialized", id); return; }

    cJSON *label_item = cJSON_GetObjectItemCaseSensitive(root, "label");
    cJSON *data_item  = cJSON_GetObjectItemCaseSensitive(root, "data");
    cJSON *mech_item  = cJSON_GetObjectItemCaseSensitive(root, "mechanism");

    if (!cJSON_IsString(label_item)) { send_error_r("missing label", id); return; }
    if (!cJSON_IsString(data_item))  { send_error_r("missing data", id); return; }

    const char *label    = label_item->valuestring;
    const char *data_b64 = data_item->valuestring;

    /* Default to ECDSA if mechanism field absent; fail-closed if field is present but unknown */
    CK_MECHANISM_TYPE mech_type = CKM_ECDSA;
    if (cJSON_IsString(mech_item)) {
        if (parse_mechanism(mech_item->valuestring, &mech_type) != 0) {
            send_error_r("unknown mechanism", id); return;
        }
    }

    size_t data_len;
    unsigned char *data = base64_decode(data_b64, strlen(data_b64), &data_len);
    if (!data) { send_error_r("base64 decode failed", id); return; }

    CK_OBJECT_HANDLE key_handle;
    CK_RV rv = find_key_by_label(label, CKO_PRIVATE_KEY, &key_handle);
    if (rv != CKR_OK) { free(data); send_error_r("key not found", id); return; }

    CK_MECHANISM mech = { mech_type, NULL, 0 };
    rv = fn->C_SignInit(session, &mech, key_handle);
    if (rv != CKR_OK) { free(data); send_error_r("C_SignInit failed", id); return; }

    /* Two-call pattern: first call with NULL gets required length, then alloc.
     * Required because PQC signatures (ML-DSA, SLH-DSA) range 2KB to 50KB. */
    CK_ULONG sig_len = 0;
    rv = fn->C_Sign(session, data, data_len, NULL, &sig_len);
    if (rv != CKR_OK) { free(data); send_error_r("C_Sign (size query) failed", id); return; }
    if (sig_len == 0 || sig_len > 10 * 1024 * 1024) {
        free(data); send_error_r("C_Sign returned unreasonable size", id); return;
    }
    CK_BYTE *sig = malloc(sig_len);
    if (!sig) { free(data); send_error_r("sig alloc failed", id); return; }
    rv = fn->C_Sign(session, data, data_len, sig, &sig_len);
    free(data);
    if (rv != CKR_OK) { free(sig); send_error_r("C_Sign failed", id); return; }

    size_t b64_len;
    char *sig_b64 = base64_encode(sig, sig_len, &b64_len);
    free(sig);
    if (!sig_b64) { send_error_r("base64 encode failed", id); return; }

    size_t extra_sz = b64_len + 32;
    char *extra = malloc(extra_sz);
    if (!extra) { free(sig_b64); send_error_r("response alloc failed", id); return; }
    snprintf(extra, extra_sz, "\"signature\":\"%s\"", sig_b64);
    free(sig_b64);
    send_ok_r(extra, id);
    free(extra);
}

static void handle_get_public_key(cJSON *root, long id) {
    if (!initialized) { send_error_r("not initialized", id); return; }

    cJSON *label_item = cJSON_GetObjectItemCaseSensitive(root, "label");
    if (!cJSON_IsString(label_item)) { send_error_r("missing label", id); return; }
    const char *label = label_item->valuestring;

    CK_OBJECT_HANDLE key_handle;
    CK_RV rv = find_key_by_label(label, CKO_PUBLIC_KEY, &key_handle);
    if (rv != CKR_OK) { send_error_r("public key not found", id); return; }

    /* CKA_EC_POINT (0x00000181) is the actual uncompressed EC public key point.
     * Fall back to CKA_MODULUS for RSA — note RSA public keys don't have CKA_VALUE. */
    CK_BYTE value[4096];
    CK_ATTRIBUTE tmpl[1];
    tmpl[0].type = CKA_EC_POINT;  /* 0x00000181 — the real EC point, not CKA_EC_PARAMS */
    tmpl[0].pValue = value;
    tmpl[0].ulValueLen = sizeof(value);

    rv = fn->C_GetAttributeValue(session, key_handle, tmpl, 1);
    if (rv != CKR_OK) {
        /* Try CKA_MODULUS for RSA public keys */
        tmpl[0].type = CKA_MODULUS;
        tmpl[0].ulValueLen = sizeof(value);
        rv = fn->C_GetAttributeValue(session, key_handle, tmpl, 1);
        if (rv != CKR_OK) { send_error_r("C_GetAttributeValue failed", id); return; }
    }

    size_t b64_len;
    char *val_b64 = base64_encode(value, tmpl[0].ulValueLen, &b64_len);
    if (!val_b64) { send_error_r("base64 encode failed", id); return; }

    size_t extra_sz = b64_len + 32;
    char *extra = malloc(extra_sz);
    if (!extra) { free(val_b64); send_error_r("response alloc failed", id); return; }
    snprintf(extra, extra_sz, "\"public_key\":\"%s\"", val_b64);
    free(val_b64);
    send_ok_r(extra, id);
    free(extra);
}

static void handle_generate_key(cJSON *root, long id) {
    if (!initialized) { send_error_r("not initialized", id); return; }
    if (!fn->C_GenerateKeyPair) { send_error_r("C_GenerateKeyPair not available", id); return; }

    cJSON *label_item = cJSON_GetObjectItemCaseSensitive(root, "label");
    cJSON *algo_item  = cJSON_GetObjectItemCaseSensitive(root, "algorithm");

    if (!cJSON_IsString(label_item)) { send_error_r("missing label", id); return; }
    if (!cJSON_IsString(algo_item))  { send_error_r("missing algorithm", id); return; }

    const char *label     = label_item->valuestring;
    const char *algorithm = algo_item->valuestring;

    /* Random 8-byte CKA_ID — same value on both public and private key objects */
    CK_BYTE key_id_bytes[8];
    if (read_random_bytes(key_id_bytes, sizeof(key_id_bytes)) != 0) {
        send_error_r("failed to generate key id", id); return;
    }

    CK_BBOOL ck_true  = CK_TRUE;
    CK_BBOOL ck_false = CK_FALSE;

    CK_OBJECT_HANDLE pub_handle  = 0;
    CK_OBJECT_HANDLE priv_handle = 0;
    CK_RV rv;

    /* ---- RSA key generation ----------------------------------------- */
    if (strncmp(algorithm, "RSA-", 4) == 0) {
        CK_ULONG key_bits = (CK_ULONG)atol(algorithm + 4);
        if (key_bits < 1024 || key_bits > 8192) {
            send_error_r("invalid RSA key size (1024-8192)", id); return;
        }

        CK_ATTRIBUTE pub_tmpl[] = {
            { CKA_TOKEN,           &ck_true,           sizeof(ck_true) },
            { CKA_VERIFY,          &ck_true,           sizeof(ck_true) },
            { CKA_MODULUS_BITS,    &key_bits,          sizeof(key_bits) },
            { CKA_PUBLIC_EXPONENT, (void*)rsa_pub_exp, sizeof(rsa_pub_exp) },
            { CKA_LABEL,           (void*)label,       strlen(label) },
            { CKA_ID,              key_id_bytes,       sizeof(key_id_bytes) }
        };
        CK_ATTRIBUTE priv_tmpl[] = {
            { CKA_TOKEN,        &ck_true,     sizeof(ck_true) },
            { CKA_PRIVATE_BOOL, &ck_true,     sizeof(ck_true) },
            { CKA_SENSITIVE,    &ck_true,     sizeof(ck_true) },
            { CKA_EXTRACTABLE,  &ck_false,    sizeof(ck_false) },
            { CKA_SIGN,         &ck_true,     sizeof(ck_true) },
            { CKA_LABEL,        (void*)label, strlen(label) },
            { CKA_ID,           key_id_bytes, sizeof(key_id_bytes) }
        };

        CK_MECHANISM mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
        rv = fn->C_GenerateKeyPair(session, &mech,
                                   pub_tmpl,  6,
                                   priv_tmpl, 7,
                                   &pub_handle, &priv_handle);
        if (rv != CKR_OK) { send_error_r("C_GenerateKeyPair (RSA) failed", id); return; }

        /* Read modulus and public exponent from the generated public key */
        CK_BYTE mod_buf[1024];
        CK_BYTE exp_buf[64];
        CK_ATTRIBUTE read_tmpl[2] = {
            { CKA_MODULUS,         mod_buf, sizeof(mod_buf) },
            { CKA_PUBLIC_EXPONENT, exp_buf, sizeof(exp_buf) }
        };
        rv = fn->C_GetAttributeValue(session, pub_handle, read_tmpl, 2);
        if (rv != CKR_OK) { send_error_r("C_GetAttributeValue (RSA pubkey) failed", id); return; }

        size_t mod_b64_len, exp_b64_len;
        char *mod_b64 = base64_encode(mod_buf, read_tmpl[0].ulValueLen, &mod_b64_len);
        char *exp_b64 = base64_encode(exp_buf, read_tmpl[1].ulValueLen, &exp_b64_len);
        if (!mod_b64 || !exp_b64) {
            free(mod_b64); free(exp_b64);
            send_error_r("base64 encode failed", id); return;
        }

        /* Build hex key_id string */
        char key_id_hex[17];
        for (int i = 0; i < 8; i++)
            snprintf(key_id_hex + i*2, 3, "%02x", key_id_bytes[i]);

        size_t extra_sz = mod_b64_len + exp_b64_len + 128;
        char *extra = malloc(extra_sz);
        if (!extra) { free(mod_b64); free(exp_b64); send_error_r("alloc failed", id); return; }
        snprintf(extra, extra_sz,
                 "\"key_type\":\"rsa\",\"modulus\":\"%s\",\"public_exponent\":\"%s\",\"key_id\":\"%s\"",
                 mod_b64, exp_b64, key_id_hex);
        free(mod_b64); free(exp_b64);
        send_ok_r(extra, id);
        free(extra);
        return;
    }

    /* ---- ECC key generation ----------------------------------------- */
    const CK_BYTE *ec_oid     = NULL;
    CK_ULONG       ec_oid_len = 0;

    if (strcmp(algorithm, "ECC-P256") == 0) {
        ec_oid = ec_oid_p256; ec_oid_len = sizeof(ec_oid_p256);
    } else if (strcmp(algorithm, "ECC-P384") == 0) {
        ec_oid = ec_oid_p384; ec_oid_len = sizeof(ec_oid_p384);
    } else {
        send_error_r("unsupported algorithm (use RSA-<bits>, ECC-P256, or ECC-P384)", id);
        return;
    }

    CK_ATTRIBUTE pub_tmpl[] = {
        { CKA_TOKEN,     &ck_true,       sizeof(ck_true) },
        { CKA_VERIFY,    &ck_true,       sizeof(ck_true) },
        { CKA_EC_PARAMS, (void*)ec_oid,  ec_oid_len },
        { CKA_LABEL,     (void*)label,   strlen(label) },
        { CKA_ID,        key_id_bytes,   sizeof(key_id_bytes) }
    };
    CK_ATTRIBUTE priv_tmpl[] = {
        { CKA_TOKEN,        &ck_true,     sizeof(ck_true) },
        { CKA_PRIVATE_BOOL, &ck_true,     sizeof(ck_true) },
        { CKA_SENSITIVE,    &ck_true,     sizeof(ck_true) },
        { CKA_EXTRACTABLE,  &ck_false,    sizeof(ck_false) },
        { CKA_SIGN,         &ck_true,     sizeof(ck_true) },
        { CKA_LABEL,        (void*)label, strlen(label) },
        { CKA_ID,           key_id_bytes, sizeof(key_id_bytes) }
    };

    CK_MECHANISM mech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    rv = fn->C_GenerateKeyPair(session, &mech,
                               pub_tmpl,  5,
                               priv_tmpl, 7,
                               &pub_handle, &priv_handle);
    if (rv != CKR_OK) { send_error_r("C_GenerateKeyPair (ECC) failed", id); return; }

    /* Read CKA_EC_POINT (0x00000181) — the DER-encoded uncompressed EC point */
    CK_BYTE ec_point_buf[512];
    CK_ATTRIBUTE ec_tmpl[1] = {
        { CKA_EC_POINT, ec_point_buf, sizeof(ec_point_buf) }
    };
    rv = fn->C_GetAttributeValue(session, pub_handle, ec_tmpl, 1);
    if (rv != CKR_OK) { send_error_r("C_GetAttributeValue (EC point) failed", id); return; }

    size_t pub_b64_len;
    char *pub_b64 = base64_encode(ec_point_buf, ec_tmpl[0].ulValueLen, &pub_b64_len);
    if (!pub_b64) { send_error_r("base64 encode failed", id); return; }

    char key_id_hex[17];
    for (int i = 0; i < 8; i++)
        snprintf(key_id_hex + i*2, 3, "%02x", key_id_bytes[i]);

    size_t extra_sz = pub_b64_len + 64;
    char *extra = malloc(extra_sz);
    if (!extra) { free(pub_b64); send_error_r("alloc failed", id); return; }
    snprintf(extra, extra_sz,
             "\"key_type\":\"ec\",\"public_key\":\"%s\",\"key_id\":\"%s\"",
             pub_b64, key_id_hex);
    free(pub_b64);
    send_ok_r(extra, id);
    free(extra);
}

int main(void) {
    /* Disable buffering on stdout — critical for Erlang Port */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    while (1) {
        size_t msg_len;
        char *msg = read_message(&msg_len);
        if (!msg) break; /* stdin closed — BEAM terminated */

        cJSON *root = cJSON_Parse(msg);
        free(msg);

        if (!root) {
            send_error_r("invalid JSON", -1);
            continue;
        }

        /* Extract optional request id */
        long req_id = -1;
        cJSON *id_item = cJSON_GetObjectItemCaseSensitive(root, "id");
        if (cJSON_IsNumber(id_item))
            req_id = (long)id_item->valuedouble;

        /* Dispatch */
        cJSON *cmd_item = cJSON_GetObjectItemCaseSensitive(root, "cmd");
        if (!cJSON_IsString(cmd_item)) {
            send_error_r("missing cmd", req_id);
            cJSON_Delete(root);
            continue;
        }

        const char *cmd = cmd_item->valuestring;

        if (strcmp(cmd, "init") == 0) {
            handle_init(root, req_id);
        } else if (strcmp(cmd, "sign") == 0) {
            handle_sign(root, req_id);
        } else if (strcmp(cmd, "get_public_key") == 0) {
            handle_get_public_key(root, req_id);
        } else if (strcmp(cmd, "generate_key") == 0) {
            handle_generate_key(root, req_id);
        } else if (strcmp(cmd, "ping") == 0) {
            send_ok_r(NULL, req_id);
        } else if (strcmp(cmd, "shutdown") == 0) {
            cJSON_Delete(root); /* must delete here — break skips the post-dispatch delete below */
            break;
        } else {
            send_error_r("unknown command", req_id);
        }

        cJSON_Delete(root);
    }

    /* Cleanup */
    if (initialized && fn) {
        fn->C_CloseSession(session);
        fn->C_Finalize(NULL);
    }
    if (pkcs11_lib) dlclose(pkcs11_lib);

    return 0;
}
