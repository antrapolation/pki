/*
 * pkcs11_port.c — Erlang Port binary wrapping PKCS#11 via dlopen.
 *
 * Protocol: 4-byte big-endian length prefix + JSON payload on stdin/stdout.
 *
 * Commands (JSON):
 *   {"cmd":"init","library":"/path/to.so","slot":0,"pin":"1234"}
 *   {"cmd":"sign","label":"key-label","data":"base64...","mechanism":"CKM_ECDSA"}
 *   {"cmd":"get_public_key","label":"key-label"}
 *   {"cmd":"ping"}
 *   {"cmd":"shutdown"}
 *
 * Responses (JSON):
 *   {"ok":true,...}
 *   {"error":"message"}
 *
 * PQC mechanism mapping:
 *   CKM_ECDSA          = 0x00001041  (ECDSA / EC keys)
 *   CKM_RSA_PKCS       = 0x00000001  (RSA PKCS#1 v1.5)
 *   CKM_VENDOR_DEFINED = 0x80000000  (base for vendor-specific)
 *     KAZ-SIGN: CKM_VENDOR_DEFINED + 0x00010001  (vendor OID: TBD by MYPKI)
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
#include <unistd.h>

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
#define CKM_ECDSA               0x00001041
#define CKM_RSA_PKCS            0x00000001
#define CKM_VENDOR_DEFINED      0x80000000UL
#define CK_TRUE                 1
#define CK_FALSE                0
#define CKA_SIGN                0x00000108
#define CKA_EC_POINT            0x00000180

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
    /* remaining functions omitted — not needed */
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

/* Simple JSON parsing — we only handle flat objects with string values */
/* This is intentionally simple. Production would use a proper JSON lib. */
static int json_get_string(const char *json, const char *key, char *out, size_t out_sz) {
    char search[256];
    snprintf(search, sizeof(search), "\"%s\":\"", key);
    const char *start = strstr(json, search);
    if (!start) {
        /* Try without quotes for numbers */
        snprintf(search, sizeof(search), "\"%s\":", key);
        start = strstr(json, search);
        if (!start) return -1;
        start += strlen(search);
        /* skip whitespace */
        while (*start == ' ') start++;
        const char *end = start;
        while (*end && *end != ',' && *end != '}' && *end != ' ') end++;
        size_t len = (size_t)(end - start);
        if (len >= out_sz) return -1;
        memcpy(out, start, len);
        out[len] = '\0';
        return 0;
    }
    start += strlen(search);
    const char *end = strchr(start, '"');
    if (!end) return -1;
    size_t len = (size_t)(end - start);
    if (len >= out_sz) return -1;
    memcpy(out, start, len);
    out[len] = '\0';
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

static void send_error(const char *msg) {
    char buf[1024];
    int n = snprintf(buf, sizeof(buf), "{\"error\":\"%s\"}", msg);
    write_message(buf, (size_t)n);
}

static void send_ok(const char *extra) {
    char buf[65536];
    int n;
    if (extra)
        n = snprintf(buf, sizeof(buf), "{\"ok\":true,%s}", extra);
    else
        n = snprintf(buf, sizeof(buf), "{\"ok\":true}");
    write_message(buf, (size_t)n);
}

/* Find a private key by label */
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

static void handle_init(const char *json) {
    char library[512], slot_str[32], pin[256];
    if (json_get_string(json, "library", library, sizeof(library)) != 0) {
        send_error("missing library"); return;
    }
    if (json_get_string(json, "slot", slot_str, sizeof(slot_str)) != 0) {
        send_error("missing slot"); return;
    }
    if (json_get_string(json, "pin", pin, sizeof(pin)) != 0) {
        send_error("missing pin"); return;
    }

    CK_SLOT_ID slot = (CK_SLOT_ID)atol(slot_str);

    /* Load PKCS#11 library */
    pkcs11_lib = dlopen(library, RTLD_NOW);
    if (!pkcs11_lib) {
        char err[1024];
        snprintf(err, sizeof(err), "dlopen failed: %s", dlerror());
        send_error(err);
        return;
    }

    CK_C_GetFunctionList getFn = (CK_C_GetFunctionList)dlsym(pkcs11_lib, "C_GetFunctionList");
    if (!getFn) { send_error("C_GetFunctionList not found"); return; }

    CK_RV rv = getFn(&fn);
    if (rv != CKR_OK) { send_error("C_GetFunctionList failed"); return; }

    rv = fn->C_Initialize(NULL);
    if (rv != CKR_OK) { send_error("C_Initialize failed"); return; }

    rv = fn->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    if (rv != CKR_OK) { send_error("C_OpenSession failed"); return; }

    rv = fn->C_Login(session, CKU_USER, (CK_BYTE_PTR)pin, strlen(pin));
    if (rv != CKR_OK) { send_error("C_Login failed"); return; }

    initialized = 1;
    send_ok(NULL);
}

/* Map mechanism string to PKCS#11 mechanism type */
static CK_MECHANISM_TYPE parse_mechanism(const char *mech_str) {
    if (strcmp(mech_str, "CKM_RSA_PKCS") == 0)       return CKM_RSA_PKCS;
    if (strcmp(mech_str, "CKM_ECDSA") == 0)           return CKM_ECDSA;
    if (strcmp(mech_str, "CKM_KAZ_SIGN") == 0)        return CKM_KAZ_SIGN;
    if (strcmp(mech_str, "CKM_ML_DSA") == 0)          return CKM_ML_DSA;
    if (strcmp(mech_str, "CKM_VENDOR_DEFINED") == 0)   return CKM_VENDOR_DEFINED;
    /* Default to ECDSA */
    return CKM_ECDSA;
}

static void handle_sign(const char *json) {
    if (!initialized) { send_error("not initialized"); return; }

    char label[256], data_b64[65536], mech_str[64];
    if (json_get_string(json, "label", label, sizeof(label)) != 0) {
        send_error("missing label"); return;
    }
    if (json_get_string(json, "data", data_b64, sizeof(data_b64)) != 0) {
        send_error("missing data"); return;
    }
    if (json_get_string(json, "mechanism", mech_str, sizeof(mech_str)) != 0) {
        /* default to ECDSA */
        strcpy(mech_str, "CKM_ECDSA");
    }

    CK_MECHANISM_TYPE mech_type = parse_mechanism(mech_str);

    /* Decode base64 data */
    size_t data_len;
    unsigned char *data = base64_decode(data_b64, strlen(data_b64), &data_len);
    if (!data) { send_error("base64 decode failed"); return; }

    /* Find the private key */
    CK_OBJECT_HANDLE key_handle;
    CK_RV rv = find_key_by_label(label, CKO_PRIVATE_KEY, &key_handle);
    if (rv != CKR_OK) { free(data); send_error("key not found"); return; }

    /* Sign */
    CK_MECHANISM mech = { mech_type, NULL, 0 };
    rv = fn->C_SignInit(session, &mech, key_handle);
    if (rv != CKR_OK) { free(data); send_error("C_SignInit failed"); return; }

    CK_BYTE sig[4096];
    CK_ULONG sig_len = sizeof(sig);
    rv = fn->C_Sign(session, data, data_len, sig, &sig_len);
    free(data);
    if (rv != CKR_OK) { send_error("C_Sign failed"); return; }

    /* Encode signature as base64 */
    size_t b64_len;
    char *sig_b64 = base64_encode(sig, sig_len, &b64_len);
    if (!sig_b64) { send_error("base64 encode failed"); return; }

    char extra[65536];
    snprintf(extra, sizeof(extra), "\"signature\":\"%s\"", sig_b64);
    free(sig_b64);
    send_ok(extra);
}

static void handle_get_public_key(const char *json) {
    if (!initialized) { send_error("not initialized"); return; }

    char label[256];
    if (json_get_string(json, "label", label, sizeof(label)) != 0) {
        send_error("missing label"); return;
    }

    CK_OBJECT_HANDLE key_handle;
    CK_RV rv = find_key_by_label(label, CKO_PUBLIC_KEY, &key_handle);
    if (rv != CKR_OK) { send_error("public key not found"); return; }

    /* Get the EC_POINT attribute (DER-encoded public key) */
    CK_BYTE value[4096];
    CK_ATTRIBUTE tmpl[1];
    tmpl[0].type = CKA_EC_POINT;
    tmpl[0].pValue = value;
    tmpl[0].ulValueLen = sizeof(value);

    rv = fn->C_GetAttributeValue(session, key_handle, tmpl, 1);
    if (rv != CKR_OK) {
        /* Try CKA_VALUE for RSA */
        tmpl[0].type = CKA_VALUE;
        tmpl[0].ulValueLen = sizeof(value);
        rv = fn->C_GetAttributeValue(session, key_handle, tmpl, 1);
        if (rv != CKR_OK) { send_error("C_GetAttributeValue failed"); return; }
    }

    size_t b64_len;
    char *val_b64 = base64_encode(value, tmpl[0].ulValueLen, &b64_len);
    if (!val_b64) { send_error("base64 encode failed"); return; }

    char extra[65536];
    snprintf(extra, sizeof(extra), "\"public_key\":\"%s\"", val_b64);
    free(val_b64);
    send_ok(extra);
}

int main(void) {
    /* Disable buffering on stdout — critical for Erlang Port */
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);

    while (1) {
        size_t msg_len;
        char *msg = read_message(&msg_len);
        if (!msg) break; /* stdin closed — BEAM terminated */

        char cmd[64];
        if (json_get_string(msg, "cmd", cmd, sizeof(cmd)) != 0) {
            send_error("missing cmd");
            free(msg);
            continue;
        }

        if (strcmp(cmd, "init") == 0) {
            handle_init(msg);
        } else if (strcmp(cmd, "sign") == 0) {
            handle_sign(msg);
        } else if (strcmp(cmd, "get_public_key") == 0) {
            handle_get_public_key(msg);
        } else if (strcmp(cmd, "ping") == 0) {
            send_ok(NULL);
        } else if (strcmp(cmd, "shutdown") == 0) {
            free(msg);
            break;
        } else {
            send_error("unknown command");
        }

        free(msg);
    }

    /* Cleanup */
    if (initialized && fn) {
        fn->C_CloseSession(session);
        fn->C_Finalize(NULL);
    }
    if (pkcs11_lib) dlclose(pkcs11_lib);

    return 0;
}
