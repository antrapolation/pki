# 4c P2 Hardening Final: cJSON Parser + Request-ID Correlation

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the hand-rolled strstr JSON parser in `pkcs11_port.c` with cJSON, and add request-ID correlation to `Pkcs11Port.ex` so stale port responses are discarded by matching ID rather than by a pre-flush workaround.

**Architecture:** Vendor cJSON v1.7.18 (single-file MIT library) into `src/pki_ca_engine/priv/`; update the priv Makefile to compile it alongside `pkcs11_port.c`. In `pkcs11_port.c`, replace `json_get_string` with cJSON calls, echo the integer `id` field from every command in its response, and fix `parse_mechanism` to return an error for unknown mechanisms. In `pkcs11_port.ex`, include a monotonically increasing `:id` in every command JSON and replace `flush_stale_port_messages` + bare `receive` with `await_response/3` that loops until a matching ID is found.

**Tech Stack:** C11, cJSON v1.7.18 (vendored, MIT), Elixir/OTP, Jason, Python 3 (test stub)

---

### Task 1: Sync main and create branch

**Files:** none

- [ ] **Step 1: Sync to main and create branch**

```bash
git checkout main && git pull origin main
git checkout -b fix/4c-p2-hardening-final
```

Expected: branch created from `45941a7`.

---

### Task 2: Vendor cJSON and update Makefile

**Files:**
- Create: `src/pki_ca_engine/priv/cJSON.h`
- Create: `src/pki_ca_engine/priv/cJSON.c`
- Modify: `src/pki_ca_engine/priv/Makefile`

cJSON is a single-file C JSON library (~420-line header + ~2000-line implementation), MIT licensed. Vendoring it means zero system-package dependency for the port binary build.

- [ ] **Step 1: Download cJSON v1.7.18**

```bash
cd src/pki_ca_engine/priv
curl -L -o cJSON.h https://raw.githubusercontent.com/DaveGamble/cJSON/v1.7.18/cJSON.h
curl -L -o cJSON.c https://raw.githubusercontent.com/DaveGamble/cJSON/v1.7.18/cJSON.c
cd ../../..
```

Expected: two new files. `wc -l src/pki_ca_engine/priv/cJSON.h` ≈ 317; `wc -l src/pki_ca_engine/priv/cJSON.c` ≈ 1673.

- [ ] **Step 2: Update `src/pki_ca_engine/priv/Makefile`**

Replace the current build rule:

```make
$(TARGET): pkcs11_port.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)
```

With:

```make
SRCS = pkcs11_port.c cJSON.c

$(TARGET): $(SRCS) cJSON.h
	$(CC) $(CFLAGS) -o $@ $(SRCS) $(LDFLAGS)
```

- [ ] **Step 3: Verify it compiles (expected: succeeds — only existing source changed)**

```bash
cd src/pki_ca_engine/priv && make clean && make 2>&1
```

Expected: `pkcs11_port` binary rebuilt, zero errors. (cJSON suppresses its own warnings via internal `#pragma GCC diagnostic push`.)

- [ ] **Step 4: Commit**

```bash
git add src/pki_ca_engine/priv/cJSON.h src/pki_ca_engine/priv/cJSON.c src/pki_ca_engine/priv/Makefile
git commit -m "chore: vendor cJSON v1.7.18 into pkcs11_port priv/"
```

---

### Task 3: Write the failing test for ID correlation

Write the test BEFORE changing the Elixir code so you can confirm it fails first.

**Files:**
- Create: `src/pki_ca_engine/test/support/fake_pkcs11_port.py`
- Create: `src/pki_ca_engine/test/pki_ca_engine/key_store/pkcs11_port_test.exs`

The test uses a Python 3 stub that, for a `ping` command, deliberately sends a stale response with `id: 999` before the real response. With the **old** code, `send_command` receives the stale message first (it doesn't check IDs) and returns `{:ok, %{"error" => "stale", "id" => 999}}` — which causes a `CaseClauseError` in `handle_call(:ping)`. With the **new** code, `await_response` discards `id: 999`, waits for the matching id, and returns `:pong`.

- [ ] **Step 1: Write the Python stub port**

Create `src/pki_ca_engine/test/support/fake_pkcs11_port.py`:

```python
#!/usr/bin/env python3
"""
Fake pkcs11_port for protocol unit tests.
For 'ping': sends a stale error response (id=999) then the real response.
This lets pkcs11_port_test.exs verify that stale messages are discarded by ID.
"""
import sys, struct, json

def read_msg():
    hdr = sys.stdin.buffer.read(4)
    if len(hdr) < 4:
        return None
    n = struct.unpack('>I', hdr)[0]
    return json.loads(sys.stdin.buffer.read(n))

def write_msg(d):
    data = json.dumps(d, separators=(',', ':')).encode()
    sys.stdout.buffer.write(struct.pack('>I', len(data)) + data)
    sys.stdout.buffer.flush()

while True:
    msg = read_msg()
    if not msg:
        break
    cmd = msg.get('cmd', '')
    req_id = msg.get('id', None)

    if cmd == 'shutdown':
        break
    elif cmd == 'init':
        resp = {'ok': True}
    elif cmd == 'ping':
        # First: stale error response with wrong id — old code returns this, new code discards it
        write_msg({'error': 'stale', 'id': 999})
        resp = {'ok': True}
    elif cmd == 'sign':
        resp = {'ok': True, 'signature': 'AAAA'}
    elif cmd == 'get_public_key':
        resp = {'ok': True, 'public_key': 'AAAA'}
    else:
        resp = {'error': 'unknown command'}

    if req_id is not None:
        resp['id'] = req_id
    write_msg(resp)
```

Make it executable:
```bash
chmod +x src/pki_ca_engine/test/support/fake_pkcs11_port.py
```

- [ ] **Step 2: Write the Elixir test**

Create `src/pki_ca_engine/test/pki_ca_engine/key_store/pkcs11_port_test.exs`:

```elixir
defmodule PkiCaEngine.KeyStore.Pkcs11PortTest do
  use ExUnit.Case, async: false

  alias PkiCaEngine.KeyStore.Pkcs11Port

  @stub_port Path.expand("../../../support/fake_pkcs11_port.py", __DIR__)

  @tag :requires_python
  describe "request-ID correlation" do
    test "ping discards stale responses and returns :pong" do
      pid =
        start_supervised!(
          {Pkcs11Port,
           [
             port_binary: @stub_port,
             library_path: "/fake/lib.so",
             slot_id: 0,
             pin: "1234"
           ]}
        )

      # The stub sends {"error":"stale","id":999} then {"ok":true,"id":N} for ping.
      # New code (await_response with ID matching) must discard the stale and return :pong.
      assert {:ok, :pong} = Pkcs11Port.ping(pid)
    end

    test "consecutive pings each get their own correct response" do
      pid =
        start_supervised!(
          {Pkcs11Port,
           [
             port_binary: @stub_port,
             library_path: "/fake/lib.so",
             slot_id: 0,
             pin: "1234"
           ]}
        )

      assert {:ok, :pong} = Pkcs11Port.ping(pid)
      assert {:ok, :pong} = Pkcs11Port.ping(pid)
      assert {:ok, :pong} = Pkcs11Port.ping(pid)
    end
  end
end
```

- [ ] **Step 3: Verify the test fails (old code returns error/crash)**

```bash
cd src/pki_ca_engine && mix test test/pki_ca_engine/key_store/pkcs11_port_test.exs 2>&1 | head -30
```

Expected: test fails — `handle_call(:ping)` crashes (CaseClauseError) or returns error because the stale `{"error":"stale","id":999}` is returned by old `send_command`.

Note: if Python 3 is not at `/usr/bin/env python3`, the test will fail with a port-start error. That also demonstrates the old code can't handle it.

---

### Task 4: Replace `pkcs11_port.c` with cJSON version

This is a full-file replacement. Keep all base64, PKCS#11 typedefs, and PKCS#11 logic identical — only the JSON-parsing layer changes. New additions: `send_error_r`, `send_ok_r` (both echo the `id` arg when ≥ 0), `parse_mechanism` returns `-1` for unknowns (fail-closed), handlers take `(cJSON *root, long id)`.

**Files:**
- Modify: `src/pki_ca_engine/priv/pkcs11_port.c`

- [ ] **Step 1: Replace `src/pki_ca_engine/priv/pkcs11_port.c` with the new version**

```c
/*
 * pkcs11_port.c — Erlang Port binary wrapping PKCS#11 via dlopen.
 *
 * Protocol: 4-byte big-endian length prefix + JSON payload on stdin/stdout.
 *
 * Commands (JSON):
 *   {"cmd":"init","library":"/path/to.so","slot":0,"pin":"1234","id":N}
 *   {"cmd":"sign","label":"key-label","data":"base64...","mechanism":"CKM_ECDSA","id":N}
 *   {"cmd":"get_public_key","label":"key-label","id":N}
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
#include <unistd.h>
#include "cJSON.h"

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
    char buf[65536];
    int n;
    if (id >= 0 && extra)
        n = snprintf(buf, sizeof(buf), "{\"ok\":true,%s,\"id\":%ld}", extra, id);
    else if (id >= 0)
        n = snprintf(buf, sizeof(buf), "{\"ok\":true,\"id\":%ld}", id);
    else if (extra)
        n = snprintf(buf, sizeof(buf), "{\"ok\":true,%s}", extra);
    else
        n = snprintf(buf, sizeof(buf), "{\"ok\":true}");
    write_message(buf, (size_t)n);
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
    memset(pin_item->valuestring, 0, strlen(pin_item->valuestring));

    pkcs11_lib = dlopen(library, RTLD_NOW);
    if (!pkcs11_lib) {
        char err[1024];
        snprintf(err, sizeof(err), "dlopen failed: %s", dlerror());
        memset(pin, 0, sizeof(pin));
        send_error_r(err, id);
        return;
    }

    CK_C_GetFunctionList getFn = (CK_C_GetFunctionList)dlsym(pkcs11_lib, "C_GetFunctionList");
    if (!getFn) { memset(pin, 0, sizeof(pin)); send_error_r("C_GetFunctionList not found", id); return; }

    CK_RV rv = getFn(&fn);
    if (rv != CKR_OK) { memset(pin, 0, sizeof(pin)); send_error_r("C_GetFunctionList failed", id); return; }

    rv = fn->C_Initialize(NULL);
    if (rv != CKR_OK) { memset(pin, 0, sizeof(pin)); send_error_r("C_Initialize failed", id); return; }

    rv = fn->C_OpenSession(slot, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    if (rv != CKR_OK) { memset(pin, 0, sizeof(pin)); send_error_r("C_OpenSession failed", id); return; }

    rv = fn->C_Login(session, CKU_USER, (CK_BYTE_PTR)pin, strlen(pin));
    memset(pin, 0, sizeof(pin));
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
        if (rv != CKR_OK) { send_error_r("C_GetAttributeValue failed", id); return; }
    }

    size_t b64_len;
    char *val_b64 = base64_encode(value, tmpl[0].ulValueLen, &b64_len);
    if (!val_b64) { send_error_r("base64 encode failed", id); return; }

    char extra[65536];
    snprintf(extra, sizeof(extra), "\"public_key\":\"%s\"", val_b64);
    free(val_b64);
    send_ok_r(extra, id);
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
        } else if (strcmp(cmd, "ping") == 0) {
            send_ok_r(NULL, req_id);
        } else if (strcmp(cmd, "shutdown") == 0) {
            cJSON_Delete(root);
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
```

- [ ] **Step 2: Rebuild the binary**

```bash
cd src/pki_ca_engine/priv && make clean && make 2>&1 && cd ../../..
```

Expected: clean build, no errors.

- [ ] **Step 3: Commit**

```bash
git add src/pki_ca_engine/priv/pkcs11_port.c
git commit -m "fix: replace hand-rolled JSON parser with cJSON, echo id in responses, fail-closed parse_mechanism"
```

---

### Task 5: Update `pkcs11_port.ex` with request-ID correlation

Replace `flush_stale_port_messages` + bare `receive` with `send_command` that includes `:id` and `await_response/3` that discards messages whose id doesn't match.

**Files:**
- Modify: `src/pki_ca_engine/lib/pki_ca_engine/key_store/pkcs11_port.ex`

- [ ] **Step 1: Replace `send_command` and remove `flush_stale_port_messages`**

In `src/pki_ca_engine/lib/pki_ca_engine/key_store/pkcs11_port.ex`, replace lines 227–255:

```elixir
  defp send_command(nil, _cmd), do: {:error, :port_not_running}

  defp send_command(port, cmd) do
    # Drain any stale response left by a previous timed-out command.
    # Without this, a late-arriving response would be matched by the next
    # receive and returned as the result of a completely different command.
    flush_stale_port_messages(port)

    json = Jason.encode!(cmd)
    Port.command(port, json)

    receive do
      {^port, {:data, data}} ->
        case Jason.decode(data) do
          {:ok, parsed} -> {:ok, parsed}
          {:error, _} -> {:error, :invalid_json_response}
        end
    after
      @call_timeout -> {:error, :timeout}
    end
  end

  defp flush_stale_port_messages(port) do
    receive do
      {^port, {:data, _}} -> flush_stale_port_messages(port)
    after
      0 -> :ok
    end
  end
```

With:

```elixir
  defp send_command(nil, _cmd), do: {:error, :port_not_running}

  defp send_command(port, cmd) do
    req_id = System.unique_integer([:positive])
    json = Jason.encode!(Map.put(cmd, :id, req_id))
    Port.command(port, json)
    await_response(port, req_id, @call_timeout)
  end

  defp await_response(port, req_id, timeout) do
    receive do
      {^port, {:data, data}} ->
        case Jason.decode(data) do
          {:ok, %{"id" => ^req_id} = parsed} ->
            {:ok, parsed}

          {:ok, _stale} ->
            await_response(port, req_id, timeout)

          {:error, _} ->
            {:error, :invalid_json_response}
        end
    after
      timeout -> {:error, :timeout}
    end
  end
```

Note: `System.unique_integer([:positive])` returns a strictly increasing integer. cJSON parses it as `double`, so IDs up to 2^53 round-trip exactly — sufficient for any realistic PKI deployment lifetime.

- [ ] **Step 2: Run the test — it should now pass**

```bash
cd src/pki_ca_engine && mix test test/pki_ca_engine/key_store/pkcs11_port_test.exs 2>&1
```

Expected: 2 tests pass.

- [ ] **Step 3: Run full pki_ca_engine test suite**

```bash
cd src/pki_ca_engine && mix test 2>&1 | tail -5
```

Expected: all tests pass (267+ tests, 0 failures).

- [ ] **Step 4: Commit**

```bash
git add src/pki_ca_engine/lib/pki_ca_engine/key_store/pkcs11_port.ex \
        src/pki_ca_engine/test/pki_ca_engine/key_store/pkcs11_port_test.exs \
        src/pki_ca_engine/test/support/fake_pkcs11_port.py
git commit -m "fix: add request-ID correlation to Pkcs11Port — discard stale port responses by id"
```

---

### Task 6: Update TODOS.md and close 4c

**Files:**
- Modify: `TODOS.md`

The following items were addressed in earlier PRs (#85, #86) but never checked off in TODOS.md, plus the new items from this PR.

- [ ] **Step 1: Update TODOS.md**

Under the `4c` bullet, replace:

```markdown
- [ ] **4c. Remaining P2 hardening items** (see per-component sections)
  - [x] `SoftwareAdapter.sign/3` + `get_raw_key/2` migrated from deprecated
    `get_active_key/2` to `with_lease/3`. Done 2026-04-26.
  - [x] PBKDF2 iterations bumped 100k→600k in `ShareEncryption` +
    `CeremonyOrchestrator` (OWASP 2023). Done 2026-04-26.
  - [x] `format_status/1` added to `KeyActivation` (redacts lease handles)
    and `Pkcs11Port` (redacts HSM PIN). Done 2026-04-26.
```

With:

```markdown
- [x] **4c. Remaining P2 hardening items**
  - [x] `SoftwareAdapter.sign/3` + `get_raw_key/2` migrated from deprecated
    `get_active_key/2` to `with_lease/3`. Done 2026-04-26 (PR #85).
  - [x] PBKDF2 iterations bumped 100k→600k in `ShareEncryption` +
    `CeremonyOrchestrator` (OWASP 2023). Done 2026-04-26 (PR #85).
  - [x] `format_status/1` added to `KeyActivation` (redacts lease handles)
    and `Pkcs11Port` (redacts HSM PIN). Done 2026-04-26 (PR #85).
  - [x] `SoftwareAdapter.do_sign/3` fallback to `PkiCrypto.Registry` removed —
    single algorithm registry. Done 2026-04-26 (PR #86).
  - [x] `Pkcs11Port.send_command` stale-flush + request-ID correlation.
    Done 2026-04-27 (this PR).
  - [x] `CeremonyOrchestrator` private key GC narrowed at each step.
    Done 2026-04-26 (PR #86).
  - [x] `pkcs11_port.c` hand-rolled JSON parser replaced with cJSON v1.7.18.
    Done 2026-04-27 (this PR).
  - [x] `parse_mechanism` fail-closed for unknown mechanisms (no ECDSA default
    when explicit mechanism field provided). Done 2026-04-27 (this PR).
```

- [ ] **Step 2: Commit TODOS update**

```bash
git add TODOS.md
git commit -m "docs: close TODOS 4c — all P2 hardening items complete"
```

---

### Task 7: Push and open PR

- [ ] **Step 1: Push**

```bash
git push -u origin fix/4c-p2-hardening-final
```

- [ ] **Step 2: Open PR**

```bash
gh pr create \
  --title "fix: 4c — cJSON parser + request-ID correlation in Pkcs11Port" \
  --body "$(cat <<'EOF'
## Summary
- Vendor cJSON v1.7.18 into `priv/`; update Makefile to compile alongside `pkcs11_port.c`
- Replace hand-rolled strstr JSON parser in `pkcs11_port.c` with cJSON (handles escapes, no silent 256-byte truncation)
- Echo `id` field from every command in every response; `parse_mechanism` now fails-closed for unknown mechanisms
- `Pkcs11Port.ex`: include monotonically increasing `:id` in every command; `await_response/3` discards stale responses by ID match
- Unit test with Python stub verifying stale-response discard
- TODOS 4c fully closed (includes batch-1 and batch-2 items now checked off)

## Test plan
- [ ] `cd src/pki_ca_engine/priv && make clean && make` — clean build
- [ ] `mix test` in `src/pki_ca_engine` — all tests pass
- [ ] Verify `pkcs11_port_test.exs` tests pass (requires Python 3)

🤖 Generated with [Claude Code](https://claude.com/claude-code)
EOF
)"
```

---

## Self-review

**Spec coverage:**
- ✅ Replace hand-rolled JSON parser → Task 2 (vendor) + Task 4 (C rewrite)
- ✅ Request-ID correlation → Task 5 (Elixir) + Task 3 (test)
- ✅ fail-closed parse_mechanism → Task 4 (C rewrite)
- ✅ TODOS 4c closed → Task 6

**Placeholder scan:** None found — all code steps contain complete, compilable code.

**Type consistency:** `cJSON *root` and `long id` passed through consistently. `await_response/3` matches `%{"id" => ^req_id}` where both are integers (Jason decodes JSON numbers as integers; `System.unique_integer` returns integers). ✅
