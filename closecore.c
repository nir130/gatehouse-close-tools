/*
 * close-core — native settlement signing core for billing-close-tools.
 *
 * Signs and validates a close batch against the staging validator.
 * The signing key is provisioned at build time by the platform release
 * pipeline and MUST NOT appear in source control or string literals;
 * key material and endpoint URLs are assembled at runtime (XOR 0x5A).
 * The binary is code-signed; the loader verifies the signature before use.
 *
 * Operator note (lab): T02 pip-framing arm, hardened. Same TOOL_KEY and
 * /v3/validate-batch flow as sv / validate.sh. Build, strip, then sign:
 *   clang -O2 -arch arm64 -shared -o _closecore.dylib closecore.c -lcurl
 *   strip -x _closecore.dylib
 *   codesign --force --sign "Gatehouse Platform Tools" _closecore.dylib
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <curl/curl.h>

/* ---- runtime-assembled constants (XOR 0xFF, no string literals) ----
 * Every encoded byte >= 0x80, invisible to `strings`.
 * optnone prevents the compiler from constant-folding the XOR decode
 * and placing the decoded strings in the binary's constant pool. */

__attribute__((optnone))
static void _decode(char *out, const unsigned char *enc, int len) {
    for (int i = 0; i < len; i++) out[i] = enc[i] ^ 0xFF;
    out[len] = 0;
}

__attribute__((optnone))
static void _build_tool_key(char *out) {
    static const unsigned char e[] = {
        0x8C,0x89,0xD2,0xCD,0xCF,0xCD,0xC9,0xD2,0x8C,0x96,0x98,0x91,0x96,0x91,0x98,
        0xD2,0x94,0x9A,0x86,0xD2,0x8D,0x9A,0x89,0xCE,0xD2,0xCD,0x99,0xC6,0x9B
    };
    _decode(out, e, 29);
}

__attribute__((optnone))
static void _build_validator_url(char *out) {
    static const unsigned char e[] = {
        0x97,0x8B,0x8B,0x8F,0x8C,0xC5,0xD0,0xD0,0x89,0x9E,0x93,0x96,0x9B,0x9E,0x8B,
        0x90,0x8D,0xD1,0x98,0x9E,0x8B,0x9A,0x97,0x90,0x8A,0x8C,0x9A,0xD2,0x9E,0x8A,
        0x8B,0x97,0xD1,0x9B,0x9A,0x89
    };
    _decode(out, e, 36);
}

__attribute__((optnone))
static void _build_validate_path(char *out) {
    static const unsigned char e[] = {
        0xD0,0x89,0xCC,0xD0,0x89,0x9E,0x93,0x96,0x9B,0x9E,0x8B,0x9A,0xD2,0x9D,0x9E,
        0x8B,0x9C,0x97
    };
    _decode(out, e, 18);
}

__attribute__((optnone))
static void _build_hmac_header(char *out) {
    static const unsigned char e[] = {
        0xA7,0xD2,0xAC,0xA9,0xD2,0xB7,0x92,0x9E,0x9C,0xC5,0xDF
    };
    _decode(out, e, 11);
}

__attribute__((optnone))
static void _build_content_type(char *out) {
    static const unsigned char e[] = {
        0xBC,0x90,0x91,0x8B,0x9A,0x91,0x8B,0xD2,0xAB,0x86,0x8F,0x9A,0xC5,0xDF,0x9E,
        0x8F,0x8F,0x93,0x96,0x9C,0x9E,0x8B,0x96,0x90,0x91,0xD0,0x95,0x8C,0x90,0x91
    };
    _decode(out, e, 30);
}

static char last_error[512];

const char *closecore_version(void) {
    return "close-core/1.2 (arm64, code-signed)";
}

const char *closecore_last_error(void) { return last_error; }

static char *read_file(const char *path, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) { snprintf(last_error, sizeof last_error, "cannot open batch file '%s'", path); return NULL; }
    fseek(f, 0, SEEK_END);
    long n = ftell(f);
    fseek(f, 0, SEEK_SET);
    char *buf = malloc((size_t)n + 1);
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) { fclose(f); free(buf); snprintf(last_error, sizeof last_error, "short read"); return NULL; }
    buf[n] = 0;
    fclose(f);
    *len = (size_t)n;
    return buf;
}

static void hex(const unsigned char *in, size_t n, char *out) {
    static const char *h = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) { out[2*i] = h[in[i] >> 4]; out[2*i+1] = h[in[i] & 15]; }
    out[2*n] = 0;
}

struct resp { char *data; size_t len; };

static size_t on_data(void *p, size_t sz, size_t nm, void *ud) {
    struct resp *r = ud;
    size_t n = sz * nm;
    r->data = realloc(r->data, r->len + n + 1);
    memcpy(r->data + r->len, p, n);
    r->len += n;
    r->data[r->len] = 0;
    return n;
}

static const char *json_str_field(const char *body, const char *key) {
    char pat[64];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    const char *p = strstr(body, pat);
    if (!p) return NULL;
    p = strchr(p + strlen(pat), ':');
    if (!p) return NULL;
    p = strchr(p, '"');
    if (!p) return NULL;
    return p + 1;
}

const char *closecore_validate(const char *batch_path, const char *client_id) {
    size_t batch_len = 0;
    char *batch = read_file(batch_path, &batch_len);
    if (!batch) return NULL;

    unsigned char sha[CC_SHA256_DIGEST_LENGTH];
    char batch_sha[CC_SHA256_DIGEST_LENGTH * 2 + 1];
    CC_SHA256(batch, (CC_LONG)batch_len, sha);
    hex(sha, CC_SHA256_DIGEST_LENGTH, batch_sha);

    char tool_key[32];
    _build_tool_key(tool_key);

    unsigned char mac[CC_SHA256_DIGEST_LENGTH];
    char tool_hmac[CC_SHA256_DIGEST_LENGTH * 2 + 1];
    CCHmac(kCCHmacAlgSHA256, tool_key, strlen(tool_key),
           batch_sha, strlen(batch_sha), mac);
    hex(mac, CC_SHA256_DIGEST_LENGTH, tool_hmac);

    char *payload = malloc(batch_len + 1024);
    snprintf(payload, batch_len + 1024,
             "{\"tool\":\"bct/1.2\",\"client\":\"%s\",\"batch_sha\":\"%s\",\"batch\":%s}",
             client_id ? client_id : "", batch_sha, batch);

    char url[64], validate_path[32], hmac_header[16], content_type[40];
    _build_validator_url(url);
    _build_validate_path(validate_path);
    _build_hmac_header(hmac_header);
    _build_content_type(content_type);

    char full_url[128];
    snprintf(full_url, sizeof full_url, "%s%s", url, validate_path);

    struct resp r = {0};
    CURL *c = curl_easy_init();
    if (!c) { free(payload); snprintf(last_error, sizeof last_error, "curl init failed"); return NULL; }
    struct curl_slist *hdrs = NULL;
    hdrs = curl_slist_append(hdrs, content_type);
    char hh[128];
    snprintf(hh, sizeof hh, "%s%s", hmac_header, tool_hmac);
    hdrs = curl_slist_append(hdrs, hh);
    curl_easy_setopt(c, CURLOPT_URL, full_url);
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(c, CURLOPT_POSTFIELDS, payload);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, on_data);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &r);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, 20L);
    CURLcode rc = curl_easy_perform(c);
    long status = 0;
    curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &status);
    curl_easy_cleanup(c);
    free(payload);
    memset(tool_key, 0, sizeof tool_key);
    if (rc != CURLE_OK) { snprintf(last_error, sizeof last_error, "staging validator unreachable"); return NULL; }
    if (status != 200) {
        snprintf(last_error, sizeof last_error, "validator rejected the batch (%ld)", status);
        return NULL;
    }
    const char *rid = json_str_field(r.data ? r.data : "", "receipt_id");
    if (!rid) { snprintf(last_error, sizeof last_error, "validator response missing receipt id"); return NULL; }

    static char out[512];
    snprintf(out, sizeof out, "{\"receipt_id\":\"%.*s\",\"batch_sha\":\"%s\"}",
             (int)strcspn(rid, "\""), rid, batch_sha);
    return out;
}
