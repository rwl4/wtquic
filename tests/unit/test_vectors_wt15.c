/*
 * Committed wire-fixture validation for the draft-15 proto plane.
 *
 * Default mode, for every vector:
 *   - read tests/vectors/wt15/<name>.bin and require byte-identity with
 *     the freshly built table wire
 *   - run the type-specific validation (decode + expected-error checks,
 *     re-encode identity for encoder-backed wires, per-name semantic
 *     assertions for decode-only fixtures)
 * plus fixture-contract gates:
 *   - the committed manifest.json must be byte-identical to a fresh
 *     render of the table
 *   - the fixture directory must contain no stale .bin files beyond
 *     the table
 *
 * --generate [dir]: (re)write the .bin fixtures and manifest.json.
 * Regeneration must be byte-stable; CI diffs the tree afterwards.
 */

#include <dirent.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wt15_vectors.h"

#include "test_support.h"

#ifndef WT15_VECTOR_DIR
#define WT15_VECTOR_DIR "tests/vectors/wt15"
#endif

#define MANIFEST_CAP (192 * 1024)

static const char *type_name(wt15_vec_type_t t)
{
    switch (t) {
    case WT15_SETTINGS:      return "settings";
    case WT15_FRAME:         return "frame";
    case WT15_CAPSULE:       return "capsule";
    case WT15_PREAMBLE_BIDI: return "preamble_bidi";
    case WT15_PREAMBLE_UNI:  return "preamble_uni";
    case WT15_CONNECT_REQ:   return "connect_req";
    case WT15_CONNECT_RESP:  return "connect_resp";
    case WT15_SF_LIST:       return "sf_list";
    }
    return "?";
}

/* Append printf output to a bounded buffer; returns 0 on overflow. */
static int buf_appendf(char *dst, size_t cap, size_t *off,
                       const char *fmt, ...)
{
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(dst + *off, cap - *off, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= cap - *off)
        return 0;
    *off += (size_t)n;
    return 1;
}

/* Minimal JSON string escaping: quotes, backslashes, control chars. */
static int buf_append_json_str(char *dst, size_t cap, size_t *off,
                               const char *s)
{
    for (const char *p = s; *p != '\0'; p++) {
        unsigned char c = (unsigned char)*p;
        int ok;
        if (c == '"' || c == '\\')
            ok = buf_appendf(dst, cap, off, "\\%c", c);
        else if (c < 0x20)
            ok = buf_appendf(dst, cap, off, "\\u%04x", c);
        else
            ok = buf_appendf(dst, cap, off, "%c", c);
        if (!ok)
            return 0;
    }
    return 1;
}

/* Render the manifest into dst; returns rendered length, 0 on error. */
static size_t manifest_render(const wt15_vector_t *vec, size_t count,
                              char *dst, size_t cap)
{
    size_t off = 0;

    if (!buf_appendf(dst, cap, &off,
                     "{\n  \"draft\": \"wt-h3-15\",\n  \"vectors\": [\n"))
        return 0;
    for (size_t i = 0; i < count; i++) {
        if (!buf_appendf(dst, cap, &off,
                         "    {\n      \"file\": \"%s.bin\",\n"
                         "      \"type\": \"%s\",\n"
                         "      \"description\": \"",
                         vec[i].name, type_name(vec[i].type)))
            return 0;
        if (!buf_append_json_str(dst, cap, &off, vec[i].desc))
            return 0;
        if (!buf_appendf(dst, cap, &off,
                         "\",\n      \"expect_error\": %s,\n"
                         "      \"decode_only\": %s,\n"
                         "      \"wire_len\": %zu,\n"
                         "      \"wire_hex\": \"",
                         vec[i].expect_error ? "true" : "false",
                         vec[i].decode_only ? "true" : "false",
                         vec[i].wire_len))
            return 0;
        for (size_t b = 0; b < vec[i].wire_len; b++)
            if (!buf_appendf(dst, cap, &off, "%02x", vec[i].wire[b]))
                return 0;
        if (!buf_appendf(dst, cap, &off, "\"\n    }%s\n",
                         (i + 1 < count) ? "," : ""))
            return 0;
    }
    if (!buf_appendf(dst, cap, &off, "  ]\n}\n"))
        return 0;
    return off;
}

static int generate(const wt15_vector_t *vec, size_t count,
                    const char *dir)
{
    static char manifest[MANIFEST_CAP];
    char path[512];

    for (size_t i = 0; i < count; i++) {
        snprintf(path, sizeof(path), "%s/%s.bin", dir, vec[i].name);
        FILE *f = fopen(path, "wb");
        if (f == NULL || fwrite(vec[i].wire, 1, vec[i].wire_len, f) !=
                             vec[i].wire_len) {
            fprintf(stderr, "cannot write %s\n", path);
            if (f)
                fclose(f);
            return 1;
        }
        fclose(f);
    }

    size_t mlen = manifest_render(vec, count, manifest, sizeof(manifest));
    if (mlen == 0) {
        fprintf(stderr, "manifest render overflow\n");
        return 1;
    }
    snprintf(path, sizeof(path), "%s/manifest.json", dir);
    FILE *m = fopen(path, "wb");
    if (m == NULL || fwrite(manifest, 1, mlen, m) != mlen) {
        fprintf(stderr, "cannot write %s\n", path);
        if (m)
            fclose(m);
        return 1;
    }
    fclose(m);
    printf("generated %zu fixtures + manifest into %s\n", count, dir);
    return 0;
}

/* The committed manifest must equal a fresh render byte-for-byte. */
static int check_manifest(const wt15_vector_t *vec, size_t count,
                          const char *dir)
{
    static char rendered[MANIFEST_CAP];
    static char committed[MANIFEST_CAP];
    char path[512];

    size_t rlen = manifest_render(vec, count, rendered, sizeof(rendered));
    if (rlen == 0) {
        fprintf(stderr, "FAIL: manifest render overflow\n");
        return 1;
    }

    snprintf(path, sizeof(path), "%s/manifest.json", dir);
    FILE *m = fopen(path, "rb");
    if (m == NULL) {
        fprintf(stderr, "FAIL: missing %s (run --generate)\n", path);
        return 1;
    }
    size_t clen = fread(committed, 1, sizeof(committed), m);
    fclose(m);

    if (clen != rlen || memcmp(committed, rendered, rlen) != 0) {
        fprintf(stderr, "FAIL: committed manifest.json differs from a "
                        "fresh render (%zu vs %zu bytes)\n", clen, rlen);
        return 1;
    }
    return 0;
}

/* No stale .bin files: every .bin in the directory must be a table
 * vector. */
static int check_no_stale(const wt15_vector_t *vec, size_t count,
                          const char *dir)
{
    DIR *d = opendir(dir);
    struct dirent *e;
    int failures = 0;

    if (d == NULL) {
        fprintf(stderr, "FAIL: cannot open %s\n", dir);
        return 1;
    }
    while ((e = readdir(d)) != NULL) {
        size_t nlen = strlen(e->d_name);
        if (nlen < 4 || strcmp(e->d_name + nlen - 4, ".bin") != 0)
            continue;
        bool known = false;
        for (size_t i = 0; i < count && !known; i++) {
            size_t vlen = strlen(vec[i].name);
            known = (nlen == vlen + 4 &&
                     memcmp(e->d_name, vec[i].name, vlen) == 0);
        }
        if (!known) {
            fprintf(stderr, "FAIL: stale fixture %s/%s not in the vector "
                            "table\n", dir, e->d_name);
            failures++;
        }
    }
    closedir(d);
    return failures;
}

int main(int argc, char **argv)
{
    static wt15_vector_t vec[WT15_MAX_VECTORS];
    size_t count = wt15_vectors_build(vec, WT15_MAX_VECTORS);
    int failures = 0;

    if (argc >= 2 && strcmp(argv[1], "--generate") == 0)
        return generate(vec, count, argc >= 3 ? argv[2] : WT15_VECTOR_DIR);

    const char *dir = (argc >= 2) ? argv[1] : WT15_VECTOR_DIR;

    failures += check_manifest(vec, count, dir);
    failures += check_no_stale(vec, count, dir);

    for (size_t i = 0; i < count; i++) {
        char path[512];
        uint8_t file_buf[WT15_MAX_WIRE + 1];

        snprintf(path, sizeof(path), "%s/%s.bin", dir, vec[i].name);
        FILE *f = fopen(path, "rb");
        if (f == NULL) {
            fprintf(stderr, "FAIL[%s]: missing fixture %s (run "
                            "--generate)\n", vec[i].name, path);
            failures++;
            continue;
        }
        size_t file_len = fread(file_buf, 1, sizeof(file_buf), f);
        fclose(f);

        if (file_len != vec[i].wire_len ||
            memcmp(file_buf, vec[i].wire, file_len) != 0) {
            fprintf(stderr, "FAIL[%s]: fixture differs from built wire "
                            "(%zu vs %zu bytes)\n", vec[i].name, file_len,
                    vec[i].wire_len);
            failures++;
            continue;
        }

        failures += wt15_vector_validate(&vec[i], file_buf, file_len);
    }

    if (failures == 0)
        printf("PASS: test_vectors_wt15 (%zu fixtures, manifest OK, no "
               "stale files)\n", count);
    return failures;
}
