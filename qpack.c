/*
 * qpack.c — QPACK decoder for HTTP/3 (RFC 9204)
 *           Huffman decode uses RFC 7541 Appendix B canonical table.
 *           QPACK static table from RFC 9204 Appendix A.
 */
#include "headers/includes.h"
#include "headers/quic.h"

/* ── RFC 7541 Appendix B: Huffman Code Table ────────────────────────────────
 * Entry format: {code_value, code_bit_length}
 * code_value is the integer code (NOT MSB-aligned, just the integer).       */
const uint32_t huff_table[256][2] = {
    /*   0 */ {0x1ff8, 13},
    /*   1 */ {0x7fffd8, 23},
    /*   2 */ {0xfffffe2, 28},
    /*   3 */ {0xfffffe3, 28},
    /*   4 */ {0xfffffe4, 28},
    /*   5 */ {0xfffffe5, 28},
    /*   6 */ {0xfffffe6, 28},
    /*   7 */ {0xfffffe7, 28},
    /*   8 */ {0xfffffe8, 28},
    /*   9 */ {0xffffea, 24},
    /*  10 */ {0x3ffffffc, 30},
    /*  11 */ {0xfffffe9, 28},
    /*  12 */ {0xfffffea, 28},
    /*  13 */ {0x3ffffffd, 30},
    /*  14 */ {0xfffffeb, 28},
    /*  15 */ {0xfffffec, 28},
    /*  16 */ {0xfffffed, 28},
    /*  17 */ {0xfffffee, 28},
    /*  18 */ {0xfffffef, 28},
    /*  19 */ {0xffffff0, 28},
    /*  20 */ {0xffffff1, 28},
    /*  21 */ {0xffffff2, 28},
    /*  22 */ {0x3ffffffe, 30},
    /*  23 */ {0xffffff3, 28},
    /*  24 */ {0xffffff4, 28},
    /*  25 */ {0xffffff5, 28},
    /*  26 */ {0xffffff6, 28},
    /*  27 */ {0xffffff7, 28},
    /*  28 */ {0xffffff8, 28},
    /*  29 */ {0xffffff9, 28},
    /*  30 */ {0xffffffa, 28},
    /*  31 */ {0xffffffb, 28},
    /* ' ' */ {0x14, 6},
    /* '!' */ {0x3f8, 10},
    /* '"' */ {0x3f9, 10},
    /* '#' */ {0xffa, 12},
    /* '$' */ {0x1ff9, 13},
    /* '%' */ {0x15, 6},
    /* '&' */ {0xf8, 8},
    /* ''' */ {0x7fa, 11},
    /* '(' */ {0x3fa, 10},
    /* ')' */ {0x3fb, 10},
    /* '*' */ {0xf9, 8},
    /* '+' */ {0x7fb, 11},
    /* ',' */ {0xfa, 8},
    /* '-' */ {0x16, 6},
    /* '.' */ {0x17, 6},
    /* '/' */ {0x18, 6},
    /* '0' */ {0x0, 5},
    /* '1' */ {0x1, 5},
    /* '2' */ {0x2, 5},
    /* '3' */ {0x19, 6},
    /* '4' */ {0x1a, 6},
    /* '5' */ {0x1b, 6},
    /* '6' */ {0x1c, 6},
    /* '7' */ {0x1d, 6},
    /* '8' */ {0x1e, 6},
    /* '9' */ {0x1f, 6},
    /* ':' */ {0x5c, 7},
    /* ';' */ {0xfb, 8},
    /* '<' */ {0x7ffc, 15},
    /* '=' */ {0x20, 6},
    /* '>' */ {0xffb, 12},
    /* '?' */ {0x3fc, 10},
    /* '@' */ {0x1ffa, 13},
    /* 'A' */ {0x21, 6},
    /* 'B' */ {0x5d, 7},
    /* 'C' */ {0x5e, 7},
    /* 'D' */ {0x5f, 7},
    /* 'E' */ {0x60, 7},
    /* 'F' */ {0x61, 7},
    /* 'G' */ {0x62, 7},
    /* 'H' */ {0x63, 7},
    /* 'I' */ {0x64, 7},
    /* 'J' */ {0x65, 7},
    /* 'K' */ {0x66, 7},
    /* 'L' */ {0x67, 7},
    /* 'M' */ {0x68, 7},
    /* 'N' */ {0x69, 7},
    /* 'O' */ {0x6a, 7},
    /* 'P' */ {0x6b, 7},
    /* 'Q' */ {0x6c, 7},
    /* 'R' */ {0x6d, 7},
    /* 'S' */ {0x6e, 7},
    /* 'T' */ {0x6f, 7},
    /* 'U' */ {0x70, 7},
    /* 'V' */ {0x71, 7},
    /* 'W' */ {0x72, 7},
    /* 'X' */ {0xfc, 8},
    /* 'Y' */ {0x73, 7},
    /* 'Z' */ {0xfd, 8},
    /* '[' */ {0x1ffb, 13},
    /* '\' */ {0x7fff0, 19},
    /* ']' */ {0x1ffc, 13},
    /* '^' */ {0x3ffc, 14},
    /* '_' */ {0x22, 6},
    /* '`' */ {0x7ffd, 15},
    /* 'a' */ {0x3, 5},
    /* 'b' */ {0x23, 6},
    /* 'c' */ {0x4, 5},
    /* 'd' */ {0x24, 6},
    /* 'e' */ {0x5, 5},
    /* 'f' */ {0x25, 6},
    /* 'g' */ {0x26, 6},
    /* 'h' */ {0x27, 6},
    /* 'i' */ {0x6, 5},
    /* 'j' */ {0x74, 7},
    /* 'k' */ {0x75, 7},
    /* 'l' */ {0x28, 6},
    /* 'm' */ {0x29, 6},
    /* 'n' */ {0x2a, 6},
    /* 'o' */ {0x7, 5},
    /* 'p' */ {0x2b, 6},
    /* 'q' */ {0x76, 7},
    /* 'r' */ {0x2c, 6},
    /* 's' */ {0x8, 5},
    /* 't' */ {0x9, 5},
    /* 'u' */ {0x2d, 6},
    /* 'v' */ {0x77, 7},
    /* 'w' */ {0x78, 7},
    /* 'x' */ {0x79, 7},
    /* 'y' */ {0x7a, 7},
    /* 'z' */ {0x7b, 7},
    /* '{' */ {0x7ffe, 15},
    /* '|' */ {0x7fc, 11},
    /* '}' */ {0x3ffd, 14},
    /* '~' */ {0x1ffd, 13},
    /* 127 */ {0xffffffc, 28},
    /* 128 */ {0xfffe6, 20},
    /* 129 */ {0x3fffd2, 22},
    /* 130 */ {0xfffe7, 20},
    /* 131 */ {0xfffe8, 20},
    /* 132 */ {0x3fffd3, 22},
    /* 133 */ {0x3fffd4, 22},
    /* 134 */ {0x3fffd5, 22},
    /* 135 */ {0x7fffd9, 23},
    /* 136 */ {0x3fffd6, 22},
    /* 137 */ {0x7fffda, 23},
    /* 138 */ {0x7fffdb, 23},
    /* 139 */ {0x7fffdc, 23},
    /* 140 */ {0x7fffdd, 23},
    /* 141 */ {0x7fffde, 23},
    /* 142 */ {0xffffeb, 24},
    /* 143 */ {0x7fffdf, 23},
    /* 144 */ {0xffffec, 24},
    /* 145 */ {0xffffed, 24},
    /* 146 */ {0x3fffd7, 22},
    /* 147 */ {0x7fffe0, 23},
    /* 148 */ {0xffffee, 24},
    /* 149 */ {0x7fffe1, 23},
    /* 150 */ {0x7fffe2, 23},
    /* 151 */ {0x7fffe3, 23},
    /* 152 */ {0x7fffe4, 23},
    /* 153 */ {0x1fffdc, 21},
    /* 154 */ {0x3fffd8, 22},
    /* 155 */ {0x7fffe5, 23},
    /* 156 */ {0x3fffd9, 22},
    /* 157 */ {0x7fffe6, 23},
    /* 158 */ {0x7fffe7, 23},
    /* 159 */ {0xffffef, 24},
    /* 160 */ {0x3fffda, 22},
    /* 161 */ {0x1fffdd, 21},
    /* 162 */ {0xfffe9, 20},
    /* 163 */ {0x3fffdb, 22},
    /* 164 */ {0x3fffdc, 22},
    /* 165 */ {0x7fffe8, 23},
    /* 166 */ {0x7fffe9, 23},
    /* 167 */ {0x1fffde, 21},
    /* 168 */ {0x7fffea, 23},
    /* 169 */ {0x3fffdd, 22},
    /* 170 */ {0x3fffde, 22},
    /* 171 */ {0xfffff0, 24},
    /* 172 */ {0x1fffdf, 21},
    /* 173 */ {0x3fffdf, 22},
    /* 174 */ {0x7fffeb, 23},
    /* 175 */ {0x7fffec, 23},
    /* 176 */ {0x1fffe0, 21},
    /* 177 */ {0x1fffe1, 21},
    /* 178 */ {0x3fffe0, 22},
    /* 179 */ {0x1fffe2, 21},
    /* 180 */ {0x7fffed, 23},
    /* 181 */ {0x3fffe1, 22},
    /* 182 */ {0x7fffee, 23},
    /* 183 */ {0x7fffef, 23},
    /* 184 */ {0xfffea, 20},
    /* 185 */ {0x3fffe2, 22},
    /* 186 */ {0x3fffe3, 22},
    /* 187 */ {0x3fffe4, 22},
    /* 188 */ {0x7ffff0, 23},
    /* 189 */ {0x3fffe5, 22},
    /* 190 */ {0x3fffe6, 22},
    /* 191 */ {0x7ffff1, 23},
    /* 192 */ {0x3ffffe0, 26},
    /* 193 */ {0x3ffffe1, 26},
    /* 194 */ {0xfffeb, 20},
    /* 195 */ {0x7fff1, 19},
    /* 196 */ {0x3fffe7, 22},
    /* 197 */ {0x7ffff2, 23},
    /* 198 */ {0x3fffe8, 22},
    /* 199 */ {0x1ffffec, 25},
    /* 200 */ {0x3ffffe2, 26},
    /* 201 */ {0x3ffffe3, 26},
    /* 202 */ {0x3ffffe4, 26},
    /* 203 */ {0x7ffffde, 27},
    /* 204 */ {0x7ffffdf, 27},
    /* 205 */ {0x3ffffe5, 26},
    /* 206 */ {0xfffff1, 24},
    /* 207 */ {0x1ffffed, 25},
    /* 208 */ {0x7fff2, 19},
    /* 209 */ {0x1fffe3, 21},
    /* 210 */ {0x3ffffe6, 26},
    /* 211 */ {0x7ffffe0, 27},
    /* 212 */ {0x7ffffe1, 27},
    /* 213 */ {0x3ffffe7, 26},
    /* 214 */ {0x7ffffe2, 27},
    /* 215 */ {0xfffff2, 24},
    /* 216 */ {0x1fffe4, 21},
    /* 217 */ {0x1fffe5, 21},
    /* 218 */ {0x3ffffe8, 26},
    /* 219 */ {0x3ffffe9, 26},
    /* 220 */ {0xffffffd, 28},
    /* 221 */ {0x7ffffe3, 27},
    /* 222 */ {0x7ffffe4, 27},
    /* 223 */ {0x7ffffe5, 27},
    /* 224 */ {0xfffec, 20},
    /* 225 */ {0xfffff3, 24},
    /* 226 */ {0xfffed, 20},
    /* 227 */ {0x1fffe6, 21},
    /* 228 */ {0x3fffe9, 22},
    /* 229 */ {0x1fffe7, 21},
    /* 230 */ {0x1fffe8, 21},
    /* 231 */ {0x7ffff3, 23},
    /* 232 */ {0x3fffea, 22},
    /* 233 */ {0x3fffeb, 22},
    /* 234 */ {0x1ffffee, 25},
    /* 235 */ {0x1ffffef, 25},
    /* 236 */ {0xfffff4, 24},
    /* 237 */ {0xfffff5, 24},
    /* 238 */ {0x3ffffea, 26},
    /* 239 */ {0x7ffff4, 23},
    /* 240 */ {0x3ffffeb, 26},
    /* 241 */ {0x7ffffe6, 27},
    /* 242 */ {0x3ffffec, 26},
    /* 243 */ {0x3ffffed, 26},
    /* 244 */ {0x7ffffe7, 27},
    /* 245 */ {0x7ffffe8, 27},
    /* 246 */ {0x7ffffe9, 27},
    /* 247 */ {0x7ffffea, 27},
    /* 248 */ {0x7ffffeb, 27},
    /* 249 */ {0xffffffe, 28},
    /* 250 */ {0x7ffffec, 27},
    /* 251 */ {0x7ffffed, 27},
    /* 252 */ {0x7ffffee, 27},
    /* 253 */ {0x7ffffef, 27},
    /* 254 */ {0x7fffff0, 27},
    /* 255 */ {0x3ffffee, 26}
};

/* ── Huffman decode (bit-by-bit linear scan over the 256-symbol table) ───── */
void huffman_decode(const uint8_t *in, int len, char *out, int max_out) {
    int out_pos = 0;
    uint64_t acc = 0;
    int acc_bits = 0;
    int in_pos = 0;

    while (in_pos < len || acc_bits > 0) {
        /* Load bytes into the accumulator as long as there is space and input */
        while (acc_bits <= 55 && in_pos < len) {
            acc = (acc << 8) | in[in_pos++];
            acc_bits += 8;
        }

        int matched = 0;
        for (int sym = 0; sym < 256; sym++) {
            int clen = (int)huff_table[sym][1];
            if (clen > acc_bits) continue;
            uint64_t code = huff_table[sym][0];
            uint64_t top = (acc >> (acc_bits - clen)) & ((1ULL << clen) - 1);
            if (top == code) {
                if (out_pos < max_out - 1) {
                    out[out_pos++] = (char)sym;
                }
                acc_bits -= clen;
                /* Safely mask the accumulator to keep only the bottom acc_bits */
                if (acc_bits >= 64) {
                    acc = 0;
                } else {
                    acc &= (1ULL << acc_bits) - 1;
                }
                matched = 1;
                break;
            }
        }

        if (!matched) {
            break;
        }
    }
    out[out_pos] = '\0';
}

/* ── QPACK static table (RFC 9204 Appendix A, indices 0–98) ──────────────── */
const char *qpack_static[] = {
    /* 0  */ ":authority",                   "",
    /* 1  */ ":path",                        "/",
    /* 2  */ "age",                          "0",
    /* 3  */ "content-disposition",          "",
    /* 4  */ "content-length",               "0",
    /* 5  */ "cookie",                       "",
    /* 6  */ "date",                         "",
    /* 7  */ "etag",                         "",
    /* 8  */ "if-modified-since",            "",
    /* 9  */ "if-none-match",                "",
    /* 10 */ "last-modified",                "",
    /* 11 */ "link",                         "",
    /* 12 */ "location",                     "",
    /* 13 */ "referer",                      "",
    /* 14 */ "set-cookie",                   "",
    /* 15 */ ":method",                      "CONNECT",
    /* 16 */ ":method",                      "DELETE",
    /* 17 */ ":method",                      "GET",
    /* 18 */ ":method",                      "HEAD",
    /* 19 */ ":method",                      "OPTIONS",
    /* 20 */ ":method",                      "POST",
    /* 21 */ ":method",                      "PUT",
    /* 22 */ ":scheme",                      "http",
    /* 23 */ ":scheme",                      "https",
    /* 24 */ ":status",                      "103",
    /* 25 */ ":status",                      "200",
    /* 26 */ ":status",                      "304",
    /* 27 */ ":status",                      "404",
    /* 28 */ ":status",                      "503",
    /* 29 */ "accept",                       "*/*",
    /* 30 */ "accept",                       "application/dns-message",
    /* 31 */ "accept-encoding",              "gzip, deflate, br",
    /* 32 */ "accept-ranges",                "bytes",
    /* 33 */ "access-control-allow-headers", "cache-control",
    /* 34 */ "access-control-allow-headers", "content-type",
    /* 35 */ "access-control-allow-origin",  "*",
    /* 36 */ "cache-control",                "max-age=0",
    /* 37 */ "cache-control",                "max-age=2592000",
    /* 38 */ "cache-control",                "max-age=604800",
    /* 39 */ "cache-control",                "no-cache",
    /* 40 */ "cache-control",                "no-store",
    /* 41 */ "cache-control",                "public, max-age=31536000",
    /* 42 */ "content-encoding",             "br",
    /* 43 */ "content-encoding",             "gzip",
    /* 44 */ "content-type",                 "application/dns-message",
    /* 45 */ "content-type",                 "application/javascript",
    /* 46 */ "content-type",                 "application/json",
    /* 47 */ "content-type",                 "application/x-www-form-urlencoded",
    /* 48 */ "content-type",                 "image/gif",
    /* 49 */ "content-type",                 "image/jpeg",
    /* 50 */ "content-type",                 "image/png",
    /* 51 */ "content-type",                 "text/css",
    /* 52 */ "content-type",                 "text/html; charset=utf-8",
    /* 53 */ "content-type",                 "text/plain",
    /* 54 */ "content-type",                 "text/plain;charset=utf-8",
    /* 55 */ "range",                        "bytes=0-",
    /* 56 */ "strict-transport-security",    "max-age=31536000",
    /* 57 */ "strict-transport-security",    "max-age=31536000; includesubdomains",
    /* 58 */ "strict-transport-security",    "max-age=31536000; includesubdomains; preload",
    /* 59 */ "vary",                         "accept-encoding",
    /* 60 */ "vary",                         "origin",
    /* 61 */ "x-content-type-options",       "nosniff",
    /* 62 */ "x-xss-protection",             "1; mode=block",
    /* 63 */ ":status",                      "100",
    /* 64 */ ":status",                      "204",
    /* 65 */ ":status",                      "206",
    /* 66 */ ":status",                      "302",
    /* 67 */ ":status",                      "400",
    /* 68 */ ":status",                      "403",
    /* 69 */ ":status",                      "421",
    /* 70 */ ":status",                      "425",
    /* 71 */ ":status",                      "500",
    /* 72 */ "accept-language",              "",
    /* 73 */ "access-control-allow-credentials","FALSE",
    /* 74 */ "access-control-allow-credentials","TRUE",
    /* 75 */ "access-control-allow-headers", "*",
    /* 76 */ "access-control-allow-methods", "get",
    /* 77 */ "access-control-allow-methods", "get, post, options",
    /* 78 */ "access-control-allow-methods", "options",
    /* 79 */ "access-control-expose-headers","content-length",
    /* 80 */ "access-control-request-headers","content-type",
    /* 81 */ "access-control-request-method","get",
    /* 82 */ "access-control-request-method","post",
    /* 83 */ "alt-svc",                      "clear",
    /* 84 */ "authorization",                "",
    /* 85 */ "content-security-policy",      "script-src 'none'; object-src 'none'; base-uri 'none'",
    /* 86 */ "early-data",                   "1",
    /* 87 */ "expect-ct",                    "",
    /* 88 */ "forwarded",                    "",
    /* 89 */ "if-range",                     "",
    /* 90 */ "origin",                       "",
    /* 91 */ "purpose",                      "prefetch",
    /* 92 */ "server",                       "",
    /* 93 */ "timing-allow-origin",          "*",
    /* 94 */ "upgrade-insecure-requests",    "1",
    /* 95 */ "user-agent",                   "",
    /* 96 */ "x-forwarded-for",              "",
    /* 97 */ "x-frame-options",              "deny",
    /* 98 */ "x-frame-options",              "sameorigin",
    NULL
};
#define QPACK_STATIC_MAX 99

/* ── print_qpack_val ─────────────────────────────────────────────────────── */
void print_qpack_val(const uint8_t *data, int len, int huff) {
    if (huff) {
        char buf[512];
        huffman_decode(data, len, buf, sizeof(buf));
        printf("%s", buf);
    } else {
        for (int i = 0; i < len && i < 511; i++) {
            uint8_t c = data[i];
            printf("%c", (c >= 32 && c <= 126) ? c : '?');
        }
    }
}

/* Read a QPACK integer prefix-encoded varint.
 * prefix_bits = number of bits available for the integer in the first byte.
 * Returns integer value, advances *off. */
static int qpack_int(const uint8_t *data, int len, int *off, int prefix_bits) {
    int mask = (1 << prefix_bits) - 1;
    int val = data[(*off)++] & mask;
    if (val < mask) return val;
    int m = 0;
    while (*off < len) {
        int b = data[(*off)++];
        val += (b & 0x7F) << m;
        m += 7;
        if (!(b & 0x80)) break;
    }
    return val;
}

int qpack_get_dynamic_entry(quic_conn *conn, uint64_t idx, const char **name, const char **value) {
    if (conn->qpack_dyn.insert_count == 0) return 0;
    if (idx >= conn->qpack_dyn.insert_count) return 0;
    uint64_t abs_idx = conn->qpack_dyn.insert_count - 1 - idx;
    uint64_t oldest_idx = conn->qpack_dyn.insert_count - conn->qpack_dyn.count;
    if (abs_idx < oldest_idx || abs_idx >= conn->qpack_dyn.insert_count) return 0;
    uint64_t dyn_pos = (conn->qpack_dyn.tail + (abs_idx - oldest_idx)) % QPACK_DYNAMIC_MAX;
    *name = conn->qpack_dyn.entries[dyn_pos].name;
    *value = conn->qpack_dyn.entries[dyn_pos].value;
    return 1;
}

void qpack_add_dynamic_entry(quic_conn *conn, const char *name, const char *value) {
    uint64_t tail = conn->qpack_dyn.tail;
    uint64_t count = conn->qpack_dyn.count;
    uint64_t insert_pos = (tail + count) % QPACK_DYNAMIC_MAX;
    if (count == QPACK_DYNAMIC_MAX) {
        conn->qpack_dyn.tail = (tail + 1) % QPACK_DYNAMIC_MAX;
    } else {
        conn->qpack_dyn.count++;
    }
    strncpy(conn->qpack_dyn.entries[insert_pos].name, name, 255);
    conn->qpack_dyn.entries[insert_pos].name[255] = '\0';
    strncpy(conn->qpack_dyn.entries[insert_pos].value, value, 255);
    conn->qpack_dyn.entries[insert_pos].value[255] = '\0';
    conn->qpack_dyn.insert_count++;
    printf("[qpack-dyn] Added entry %llu: %s = %s\n",
               (unsigned long long)(conn->qpack_dyn.insert_count - 1), name, value);
}

void qpack_parse_encoder_instructions(quic_conn *conn, const uint8_t *data, int len) {
    int off = 0;
    while (off < len) {
        uint8_t b = data[off];
        if (b & 0x80) {
            /* ── Insert with Name Reference (1Txxxxxx) */
            int T = (b >> 6) & 1;
            int idx = qpack_int(data, len, &off, 6);
            if (off >= len) break;
            int vhuff = (data[off] >> 7) & 1;
            int vlen = qpack_int(data, len, &off, 7);
            if (off + vlen > len) break;
            char val_str[256];
            if (vhuff) {
                huffman_decode(data + off, vlen, val_str, sizeof(val_str));
            } else {
                int i; for (i = 0; i < vlen && i < 255; i++) val_str[i] = data[off + i];
                val_str[i] = '\0';
            }
            off += vlen;
            const char *name = "";
            if (T) {
                if (idx < QPACK_STATIC_MAX) name = qpack_static[idx * 2];
            } else {
                const char *unused_val;
                qpack_get_dynamic_entry(conn, idx, &name, &unused_val);
            }
            if (name && name[0] != '\0') {
                qpack_add_dynamic_entry(conn, name, val_str);
            }
        } else if ((b & 0xC0) == 0x40) {
            /* ── Insert with Literal Name (01xxxxxx) */
            int nhuff = (b >> 5) & 1;
            int nlen = qpack_int(data, len, &off, 5);
            if (off + nlen > len) break;
            char name_str[256];
            if (nhuff) {
                huffman_decode(data + off, nlen, name_str, sizeof(name_str));
            } else {
                int i; for (i = 0; i < nlen && i < 255; i++) name_str[i] = data[off + i];
                name_str[i] = '\0';
            }
            off += nlen;
            if (off >= len) break;
            int vhuff = (data[off] >> 7) & 1;
            int vlen = qpack_int(data, len, &off, 7);
            if (off + vlen > len) break;
            char val_str[256];
            if (vhuff) {
                huffman_decode(data + off, vlen, val_str, sizeof(val_str));
            } else {
                int i; for (i = 0; i < vlen && i < 255; i++) val_str[i] = data[off + i];
                val_str[i] = '\0';
            }
            off += vlen;
            qpack_add_dynamic_entry(conn, name_str, val_str);
        } else if ((b & 0xE0) == 0x20) {
            /* ── Set Dynamic Table Capacity (001xxxxx) */
            int cap = qpack_int(data, len, &off, 5);
            (void)cap;
        } else if ((b & 0xE0) == 0x00) {
            /* ── Duplicate (000xxxxx) */
            int idx = qpack_int(data, len, &off, 5);
            const char *name = "";
            const char *value = "";
            if (qpack_get_dynamic_entry(conn, idx, &name, &value)) {
                qpack_add_dynamic_entry(conn, name, value);
            }
        } else {
            off++;
        }
    }
}

/* ── decode_qpack_headers ────────────────────────────────────────────────── */
void decode_qpack_headers(quic_conn *conn, const uint8_t *data, int len) {
    if (len < 2) return;
    int off = 0;

    /* Required Insert Count (prefix 8) */
    qpack_int(data, len, &off, 8);
    /* S bit + Delta Base (prefix 7) */
    if (off < len) qpack_int(data, len, &off, 7);

    while (off < len) {
        uint8_t b = data[off];

        if (b & 0x80) {
            /* ── Indexed Field Line (T=1: static, T=0: dynamic) (1Txxxxxx) */
            int T = (b >> 6) & 1;
            int idx = qpack_int(data, len, &off, 6);
            if (T) {
                if (idx < QPACK_STATIC_MAX) {
                    printf("  %s: %s\n", qpack_static[idx * 2], qpack_static[idx * 2 + 1]);
                }
            } else {
                const char *name = "", *value = "";
                if (qpack_get_dynamic_entry(conn, idx, &name, &value)) {
                    printf("  %s: %s\n", name, value);
                } else {
                    printf("  [dynamic#%d]\n", idx);
                }
            }
        } else if ((b & 0xF0) == 0x10) {
            /* ── Indexed Field Line with Post-Base Index (0001xxxx) */
            int idx = qpack_int(data, len, &off, 4);
            printf("  [postbase#%d]\n", idx);
        } else if ((b & 0xC0) == 0x40) {
            /* ── Literal Field Line with Name Reference (01NTxxxx) */
            int T = (b >> 4) & 1;
            int idx = qpack_int(data, len, &off, 4);
            if (off < len) {
                int vhuff = (data[off] >> 7) & 1;
                int vlen = qpack_int(data, len, &off, 7);
                if (off + vlen <= len) {
                    if (T) {
                        if (idx < QPACK_STATIC_MAX) printf("  %s: ", qpack_static[idx * 2]);
                        else printf("  [static#%d]: ", idx);
                    } else {
                        const char *name = "", *value = "";
                        if (qpack_get_dynamic_entry(conn, idx, &name, &value)) printf("  %s: ", name);
                        else printf("  [dynamic#%d]: ", idx);
                    }
                    print_qpack_val(data + off, vlen, vhuff);
                    printf("\n");
                    off += vlen;
                }
            }
        } else if ((b & 0xF8) == 0x08) {
            /* ── Literal Field Line with Post-Base Name Reference (00001Nxx) */
            int idx = qpack_int(data, len, &off, 2);
            if (off < len) {
                int vhuff = (data[off] >> 7) & 1;
                int vlen = qpack_int(data, len, &off, 7);
                if (off + vlen <= len) {
                    printf("  [postbase#%d]: ", idx);
                    print_qpack_val(data + off, vlen, vhuff);
                    printf("\n");
                    off += vlen;
                }
            }
        } else if ((b & 0xE0) == 0x20) {
            /* ── Literal Field Line with Literal Name (001Nxxxx) */
            int nhuff = (b >> 3) & 1;
            int nlen = qpack_int(data, len, &off, 3);
            if (off + nlen <= len) {
                char name[128];
                if (nhuff) {
                    huffman_decode(data + off, nlen, name, sizeof(name));
                } else {
                    int i; for (i = 0; i < nlen && i < 127; i++) name[i] = data[off + i];
                    name[i] = '\0';
                }
                off += nlen;
                if (off < len) {
                    int vhuff = (data[off] >> 7) & 1;
                    int vlen = qpack_int(data, len, &off, 7);
                    if (off + vlen <= len) {
                        printf("  %s: ", name);
                        print_qpack_val(data + off, vlen, vhuff);
                        printf("\n");
                        off += vlen;
                    }
                }
            }
        } else {
            off++;
        }
    }
}
