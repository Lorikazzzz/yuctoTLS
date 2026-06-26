#include "headers/nanotls.h"
#include "headers/includes.h"
#include "headers/crypto.h"
#include "headers/quic.h"

static __thread char current_alpn[32] = "\x08http/1.1";
static __thread int current_alpn_len = 9;
static __thread int current_mode_h2 = 0;

static __thread int current_proto_tls13 = 1;
static __thread int current_proto_tls12 = 1;
static __thread int current_proto_quic = 1;

/* ── TLS 1.3 session-ticket cache (per host) for PSK resumption ─────────── */
#define TLS_TICKET_CACHE_SIZE 16
static tls_session_ticket g_ticket_cache[TLS_TICKET_CACHE_SIZE];

static uint64_t now_ms(void) {
    struct timeval tv; gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000ULL + tv.tv_usec / 1000ULL;
}

static tls_session_ticket *ticket_find(const char *host) {
    for (int i = 0; i < TLS_TICKET_CACHE_SIZE; i++)
        if (g_ticket_cache[i].valid && strcmp(g_ticket_cache[i].host, host) == 0)
            return &g_ticket_cache[i];
    return NULL;
}

static tls_session_ticket *ticket_slot(const char *host) {
    tls_session_ticket *t = ticket_find(host);
    if (t) return t;
    for (int i = 0; i < TLS_TICKET_CACHE_SIZE; i++)
        if (!g_ticket_cache[i].valid) return &g_ticket_cache[i];
    return &g_ticket_cache[0]; /* evict slot 0 if full */
}

/* Parse a TLS 1.3 NewSessionTicket handshake message (type 0x04) and store a
 * resumption PSK for the connection's host. msg points at the handshake header. */
static void tls13_store_ticket(nanotls_conn *conn, const uint8_t *msg, int msg_len) {
    if (!conn->resumption_ms_valid || !conn->sni_host) return;
    if (msg_len < 4 || msg[0] != 0x14 /*HS_FINISHED? no*/) { /* type checked by caller */ }
    /* Body layout (RFC 8446 4.6.1):
       uint32 ticket_lifetime; uint32 ticket_age_add; opaque ticket_nonce<0..255>;
       opaque ticket<1..2^16-1>; Extension extensions<0..2^16-2>;  */
    int p = 4; /* skip handshake header (type + 3-byte length) */
    if (p + 9 > msg_len) return;
    uint32_t lifetime = (msg[p]<<24)|(msg[p+1]<<16)|(msg[p+2]<<8)|msg[p+3]; p += 4;
    uint32_t age_add  = (msg[p]<<24)|(msg[p+1]<<16)|(msg[p+2]<<8)|msg[p+3]; p += 4;
    int nonce_len = msg[p++];
    if (p + nonce_len + 2 > msg_len) return;
    const uint8_t *nonce = msg + p; p += nonce_len;
    int ticket_len = (msg[p]<<8)|msg[p+1]; p += 2;
    if (ticket_len < 1 || ticket_len > 2048 || p + ticket_len > msg_len) return;
    const uint8_t *ticket = msg + p;

    int hlen = (conn->cipher_suite == 0x1302) ? 48 : 32;
    /* PSK = HKDF-Expand-Label(resumption_master_secret, "resumption", nonce, L) */
    uint8_t psk[48];
    {
        uint8_t info[64]; int il = 0;
        info[il++] = (uint8_t)(hlen >> 8); info[il++] = (uint8_t)(hlen & 0xFF);
        const char *lbl = "tls13 resumption";
        info[il++] = (uint8_t)strlen(lbl);
        memcpy(info + il, lbl, strlen(lbl)); il += (int)strlen(lbl);
        info[il++] = (uint8_t)nonce_len;
        if (nonce_len) { memcpy(info + il, nonce, nonce_len); il += nonce_len; }
        if (conn->cipher_suite == 0x1302)
            hkdf_sha384_expand(conn->resumption_master_secret, info, il, psk, hlen);
        else
            hkdf_sha256_expand(conn->resumption_master_secret, info, il, psk, hlen);
    }

    tls_session_ticket *slot = ticket_slot(conn->sni_host);
    memset(slot, 0, sizeof(*slot));
    strncpy(slot->host, conn->sni_host, sizeof(slot->host) - 1);
    slot->cipher_suite   = conn->cipher_suite;
    slot->psk_len        = hlen;
    memcpy(slot->psk, psk, hlen);
    memcpy(slot->ticket, ticket, ticket_len);
    slot->ticket_len     = ticket_len;
    slot->ticket_age_add = age_add;
    slot->ticket_lifetime = lifetime;
    slot->obtained_ms    = now_ms();
    slot->valid          = 1;
#ifdef DEBUG
    debug("[nanotls] Stored session ticket for %s (%d-byte ticket, PSK %d bytes)\n",
          conn->sni_host, ticket_len, hlen);
#endif
}


#define HS_CLIENT_HELLO      0x01
#define HS_SERVER_HELLO      0x02
#define HS_ENCRYPTED_EXT     0x08
#define HS_CERTIFICATE       0x0b
#define HS_CERT_VERIFY       0x0f
#define HS_FINISHED          0x14

int tls13_client_hello(uint8_t *ch, const char *host, const uint8_t *dcid, int dcid_len, const uint8_t *scid, int scid_len, const uint8_t *pub_key) {
    int off = 0;
    ch[off++] = 0x01; // ClientHello
    int len_pos = off; off += 3;
    ch[off++] = 0x03; ch[off++] = 0x03; // TLS 1.2 legacy version
    bot_prng_generate_block(ch + off, 32); off += 32; // Random
    ch[off++] = 0; // Legacy Session ID
    
    // Cipher Suites
    ch[off++] = 0; ch[off++] = 0x06;
    ch[off++] = 0x13; ch[off++] = 0x01; // TLS_AES_128_GCM_SHA256
    ch[off++] = 0x13; ch[off++] = 0x02; // TLS_AES_256_GCM_SHA384
    ch[off++] = 0x13; ch[off++] = 0x03; // TLS_CHACHA20_POLY1305_SHA256
    
    ch[off++] = 1; ch[off++] = 0; // Legacy Compression Methods
    int ext_len_pos = off; off += 2;

    // 1. GREASE (0x1a1a)
    ch[off++] = 0x1a; ch[off++] = 0x1a; ch[off++] = 0; ch[off++] = 0;

    // 2. server_name
    ch[off++] = 0x00; ch[off++] = 0x00;
    int sni_len = strlen(host);
    ch[off++] = (uint8_t)((sni_len+5)>>8); ch[off++] = (uint8_t)((sni_len+5)&0xFF);
    ch[off++] = (uint8_t)((sni_len+3)>>8); ch[off++] = (uint8_t)((sni_len+3)&0xFF);
    ch[off++] = 0; // host_name
    ch[off++] = (uint8_t)(sni_len>>8); ch[off++] = (uint8_t)(sni_len&0xFF);
    memcpy(ch + off, host, sni_len); off += sni_len;

    // 3. supported_groups (x25519, p256, p384)
    ch[off++] = 0x00; ch[off++] = 0x0a;
    ch[off++] = 0; ch[off++] = 8;
    ch[off++] = 0; ch[off++] = 6;
    ch[off++] = 0; ch[off++] = 0x1d; // x25519
    ch[off++] = 0; ch[off++] = 0x17; // p256
    ch[off++] = 0; ch[off++] = 0x18; // p384

    // 4. signature_algorithms
    ch[off++] = 0x00; ch[off++] = 0x0d;
    ch[off++] = 0; ch[off++] = 8;
    ch[off++] = 0; ch[off++] = 6;
    ch[off++] = 0x04; ch[off++] = 0x03; // ecdsa_secp256r1_sha256
    ch[off++] = 0x08; ch[off++] = 0x04; // rsa_pss_rsae_sha256
    ch[off++] = 0x04; ch[off++] = 0x01; // rsa_pkcs1_sha256

    // 5. ALPN (h3)
    ch[off++] = 0x00; ch[off++] = 0x10;
    ch[off++] = 0; ch[off++] = 5;
    ch[off++] = 0; ch[off++] = 3;
    ch[off++] = 2; ch[off++] = 'h'; ch[off++] = '3';

    // 6. key_share (x25519)
    ch[off++] = 0x00; ch[off++] = 0x33;
    ch[off++] = 0; ch[off++] = 38;
    ch[off++] = 0; ch[off++] = 36;
    ch[off++] = 0; ch[off++] = 0x1d; // x25519
    ch[off++] = 0; ch[off++] = 32;
    memcpy(ch + off, pub_key, 32); off += 32;

    // 7. psk_key_exchange_modes
    ch[off++] = 0x00; ch[off++] = 0x2d;
    ch[off++] = 0; ch[off++] = 2;
    ch[off++] = 1; ch[off++] = 1; // psk_dhe_ke

    // 8. supported_versions
    ch[off++] = 0x00; ch[off++] = 0x2b;
    ch[off++] = 0; ch[off++] = 3;
    ch[off++] = 2; ch[off++] = 0x03; ch[off++] = 0x04; // TLS 1.3

    // 9. quic_transport_parameters (0x39) — matched to Chrome 114 from pcap analysis
    ch[off++] = 0x00; ch[off++] = 0x39;
    int qtp_len_pos = off; off += 2;
    // max_idle_timeout: 10000ms (2-byte varint 0x6710). 
    // 30ms (0x401e) was too short for Facebook. 4-byte varint broke Akamai's strict JA4 fingerprint length.
    ch[off++] = 0x01; ch[off++] = 2; ch[off++] = 0x67; ch[off++] = 0x10;
    // max_udp_payload_size: 1472 (0x45c0 from pcap)
    ch[off++] = 0x03; ch[off++] = 2; ch[off++] = 0x45; ch[off++] = 0xc0;
    // initial_max_data: 15728640 (0x80f00000 from pcap)
    ch[off++] = 0x04; ch[off++] = 4; ch[off++] = 0x80; ch[off++] = 0xf0; ch[off++] = 0x00; ch[off++] = 0x00;
    // initial_max_stream_data_bidi_local: 6291456 (6MB, 0x80600000)
    ch[off++] = 0x05; ch[off++] = 4; ch[off++] = 0x80; ch[off++] = 0x60; ch[off++] = 0x00; ch[off++] = 0x00;
    // initial_max_stream_data_bidi_remote: 6291456 (6MB)
    ch[off++] = 0x06; ch[off++] = 4; ch[off++] = 0x80; ch[off++] = 0x60; ch[off++] = 0x00; ch[off++] = 0x00;
    // initial_max_stream_data_uni: 6291456 (6MB, 0x80600000)
    ch[off++] = 0x07; ch[off++] = 4; ch[off++] = 0x80; ch[off++] = 0x60; ch[off++] = 0x00; ch[off++] = 0x00;
    // initial_max_streams_bidi: 100 (0x4064)
    ch[off++] = 0x08; ch[off++] = 2; ch[off++] = 0x40; ch[off++] = 0x64;
    // initial_max_streams_uni: 100 (0x4064)
    ch[off++] = 0x09; ch[off++] = 2; ch[off++] = 0x40; ch[off++] = 0x64;
    // active_connection_id_limit: 8
    ch[off++] = 0x0e; ch[off++] = 1; ch[off++] = 0x08;
    // initial_source_connection_id: our SCID (non-empty — empty causes Retry which we don't handle)
    ch[off++] = 0x0f; ch[off++] = (uint8_t)scid_len; memcpy(ch + off, scid, scid_len); off += scid_len;
    // GREASE TP: properly encoded 2-byte varint ID 0x1a1a, len=0
    ch[off++] = 0x40 | (0x1a1a >> 8); ch[off++] = (0x1a1a & 0xFF); ch[off++] = 0x00;

    int qtp_len = off - qtp_len_pos - 2;
    ch[qtp_len_pos] = (qtp_len >> 8) & 0xFF; ch[qtp_len_pos+1] = qtp_len & 0xFF;

    // 10. Padding to reach JA4-like size
    int pad_target = 512;
    if (off < pad_target) {
        ch[off++] = 0x00; ch[off++] = 0x15; // padding
        int pad_len = pad_target - off - 2;
        ch[off++] = (pad_len >> 8) & 0xFF; ch[off++] = pad_len & 0xFF;
        memset(ch + off, 0, pad_len); off += pad_len;
    }

    int ext_len = off - ext_len_pos - 2;
    ch[ext_len_pos] = (uint8_t)(ext_len >> 8); ch[ext_len_pos+1] = (uint8_t)(ext_len & 0xFF);
    int total_len = off - len_pos - 3;
    ch[len_pos] = (total_len >> 16) & 0xFF;
    ch[len_pos+1] = (total_len >> 8) & 0xFF;
    ch[len_pos+2] = total_len & 0xFF;
    return off;
}




void tls13_expand_label(const uint8_t *secret, const char *label, const uint8_t *hash, size_t hlen, uint8_t *out, int out_len) {
    uint8_t info[128]; int ilen = 0;
    info[ilen++] = (uint8_t)(out_len >> 8);
    info[ilen++] = (uint8_t)(out_len & 0xFF);
    int llen = (int)strlen(label); info[ilen++] = (uint8_t)(6 + llen);
    memcpy(info + ilen, "tls13 ", 6); ilen += 6;
    memcpy(info + ilen, label, llen); ilen += llen;
    info[ilen++] = (uint8_t)hlen; if (hlen > 0) { memcpy(info + ilen, hash, hlen); ilen += (int)hlen; }
    hkdf_sha256_expand(secret, info, (size_t)ilen, out, (size_t)out_len);
}

void tls13_expand_label_cs(uint16_t cipher_suite, const uint8_t *secret, const char *label, const uint8_t *hash, size_t hlen, uint8_t *out, int out_len) {
    uint8_t info[128]; int ilen = 0;
    info[ilen++] = (uint8_t)(out_len >> 8);
    info[ilen++] = (uint8_t)(out_len & 0xFF);
    int llen = (int)strlen(label); info[ilen++] = (uint8_t)(6 + llen);
    memcpy(info + ilen, "tls13 ", 6); ilen += 6;
    memcpy(info + ilen, label, llen); ilen += llen;
    info[ilen++] = (uint8_t)hlen; if (hlen > 0) { memcpy(info + ilen, hash, hlen); ilen += (int)hlen; }
    if (cipher_suite == 0x1302) {
        hkdf_sha384_expand(secret, info, (size_t)ilen, out, (size_t)out_len);
    } else {
        hkdf_sha256_expand(secret, info, (size_t)ilen, out, (size_t)out_len);
    }
}

void tls13_derive_secret(const uint8_t *prk, const char *label, const uint8_t *hash, size_t hlen, uint8_t *out) {
    tls13_expand_label(prk, label, hash, hlen, out, 32);
}

void tls13_derive_secret_cs(uint16_t cipher_suite, const uint8_t *prk, const char *label, const uint8_t *hash, size_t hlen, uint8_t *out) {
    int out_len = (cipher_suite == 0x1302) ? 48 : 32;
    tls13_expand_label_cs(cipher_suite, prk, label, hash, hlen, out, out_len);
}

static int read_full(int fd, uint8_t *buf, int len) {
    int total = 0;
    while (total < len) {
        int n = read(fd, buf + total, len - total);
        if (n <= 0) return -1;
        total += n;
    }
    return total;
}

static int write_full(int fd, const uint8_t *buf, int len) {
    int total = 0;
    while (total < len) {
        int n = write(fd, buf + total, len - total);
        if (n <= 0) return -1;
        total += n;
    }
    return total;
}

void tls13_xor_iv(uint8_t *iv, uint64_t seq, uint8_t *out) {
    memcpy(out, iv, 12);
    for (int i = 0; i < 8; i++) {
        out[11 - i] ^= (uint8_t)(seq >> (i * 8));
    }
}

int tls13_chrome_client_hello_psk(uint8_t *ch, const char *host, const uint8_t *pub_key, const uint8_t *pk_pq, const char *alpn_str, int alpn_len, const tls_session_ticket *psk, int *binder_pos_out);

int tls13_chrome_client_hello_tcp(uint8_t *ch, const char *host, const uint8_t *pub_key, const uint8_t *pk_pq, const char *alpn_str, int alpn_len) {
    return tls13_chrome_client_hello_psk(ch, host, pub_key, pk_pq, alpn_str, alpn_len, NULL, NULL);
}

int tls13_chrome_client_hello_psk(uint8_t *ch, const char *host, const uint8_t *pub_key, const uint8_t *pk_pq, const char *alpn_str, int alpn_len, const tls_session_ticket *psk, int *binder_pos_out) {
    int off = 0;
    ch[off++] = 0x01; // ClientHello
    int len_pos = off; off += 3;
    ch[off++] = 0x03; ch[off++] = 0x03; // TLS 1.2 legacy version
    bot_prng_generate_block(ch + off, 32); off += 32; // Random
    
    // 32-byte Legacy Session ID
    ch[off++] = 32; // Length
    bot_prng_generate_block(ch + off, 32); off += 32;
    
    // Cipher Suites — Chrome (BoringSSL) order
    int cs_len_pos = off; off += 2;
    int cs_len = 0;
    if (current_proto_tls13) {
        ch[off++] = 0x13; ch[off++] = 0x01; // TLS_AES_128_GCM_SHA256
        ch[off++] = 0x13; ch[off++] = 0x02; // TLS_AES_256_GCM_SHA384
        ch[off++] = 0x13; ch[off++] = 0x03; // TLS_CHACHA20_POLY1305_SHA256
        cs_len += 6;
    }
    if (current_proto_tls12) {
        ch[off++] = 0xC0; ch[off++] = 0x2B; // ECDHE_ECDSA_AES128_GCM_SHA256
        ch[off++] = 0xC0; ch[off++] = 0x2F; // ECDHE_RSA_AES128_GCM_SHA256
        ch[off++] = 0xC0; ch[off++] = 0x2C; // ECDHE_ECDSA_AES256_GCM_SHA384
        ch[off++] = 0xC0; ch[off++] = 0x30; // ECDHE_RSA_AES256_GCM_SHA384
        ch[off++] = 0xCC; ch[off++] = 0xA9; // ECDHE_ECDSA_CHACHA20_POLY1305
        ch[off++] = 0xCC; ch[off++] = 0xA8; // ECDHE_RSA_CHACHA20_POLY1305
        ch[off++] = 0xC0; ch[off++] = 0x13; // ECDHE_RSA_AES128_CBC_SHA
        ch[off++] = 0xC0; ch[off++] = 0x14; // ECDHE_RSA_AES256_CBC_SHA
        ch[off++] = 0x00; ch[off++] = 0x9C; // RSA_AES128_GCM_SHA256
        ch[off++] = 0x00; ch[off++] = 0x9D; // RSA_AES256_GCM_SHA384
        ch[off++] = 0x00; ch[off++] = 0x2F; // RSA_AES128_CBC_SHA
        ch[off++] = 0x00; ch[off++] = 0x35; // RSA_AES256_CBC_SHA
        cs_len += 24;
    }
    ch[cs_len_pos] = (uint8_t)(cs_len >> 8);
    ch[cs_len_pos + 1] = (uint8_t)(cs_len & 0xFF);
 
    ch[off++] = 1; ch[off++] = 0; // Legacy Compression Methods
    
    int ext_len_pos = off; off += 2;
 
    // 1. GREASE extension (0x3a3a)
    ch[off++] = 0x3a; ch[off++] = 0x3a;
    ch[off++] = 0x00; ch[off++] = 0x00;
 
    // 2. psk_key_exchange_modes (45 = 0x002d)
    ch[off++] = 0x00; ch[off++] = 0x2d;
    ch[off++] = 0x00; ch[off++] = 0x02;
    ch[off++] = 0x01; ch[off++] = 0x01; // psk_dhe_ke
 
    // 3. session_ticket (35 = 0x0023)
    ch[off++] = 0x00; ch[off++] = 0x23;
    ch[off++] = 0x00; ch[off++] = 0x00;
 
    // 4. application_layer_protocol_negotiation (16 = 0x0010)
    ch[off++] = 0x00; ch[off++] = 0x10;
    ch[off++] = 0x00; ch[off++] = (uint8_t)(alpn_len + 2);
    ch[off++] = 0x00; ch[off++] = (uint8_t)alpn_len;
    memcpy(ch + off, alpn_str, alpn_len); off += alpn_len;

    // 4b. application_settings — ALPS (17613 = 0x44cd), advertises "h2"
    ch[off++] = 0x44; ch[off++] = 0xcd;
    ch[off++] = 0x00; ch[off++] = 0x05; // ext len
    ch[off++] = 0x00; ch[off++] = 0x03; // ALPN list len
    ch[off++] = 0x02; ch[off++] = 'h'; ch[off++] = '2';

    // 5. supported_groups (10 = 0x000a)
    ch[off++] = 0x00; ch[off++] = 0x0a;
    ch[off++] = 0x00; ch[off++] = 12; // Length
    ch[off++] = 0x00; ch[off++] = 10;  // List length
    ch[off++] = 0x0a; ch[off++] = 0x0a; // GREASE
    ch[off++] = 0x11; ch[off++] = 0xec; // X25519MLKEM768 (4588)
    ch[off++] = 0x00; ch[off++] = 0x1d; // X25519
    ch[off++] = 0x00; ch[off++] = 0x17; // P-256
    ch[off++] = 0x00; ch[off++] = 0x18; // P-384
 
    // 6. compress_certificate (27 = 0x001b)
    ch[off++] = 0x00; ch[off++] = 0x1b;
    ch[off++] = 0x00; ch[off++] = 0x03;
    ch[off++] = 0x02; ch[off++] = 0x00; ch[off++] = 0x02; // brotli
 
    // 7. key_share (51 = 0x0033)
    ch[off++] = 0x00; ch[off++] = 0x33;
    ch[off++] = 0x04; ch[off++] = 0xea; // Extension Length = 1258 bytes
    ch[off++] = 0x04; ch[off++] = 0xe8; // List length = 1256 bytes
    // Entry 1: X25519MLKEM768 (0x11ec) — FIPS 203 via PQClean
    ch[off++] = 0x11; ch[off++] = 0xec;
    ch[off++] = 0x04; ch[off++] = 0xc0; // Key length = 1216 bytes
    memcpy(ch + off, pk_pq, 1184); off += 1184;
    memcpy(ch + off, pub_key, 32); off += 32;
    // Entry 2: X25519 (0x001d) — fallback
    ch[off++] = 0x00; ch[off++] = 0x1d;
    ch[off++] = 0x00; ch[off++] = 32;
    memcpy(ch + off, pub_key, 32); off += 32;
 
    // 8. server_name (0 = 0x0000)
    if (host != NULL) {
        ch[off++] = 0x00; ch[off++] = 0x00;
        int sni_len = strlen(host);
        ch[off++] = (uint8_t)((sni_len+5)>>8); ch[off++] = (uint8_t)((sni_len+5)&0xFF);
        ch[off++] = (uint8_t)((sni_len+3)>>8); ch[off++] = (uint8_t)((sni_len+3)&0xFF);
        ch[off++] = 0x00;
        ch[off++] = (uint8_t)(sni_len>>8); ch[off++] = (uint8_t)(sni_len&0xFF);
        memcpy(ch + off, host, sni_len); off += sni_len;
    }

    // 9. signed_certificate_timestamp (18 = 0x0012)
    ch[off++] = 0x00; ch[off++] = 0x12;
    ch[off++] = 0x00; ch[off++] = 0x00;

    // 10. supported_versions (43 = 0x002b)
    ch[off++] = 0x00; ch[off++] = 0x2b;
    int ver_len_pos = off; off += 2;
    int ver_list_len_pos = off++;
    ch[off++] = 0x1a; ch[off++] = 0x1a; // GREASE
    int versions_len = 2;
    if (current_proto_tls13) {
        ch[off++] = 0x03; ch[off++] = 0x04; // TLS 1.3
        versions_len += 2;
    }
    if (current_proto_tls12) {
        ch[off++] = 0x03; ch[off++] = 0x03; // TLS 1.2
        versions_len += 2;
    }
    ch[ver_list_len_pos] = (uint8_t)versions_len;
    int total_ext_len = versions_len + 1;
    ch[ver_len_pos] = (uint8_t)(total_ext_len >> 8);
    ch[ver_len_pos + 1] = (uint8_t)(total_ext_len & 0xFF);

    // 11. renegotiation_info (65281 = 0xff01)
    ch[off++] = 0xff; ch[off++] = 0x01;
    ch[off++] = 0x00; ch[off++] = 0x01;
    ch[off++] = 0x00;

    // 12. ec_point_formats (11 = 0x000b)
    ch[off++] = 0x00; ch[off++] = 0x0b;
    ch[off++] = 0x00; ch[off++] = 0x02;
    ch[off++] = 0x01; ch[off++] = 0x00;

    // 13. status_request (5 = 0x0005)
    ch[off++] = 0x00; ch[off++] = 0x05;
    ch[off++] = 0x00; ch[off++] = 0x05;
    ch[off++] = 0x01; ch[off++] = 0x00; ch[off++] = 0x00; ch[off++] = 0x00; ch[off++] = 0x00;

    // 14. signature_algorithms (13 = 0x000d)
    ch[off++] = 0x00; ch[off++] = 0x0d;
    ch[off++] = 0x00; ch[off++] = 18;
    ch[off++] = 0x00; ch[off++] = 16;
    ch[off++] = 0x04; ch[off++] = 0x03; // ecdsa_secp256r1_sha256
    ch[off++] = 0x08; ch[off++] = 0x04; // rsa_pss_rsae_sha256
    ch[off++] = 0x04; ch[off++] = 0x01; // rsa_pkcs1_sha256
    ch[off++] = 0x05; ch[off++] = 0x03; // ecdsa_secp384r1_sha384
    ch[off++] = 0x08; ch[off++] = 0x05; // rsa_pss_rsae_sha384
    ch[off++] = 0x05; ch[off++] = 0x01; // rsa_pkcs1_sha384
    ch[off++] = 0x08; ch[off++] = 0x06; // rsa_pss_rsae_sha512
    ch[off++] = 0x06; ch[off++] = 0x01; // rsa_pkcs1_sha512

    // 15. extended_master_secret (23 = 0x0017)
    ch[off++] = 0x00; ch[off++] = 0x17;
    ch[off++] = 0x00; ch[off++] = 0x00;

    // 16. encrypted_client_hello (65037 = 0xfe0d)
    ch[off++] = 0xfe; ch[off++] = 0x0d;
    ch[off++] = 0x00; ch[off++] = 0x01; // Length = 1
    ch[off++] = 0x00; // Payload: outer

    // 17. GREASE (0x2a2a)
    ch[off++] = 0x2a; ch[off++] = 0x2a;
    ch[off++] = 0x00; ch[off++] = 0x00;

    // 18. Padding (0x0015) — omitted when resuming (PSK must be last)
    int pad_target = 512;
    if (!psk && off < pad_target) {
        ch[off++] = 0x00; ch[off++] = 0x15;
        int pad_len = pad_target - off - 2;
        ch[off++] = (pad_len >> 8) & 0xFF; ch[off++] = pad_len & 0xFF;
        memset(ch + off, 0, pad_len); off += pad_len;
    }

    // 19. pre_shared_key (41 = 0x0029) — MUST be the final extension.
    // Layout: ext_type(2) ext_len(2) | identities_len(2) [ticket_len(2) ticket age(4)]
    //         | binders_len(2) [binder_len(1) binder(hash_len)]
    if (psk) {
        int hash_len = psk->psk_len;          /* 32 or 48 */
        uint32_t age = (uint32_t)(now_ms() - psk->obtained_ms) + psk->ticket_age_add;
        int identities_len = 2 + psk->ticket_len + 4;    /* len(2)+ticket+age(4) */
        int binders_len    = 1 + hash_len;               /* len(1)+binder */
        int ext_len = 2 + identities_len + 2 + binders_len;

        ch[off++] = 0x00; ch[off++] = 0x29;
        ch[off++] = (uint8_t)(ext_len >> 8); ch[off++] = (uint8_t)(ext_len & 0xFF);
        /* identities */
        ch[off++] = (uint8_t)(identities_len >> 8); ch[off++] = (uint8_t)(identities_len & 0xFF);
        ch[off++] = (uint8_t)(psk->ticket_len >> 8); ch[off++] = (uint8_t)(psk->ticket_len & 0xFF);
        memcpy(ch + off, psk->ticket, psk->ticket_len); off += psk->ticket_len;
        ch[off++] = (uint8_t)(age >> 24); ch[off++] = (uint8_t)(age >> 16);
        ch[off++] = (uint8_t)(age >> 8);  ch[off++] = (uint8_t)(age & 0xFF);
        /* binders */
        ch[off++] = (uint8_t)(binders_len >> 8); ch[off++] = (uint8_t)(binders_len & 0xFF);
        ch[off++] = (uint8_t)hash_len;
        if (binder_pos_out) *binder_pos_out = off;   /* caller fills hash_len bytes here */
        memset(ch + off, 0, hash_len); off += hash_len;
    }

    int ext_len = off - ext_len_pos - 2;
    ch[ext_len_pos] = (uint8_t)(ext_len >> 8); ch[ext_len_pos+1] = (uint8_t)(ext_len & 0xFF);
    
    int total_len = off - len_pos - 3;
    ch[len_pos] = (total_len >> 16) & 0xFF;
    ch[len_pos+1] = (total_len >> 8) & 0xFF;
    ch[len_pos+2] = total_len & 0xFF;
    return off;
}

int tls13_handshake(nanotls_conn *conn, const char *host) {
    sha256_init(&conn->transcript_ctx);
    sha384_init(&conn->transcript_ctx_384);
    uint8_t priv[32]; bot_prng_generate_block(priv, 32);
    uint8_t pub[32]; x25519_base(pub, priv);

    uint8_t pk_pq[1184];
    uint8_t sk_pq[2400];
    uint8_t coins[32];
    bot_prng_generate_block(coins, 32);
    mlkem768_keygen(pk_pq, sk_pq, coins);

    const char *sni_host = host;
    memcpy(conn->alpn_buf, current_alpn, current_alpn_len + 1);
    conn->alpn_str = conn->alpn_buf;
    conn->alpn_len = current_alpn_len;
    conn->is_h2 = current_mode_h2;

    if (strcmp(host, "1.1.1.1") == 0 || strcmp(host, "one.one.one.one") == 0) {
        sni_host = "cloudflare-dns.com";
        conn->alpn_str = "\x03" "dot";
        conn->alpn_len = 4;
        conn->is_h2 = 0;
    } else if (strcmp(host, "8.8.8.8") == 0 || strcmp(host, "dns.google") == 0) {
        sni_host = "dns.google";
        conn->alpn_str = "\x03" "dot";
        conn->alpn_len = 4;
        conn->is_h2 = 0;
    }

    const char *alpn_str = conn->alpn_str;
    int alpn_len = conn->alpn_len;
    conn->sni_host = host;

#ifdef DEBUG
    debug("[nanotls] Handshake for %s: ALPN=%s, H2=%d\n", host, alpn_str+1, conn->is_h2);
#endif

    uint8_t ch[4096];
    ch[0] = 0x16; ch[1] = 0x03; ch[2] = 0x01; // Record Header

    /* Look up a cached session ticket for PSK resumption (TLS 1.3 only) */
    tls_session_ticket *psk = NULL;
    if (current_proto_tls13) {
        tls_session_ticket *t = ticket_find(host);
        if (t && t->valid && t->ticket_len > 0) {
            /* honor ticket lifetime (seconds) if provided */
            if (t->ticket_lifetime == 0 ||
                (now_ms() - t->obtained_ms) / 1000ULL < t->ticket_lifetime) {
                psk = t;
            }
        }
    }

    int binder_pos = -1;
    int hs_len = tls13_chrome_client_hello_psk(ch + 5, sni_host, pub, pk_pq,
                                               alpn_str, alpn_len, psk, &binder_pos);
    ch[3] = (hs_len >> 8) & 0xFF;
    ch[4] = hs_len & 0xFF;

    int off = 5 + hs_len;
    memcpy(conn->client_random, ch + 11, 32);

    /* If resuming, compute and patch the PSK binder over the truncated CH */
    if (psk && binder_pos > 0) {
        int hlen = psk->psk_len;
        uint16_t cs = psk->cipher_suite;
        /* truncated transcript = CH handshake body minus binders(2)+blen(1)+binder */
        int trunc_len = binder_pos - 3;   /* binder_pos is at start of binder bytes */
        uint8_t th[48];
        if (cs == 0x1302) {
            sha384_ctx_t tx; sha384_init(&tx);
            sha384_update(&tx, ch + 5, trunc_len);
            sha384_final(&tx, th);
        } else {
            sha256_ctx_t tx; sha256_init(&tx);
            sha256_update(&tx, ch + 5, trunc_len);
            sha256_final(&tx, th);
        }
        /* binder_key = Derive-Secret(early_secret, "res binder", "") */
        uint8_t es[48], binder_key[48], fin_key[48], binder[48];
        const uint8_t eh32[32] = {
            0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
            0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55 };
        const uint8_t eh48[48] = {
            0x38,0xb0,0x60,0xa7,0x51,0xac,0x96,0x38,0x4c,0xd9,0x32,0x7e,0xb1,0xb1,0xe3,0x6a,
            0x21,0xfd,0xb7,0x11,0x14,0xbe,0x07,0x43,0x4c,0x0c,0xc7,0xbf,0x63,0xf6,0xe1,0xda,
            0x27,0x4e,0xde,0xbf,0xe7,0x6f,0x65,0xfb,0xd5,0x1a,0xd2,0xf1,0x48,0x98,0xb9,0x5b };
        const uint8_t *eh = (cs == 0x1302) ? eh48 : eh32;
        if (cs == 0x1302) hkdf_sha384_extract(NULL, 0, psk->psk, hlen, es);
        else              hkdf_sha256_extract(NULL, 0, psk->psk, hlen, es);
        tls13_derive_secret_cs(cs, es, "res binder", eh, hlen, binder_key);
        tls13_expand_label_cs(cs, binder_key, "finished", NULL, 0, fin_key, hlen);
        if (cs == 0x1302) hmac_sha384(fin_key, hlen, th, hlen, binder);
        else              hmac_sha256(fin_key, hlen, th, hlen, binder);
        memcpy(ch + 5 + binder_pos, binder, hlen);
    }

    sha256_update(&conn->transcript_ctx, ch + 5, hs_len);
    sha384_update(&conn->transcript_ctx_384, ch + 5, hs_len);
    if (write_full(conn->fd, ch, off) < 0) return -1;

    uint8_t early_secret[48], handshake_secret[48], transcript_hash[48];
    uint8_t c_hs_secret[48], s_hs_secret[48];
    static const uint8_t empty_hash[48] = {
        0x38,0xb0,0x60,0xa7,0x51,0xac,0x96,0x38,0x4c,0xd9,0x32,0x7e,0xb1,0xb1,0xe3,0x6a,
        0x21,0xfd,0xb7,0x11,0x14,0xbe,0x07,0x43,0x4c,0x0c,0xc7,0xbf,0x63,0xf6,0xe1,0xda,
        0x27,0x4e,0xde,0xbf,0xe7,0x6f,0x65,0xfb,0xd5,0x1a,0xd2,0xf1,0x48,0x98,0xb9,0x5b
    };
    static const uint8_t empty_hash_256[32] = {
        0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
        0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
    };

    while (1) {
        uint8_t head[5];
        if (read_full(conn->fd, head, 5) <= 0) break;
        int rlen = (head[3] << 8) | head[4];
#ifdef DEBUG
        debug("[nanotls] Handshake Recv Record: type=0x%02x, len=%d\n", head[0], rlen);
#endif
        uint8_t *rec = malloc(rlen);
        if (!rec) break;
        if (read_full(conn->fd, rec, rlen) <= 0) { free(rec); break; }

        if (head[0] == 0x15) {
#ifdef DEBUG
            debug("[nanotls] Received Alert from server: level=%d, description=%d\n", rec[0], rec[1]);
#endif
            free(rec);
            return -15;
        }

        if (conn->is_tls12) {
            if (head[0] == 0x14) {
#ifdef DEBUG
                debug("[nanotls] Received Server ChangeCipherSpec\n");
#endif
                conn->server_ccs_received = 1;
                free(rec);
                continue;
            }
            if (head[0] == 0x16) {
                if (conn->server_ccs_received) {
                    // Decrypt Server Finished message
                    uint8_t iv[12], ad[13];
                    uint8_t *dec = malloc(rlen);
                    if (!dec) { free(rec); break; }
                    
                    memcpy(iv, conn->server_iv, 4);
                    memcpy(iv + 4, rec, 8);
                    
                    uint64_t seq = conn->server_seq++;
                    ad[0] = (seq >> 56) & 0xff; ad[1] = (seq >> 48) & 0xff;
                    ad[2] = (seq >> 40) & 0xff; ad[3] = (seq >> 32) & 0xff;
                    ad[4] = (seq >> 24) & 0xff; ad[5] = (seq >> 16) & 0xff;
                    ad[6] = (seq >> 8) & 0xff;  ad[7] = seq & 0xff;
                    ad[8] = 0x16;
                    ad[9] = 0x03; ad[10] = 0x03;
                    ad[11] = 0x00; ad[12] = 0x10; // Plaintext length of Finished = 16
                    
                    int decrypt_res = aes_128_gcm_decrypt(conn->server_key, iv, ad, 13, rec + 8, rlen - 8 - 16, dec, rec + rlen - 16);
                    if (decrypt_res < 0) {
#ifdef DEBUG
                        debug("[nanotls] Decrypting server Finished failed!\n");
#endif
                        free(dec); free(rec); return -5;
                    }
                    
                    uint8_t th[32];
                    sha256_ctx_t fctx = conn->transcript_ctx;
                    sha256_final(&fctx, th);
                    
                    uint8_t expected_verify[12];
                    tls12_prf(conn->master_secret, 48, "server finished", th, 32, expected_verify, 12);
                    
                    if (memcmp(dec + 4, expected_verify, 12) != 0) {
#ifdef DEBUG
                        debug("[nanotls] Server Finished verification failed!\n");
#endif
                        free(dec); free(rec); return -7;
                    }
#ifdef DEBUG
                    debug("[nanotls] Server Finished verified successfully! Handshake complete.\n");
#endif
                    free(dec); free(rec);
                    return 0; // SUCCESS! Handshake complete!
                } else {
                    // Plaintext Server handshake messages: Certificate, ServerKeyExchange, ServerHelloDone
                    if (conn->hs_buf_len + rlen <= (int)sizeof(conn->hs_buf)) {
                        memcpy(conn->hs_buf + conn->hs_buf_len, rec, rlen);
                        conn->hs_buf_len += rlen;
                    } else {
                        free(rec); return -6;
                    }
                }
            }
        } else if (head[0] == 0x16 && rec[0] == HS_SERVER_HELLO) {
            int sh_len = (rec[1]<<16)|(rec[2]<<8)|rec[3];
            
            int sess_id_len = rec[38];
            conn->cipher_suite = (rec[39 + sess_id_len] << 8) | rec[39 + sess_id_len + 1];
#ifdef DEBUG
            debug("[nanotls] Selected Cipher Suite: 0x%04x\n", conn->cipher_suite);
#endif

            int ext_offset = 39 + sess_id_len + 3;
            int has_tls13_supported_versions = 0;
            int server_psk_accepted = 0;
            uint16_t selected_group = 0;
            uint8_t *s_key_share = NULL;
            int s_key_share_len = 0;
            
            if (ext_offset + 2 <= rlen) {
                int ext_len = (rec[ext_offset] << 8) | rec[ext_offset + 1];
                int ext_p = ext_offset + 2;
                int ext_end = ext_p + ext_len;
                if (ext_end > rlen) ext_end = rlen;
                
                while (ext_p + 4 <= ext_end) {
                    uint16_t ext_type = (rec[ext_p] << 8) | rec[ext_p + 1];
                    uint16_t ext_data_len = (rec[ext_p + 2] << 8) | rec[ext_p + 3];
                    if (ext_p + 4 + ext_data_len > ext_end) break;
                    
                    if (ext_type == 0x002b) { // supported_versions extension
                        if (ext_data_len == 2) {
                            uint16_t selected_version = (rec[ext_p + 4] << 8) | rec[ext_p + 5];
                            if (selected_version == 0x0304) {
                                has_tls13_supported_versions = 1;
                            }
                        }
                    }
                    if (ext_type == 0x0029) { // pre_shared_key — server accepted our PSK
                        server_psk_accepted = 1;
                    }
                    if (ext_type == 0x0033) { // key_share extension
                        if (ext_data_len >= 4) {
                            selected_group = (rec[ext_p + 4] << 8) | rec[ext_p + 5];
                            s_key_share_len = (rec[ext_p + 6] << 8) | rec[ext_p + 7];
                            if (ext_data_len >= 4 + s_key_share_len) {
                                s_key_share = rec + ext_p + 8;
                            }
                        }
                    }
                    ext_p += 4 + ext_data_len;
                }
            }

            int is_tls13_negotiated = 0;
            if (conn->cipher_suite == 0x1301 || conn->cipher_suite == 0x1302 || conn->cipher_suite == 0x1303) {
                if (has_tls13_supported_versions) {
                    is_tls13_negotiated = 1;
                }
            }

            if (is_tls13_negotiated && !current_proto_tls13) {
#ifdef DEBUG
                debug("[nanotls] Error: Server negotiated TLS 1.3 but TLS 1.3 is disabled!\n");
#endif
                free(rec);
                return -4;
            }
            if (!is_tls13_negotiated && !current_proto_tls12) {
#ifdef DEBUG
                debug("[nanotls] Error: Server negotiated TLS 1.2 but TLS 1.2 is disabled!\n");
#endif
                free(rec);
                return -4;
            }

            if (!is_tls13_negotiated) {
                conn->is_tls12 = 1;
#ifdef DEBUG
                debug("[nanotls] Auto-negotiated TLS 1.2 fallback!\n");
#endif
                memcpy(conn->server_random, rec + 6, 32);
                sha256_update(&conn->transcript_ctx, rec, rlen);
                free(rec);
                continue;
            }

            if (!s_key_share) { free(rec); return -3; }
            
            uint8_t shared[64];
            int shared_len = 32;
            uint8_t s_priv[32]; memcpy(s_priv, priv, 32);

            if (selected_group == 0x11ec) {
                if (s_key_share_len < 1120) { free(rec); return -3; }
                uint8_t pq_secret[32];
                mlkem768_decaps(pq_secret, s_key_share, sk_pq);
                
                uint8_t cl_secret[32];
                x25519(cl_secret, s_priv, s_key_share + 1088);
                
                memcpy(shared, cl_secret, 32);      // X25519 first (per draft-ietf-tls-hybrid-design)
                memcpy(shared + 32, pq_secret, 32); // ML-KEM second
                shared_len = 64;
#ifdef DEBUG
                debug("[nanotls] Decapsulated hybrid PQ secret successfully!\n");
#endif
            } else {
                x25519(shared, s_priv, s_key_share);
                shared_len = 32;
            }

            sha256_update(&conn->transcript_ctx, rec, rlen);
            sha384_update(&conn->transcript_ctx_384, rec, rlen);
            
            int hash_len = (conn->cipher_suite == 0x1302) ? 48 : 32;
            const uint8_t *eh = (conn->cipher_suite == 0x1302) ? empty_hash : empty_hash_256;
            uint8_t derived_secret[48];

            if (conn->cipher_suite == 0x1302) {
                sha384_ctx_t tmp_ctx = conn->transcript_ctx_384; sha384_final(&tmp_ctx, transcript_hash);
                if (server_psk_accepted && psk)
                    hkdf_sha384_extract(NULL, 0, psk->psk, psk->psk_len, early_secret);
                else
                    hkdf_sha384_extract(NULL, 0, NULL, 0, early_secret);
                tls13_derive_secret_cs(conn->cipher_suite, early_secret, "derived", eh, hash_len, derived_secret);
                hkdf_sha384_extract(derived_secret, 48, shared, shared_len, handshake_secret);
                tls13_derive_secret_cs(conn->cipher_suite, handshake_secret, "c hs traffic", transcript_hash, hash_len, c_hs_secret);
                tls13_derive_secret_cs(conn->cipher_suite, handshake_secret, "s hs traffic", transcript_hash, hash_len, s_hs_secret);
#ifdef DEBUG
                debug("[nanotls] shared: "); for(int i=0;i<shared_len;i++) debug("%02x", shared[i]); debug("\n");
                debug("[nanotls] transcript_hash: "); for(int i=0;i<48;i++) debug("%02x", transcript_hash[i]); debug("\n");
                debug("[nanotls] early_secret: "); for(int i=0;i<48;i++) debug("%02x", early_secret[i]); debug("\n");
                debug("[nanotls] derived_secret: "); for(int i=0;i<48;i++) debug("%02x", derived_secret[i]); debug("\n");
                debug("[nanotls] handshake_secret: "); for(int i=0;i<48;i++) debug("%02x", handshake_secret[i]); debug("\n");
                debug("[nanotls] s_hs_secret: "); for(int i=0;i<48;i++) debug("%02x", s_hs_secret[i]); debug("\n");
#endif
            } else {
                sha256_ctx_t tmp_ctx = conn->transcript_ctx; sha256_final(&tmp_ctx, transcript_hash);
                if (server_psk_accepted && psk)
                    hkdf_sha256_extract(NULL, 0, psk->psk, psk->psk_len, early_secret);
                else
                    hkdf_sha256_extract(NULL, 0, NULL, 0, early_secret);
                tls13_derive_secret_cs(conn->cipher_suite, early_secret, "derived", eh, hash_len, derived_secret);
                hkdf_sha256_extract(derived_secret, 32, shared, shared_len, handshake_secret);
                tls13_derive_secret_cs(conn->cipher_suite, handshake_secret, "c hs traffic", transcript_hash, hash_len, c_hs_secret);
                tls13_derive_secret_cs(conn->cipher_suite, handshake_secret, "s hs traffic", transcript_hash, hash_len, s_hs_secret);
            }
            
            int key_len = (conn->cipher_suite == 0x1301) ? 16 : 32;
            tls13_expand_label_cs(conn->cipher_suite, c_hs_secret, "key", NULL, 0, conn->client_key, key_len);
            tls13_expand_label_cs(conn->cipher_suite, c_hs_secret, "iv", NULL, 0, conn->client_iv, 12);
            tls13_expand_label_cs(conn->cipher_suite, s_hs_secret, "key", NULL, 0, conn->server_key, key_len);
            tls13_expand_label_cs(conn->cipher_suite, s_hs_secret, "iv", NULL, 0, conn->server_iv, 12);
#ifdef DEBUG
            if (conn->cipher_suite == 0x1302) {
                debug("[nanotls] server_key: "); for(int i=0;i<32;i++) debug("%02x", conn->server_key[i]); debug("\n");
                debug("[nanotls] server_iv: "); for(int i=0;i<12;i++) debug("%02x", conn->server_iv[i]); debug("\n");
            }
#endif
            
        } else if (head[0] == 0x17) {
            uint8_t iv[12], ad[5];
            uint8_t *dec = malloc(rlen);
            if (!dec) { free(rec); break; }
            tls13_xor_iv(conn->server_iv, conn->server_seq++, iv);
            ad[0] = head[0]; ad[1] = head[1]; ad[2] = head[2]; ad[3] = head[3]; ad[4] = head[4];
            
            if (conn->cipher_suite == 0x1301) {
                if (aes_128_gcm_decrypt(conn->server_key, iv, ad, 5, rec, rlen - 16, dec, rec + rlen - 16) < 0) {
                    free(dec); free(rec); return -5;
                }
            } else if (conn->cipher_suite == 0x1302) {
#ifdef DEBUG
                debug("[nanotls] GCM decrypt input:\n");
                debug("  key:  "); for(int i=0;i<32;i++) debug("%02x", conn->server_key[i]); debug("\n");
                debug("  iv:   "); for(int i=0;i<12;i++) debug("%02x", iv[i]); debug("\n");
                debug("  ad:   "); for(int i=0;i<5;i++) debug("%02x", ad[i]); debug("\n");
                debug("  len:  %d\n", rlen - 16);
                debug("  ciphertext: "); for(int i=0;i<rlen-16;i++) debug("%02x", rec[i]); debug("\n");
                debug("  tag:  "); for(int i=0;i<16;i++) debug("%02x", rec[rlen - 16 + i]); debug("\n");
#endif
                int res = aes_256_gcm_decrypt(conn->server_key, iv, ad, 5, rec, rlen - 16, dec, rec + rlen - 16);
#ifdef DEBUG
                debug("  res:  %d\n", res);
#endif
                if (res < 0) {
                    free(dec); free(rec); return -5;
                }
            } else {
                if (chacha20_poly1305_decrypt(conn->server_key, iv, ad, 5, rec, rlen - 16, dec, rec + rlen - 16) < 0) {
                    free(dec); free(rec); return -5;
                }
            }
            
            int dlen = rlen - 16;
            while (dlen > 0 && dec[dlen-1] == 0) dlen--;
            if (dlen > 0) dlen--;
            
            // Append decrypted payload to handshake queue
            if (conn->hs_buf_len + dlen <= (int)sizeof(conn->hs_buf)) {
                memcpy(conn->hs_buf + conn->hs_buf_len, dec, dlen);
                conn->hs_buf_len += dlen;
            } else {
                free(dec); free(rec); return -6; // Handshake buffer overflow
            }
            free(dec);
            
            // --- End of head[0] == 0x17 block ---
        }

        // --- Unified Handshake Queue Processing ---
        int finished_success = 0;
        while (conn->hs_buf_len >= 4) {
            int mlen = (conn->hs_buf[1] << 16) | (conn->hs_buf[2] << 8) | conn->hs_buf[3];
            if (conn->hs_buf_len < 4 + mlen) {
                break;
            }
            
            if (conn->is_tls12) {
                // Update transcript with this message BEFORE processing it, so CKE can be added in correct order
                sha256_update(&conn->transcript_ctx, conn->hs_buf, 4 + mlen);
                
                if (conn->hs_buf[0] == 0x0c) { // ServerKeyExchange
                    uint16_t curve_id = (conn->hs_buf[5] << 8) | conn->hs_buf[6];
                    if (curve_id == 0x001d) {
                        uint8_t s_pub[32];
                        memcpy(s_pub, conn->hs_buf + 8, 32);
                        
                        uint8_t s_priv[32];
                        memcpy(s_priv, priv, 32);

                        x25519(conn->handshake_secret, s_priv, s_pub);
#ifdef DEBUG
                        debug("[nanotls] Parsed X25519 ServerKeyExchange\n");
#endif
                    } else {
                        free(rec); return -8;
                    }
                } else if (conn->hs_buf[0] == 0x0e) { // ServerHelloDone
#ifdef DEBUG
                    debug("[nanotls] Received ServerHelloDone. Initiating Client flight.\n");
#endif
                    uint8_t seed[64];
                    memcpy(seed, conn->client_random, 32);
                    memcpy(seed + 32, conn->server_random, 32);
                    
                    tls12_prf(conn->handshake_secret, 32, "master secret", seed, 64, conn->master_secret, 48);
                    
                    uint8_t cke[37];
                    cke[0] = 0x10;
                    cke[1] = 0; cke[2] = 0; cke[3] = 33;
                    cke[4] = 32;
                    memcpy(cke + 5, pub, 32);
                    
                    sha256_update(&conn->transcript_ctx, cke, 37);
                    
                    uint8_t seed_kb[64];
                    memcpy(seed_kb, conn->server_random, 32);
                    memcpy(seed_kb + 32, conn->client_random, 32);
                    
                    uint8_t kb[40];
                    tls12_prf(conn->master_secret, 48, "key expansion", seed_kb, 64, kb, 40);
                    
                    memcpy(conn->client_key, kb, 16);
                    memcpy(conn->server_key, kb + 16, 16);
                    memcpy(conn->client_iv, kb + 32, 4);
                    memcpy(conn->server_iv, kb + 36, 4);
                    aes_128_key_expand(conn->client_key, conn->client_key_w);
                    aes_128_key_expand(conn->server_key, conn->server_key_w);
                    conn->ks_rounds = 10;
                    
                    uint8_t th[32];
                    sha256_ctx_t tmp_ctx = conn->transcript_ctx;
                    sha256_final(&tmp_ctx, th);
                    
                    uint8_t verify[12];
                    tls12_prf(conn->master_secret, 48, "client finished", th, 32, verify, 12);
                    
                    uint8_t fin[16];
                    fin[0] = 0x14;
                    fin[1] = 0; fin[2] = 0; fin[3] = 12;
                    memcpy(fin + 4, verify, 12);
                    
                    sha256_update(&conn->transcript_ctx, fin, 16);
                    
                    uint8_t c_flight[200];
                    int c_off = 0;
                    
                    c_flight[c_off++] = 0x16;
                    c_flight[c_off++] = 0x03; c_flight[c_off++] = 0x03;
                    c_flight[c_off++] = 0; c_flight[c_off++] = 37;
                    memcpy(c_flight + c_off, cke, 37);
                    c_off += 37;
                    
                    c_flight[c_off++] = 0x14;
                    c_flight[c_off++] = 0x03; c_flight[c_off++] = 0x03;
                    c_flight[c_off++] = 0; c_flight[c_off++] = 1;
                    c_flight[c_off++] = 0x01;
                    
                    uint8_t f_payload[40];
                    uint8_t iv[12], ad[13];
                    
                    uint64_t seq = conn->client_seq++;
                    f_payload[0] = (seq >> 56) & 0xff; f_payload[1] = (seq >> 48) & 0xff;
                    f_payload[2] = (seq >> 40) & 0xff; f_payload[3] = (seq >> 32) & 0xff;
                    f_payload[4] = (seq >> 24) & 0xff; f_payload[5] = (seq >> 16) & 0xff;
                    f_payload[6] = (seq >> 8) & 0xff;  f_payload[7] = seq & 0xff;
                    
                    memcpy(iv, conn->client_iv, 4);
                    memcpy(iv + 4, f_payload, 8);
                    
                    memcpy(ad, f_payload, 8);
                    ad[8] = 0x16;
                    ad[9] = 0x03; ad[10] = 0x03;
                    ad[11] = 0x00; ad[12] = 0x10;
                    
                    aes_128_gcm_encrypt(conn->client_key, iv, ad, 13, fin, 16, f_payload + 8, f_payload + 8 + 16);
                    
                    c_flight[c_off++] = 0x16;
                    c_flight[c_off++] = 0x03; c_flight[c_off++] = 0x03;
                    c_flight[c_off++] = 0; c_flight[c_off++] = 40;
                    memcpy(c_flight + c_off, f_payload, 40);
                    c_off += 40;
                    
                    if (write_full(conn->fd, c_flight, c_off) < 0) { free(rec); return -1; }
                }
                
                int consumed = 4 + mlen;
                memmove(conn->hs_buf, conn->hs_buf + consumed, conn->hs_buf_len - consumed);
                conn->hs_buf_len -= consumed;
                continue;
            }
            
            sha256_update(&conn->transcript_ctx, conn->hs_buf, 4 + mlen);
            sha384_update(&conn->transcript_ctx_384, conn->hs_buf, 4 + mlen);
            
#ifdef DEBUG
            debug("[nanotls] Parsed Handshake Message: type=0x%02x, len=%d\n", conn->hs_buf[0], mlen);
#endif
            
            if (conn->hs_buf[0] == HS_ENCRYPTED_EXT) {
                int ext_len = (conn->hs_buf[4] << 8) | conn->hs_buf[5];
                uint8_t *ep = conn->hs_buf + 6;
                uint8_t *end = ep + ext_len;
                conn->is_h2 = 0;
                while (ep + 4 <= end) {
                    uint16_t etype = (ep[0] << 8) | ep[1];
                    uint16_t elen = (ep[2] << 8) | ep[3];
                    if (ep + 4 + elen > end) break;
                    if (etype == 0x0010) {
                        if (elen >= 3) {
                            int proto_len = ep[6];
                            if (proto_len == 2 && memcmp(ep + 7, "h2", 2) == 0) {
                                conn->is_h2 = 1;
                            }
                        }
                    }
                    ep += 4 + elen;
                }
#ifdef DEBUG
                debug("[nanotls] Server EncryptedExtensions parsed. conn->is_h2 = %d\n", conn->is_h2);
#endif
            }
            
            if (conn->hs_buf[0] == HS_FINISHED) {
                uint8_t th[48];
                int hash_len = (conn->cipher_suite == 0x1302) ? 48 : 32;
                const uint8_t *eh = (conn->cipher_suite == 0x1302) ? empty_hash : empty_hash_256;
                
                if (conn->cipher_suite == 0x1302) {
                    sha384_ctx_t fctx = conn->transcript_ctx_384; sha384_final(&fctx, th);
                } else {
                    sha256_ctx_t fctx = conn->transcript_ctx; sha256_final(&fctx, th);
                }
                
                uint8_t c_fin_key[48], verify[48];
                tls13_expand_label_cs(conn->cipher_suite, c_hs_secret, "finished", NULL, 0, c_fin_key, hash_len);
                
                if (conn->cipher_suite == 0x1302) {
                    hmac_sha384(c_fin_key, hash_len, th, hash_len, verify);
                } else {
                    hmac_sha256(c_fin_key, hash_len, th, hash_len, verify);
                }
                
                int fin_msg_len = 4 + hash_len;
                uint8_t *fin = malloc(fin_msg_len + 1);
                if (!fin) { free(rec); return -1; }
                fin[0]=HS_FINISHED; fin[1]=0; fin[2]=0; fin[3]=hash_len; 
                memcpy(fin+4, verify, hash_len);
                fin[fin_msg_len] = 0x16;
                
                int clen = fin_msg_len + 1 + 16;
                uint8_t *enc_pkt = malloc(5 + clen);
                if (!enc_pkt) { free(fin); free(rec); return -1; }
                
                uint8_t c_iv[12], tag[16];
                tls13_xor_iv(conn->client_iv, conn->client_seq++, c_iv);
                uint8_t ad[5]; ad[0]=0x17; ad[1]=0x03; ad[2]=0x03; ad[3]=clen>>8; ad[4]=clen&0xff;
                
                if (conn->cipher_suite == 0x1301) {
                    aes_128_gcm_encrypt(conn->client_key, c_iv, ad, 5, fin, fin_msg_len + 1, enc_pkt + 5, tag);
                } else if (conn->cipher_suite == 0x1302) {
                    aes_256_gcm_encrypt(conn->client_key, c_iv, ad, 5, fin, fin_msg_len + 1, enc_pkt + 5, tag);
                } else {
                    chacha20_poly1305_encrypt(conn->client_key, c_iv, ad, 5, fin, fin_msg_len + 1, enc_pkt + 5, tag);
                }
                enc_pkt[0]=0x17; enc_pkt[1]=0x03; enc_pkt[2]=0x03; enc_pkt[3]=(uint8_t)(clen>>8); enc_pkt[4]=(uint8_t)(clen&0xff);
                memcpy(enc_pkt + 5 + fin_msg_len + 1, tag, 16);
                if (write_full(conn->fd, enc_pkt, 5 + clen) < 0) {
                    free(enc_pkt); free(fin); free(rec); return -1;
                }
                free(enc_pkt);
                /* Add client Finished to transcript (needed for resumption master secret) */
                if (conn->cipher_suite == 0x1302)
                    sha384_update(&conn->transcript_ctx_384, fin, fin_msg_len);
                else
                    sha256_update(&conn->transcript_ctx, fin, fin_msg_len);
                free(fin);
                
                uint8_t derived2[48], master_secret[48];
                tls13_derive_secret_cs(conn->cipher_suite, handshake_secret, "derived", eh, hash_len, derived2);
                
                if (conn->cipher_suite == 0x1302) {
                    uint8_t zeros48[48] = {0};
                    hkdf_sha384_extract(derived2, 48, zeros48, 48, master_secret);
                } else {
                    uint8_t zeros32[32] = {0};
                    hkdf_sha256_extract(derived2, 32, zeros32, 32, master_secret);
                }
                
                uint8_t c_ap[48], s_ap[48];
                tls13_derive_secret_cs(conn->cipher_suite, master_secret, "c ap traffic", th, hash_len, c_ap);
                tls13_derive_secret_cs(conn->cipher_suite, master_secret, "s ap traffic", th, hash_len, s_ap);
                
                int app_key_len = (conn->cipher_suite == 0x1301) ? 16 : 32;
                tls13_expand_label_cs(conn->cipher_suite, c_ap, "key", NULL, 0, conn->client_key, app_key_len);
                tls13_expand_label_cs(conn->cipher_suite, c_ap, "iv", NULL, 0, conn->client_iv, 12);
                tls13_expand_label_cs(conn->cipher_suite, s_ap, "key", NULL, 0, conn->server_key, app_key_len);
                tls13_expand_label_cs(conn->cipher_suite, s_ap, "iv", NULL, 0, conn->server_iv, 12);
                conn->client_seq = 0; conn->server_seq = 0;

                /* Resumption master secret: Derive-Secret(MS, "res master",
                   ClientHello..client Finished). Client Finished already in transcript. */
                uint8_t th_cf[48];
                if (conn->cipher_suite == 0x1302) {
                    sha384_ctx_t fc = conn->transcript_ctx_384; sha384_final(&fc, th_cf);
                } else {
                    sha256_ctx_t fc = conn->transcript_ctx; sha256_final(&fc, th_cf);
                }
                tls13_derive_secret_cs(conn->cipher_suite, master_secret, "res master",
                                       th_cf, hash_len, conn->resumption_master_secret);
                conn->resumption_ms_valid = 1;

                /* Pre-expand AES key schedules for fast send/recv */
                if (conn->cipher_suite == 0x1301) {
                    aes_128_key_expand(conn->client_key, conn->client_key_w);
                    aes_128_key_expand(conn->server_key, conn->server_key_w);
                    conn->ks_rounds = 10;
                } else if (conn->cipher_suite == 0x1302) {
                    aes_256_key_expand(conn->client_key, conn->client_key_w);
                    aes_256_key_expand(conn->server_key, conn->server_key_w);
                    conn->ks_rounds = 14;
                } else {
                    conn->ks_rounds = 0; /* ChaCha20 — no key schedule */
                }
                
                finished_success = 1;
                conn->hs_buf_len = 0;
                break;
            }
            
            int consumed = 4 + mlen;
            memmove(conn->hs_buf, conn->hs_buf + consumed, conn->hs_buf_len - consumed);
            conn->hs_buf_len -= consumed;
        }
        
        if (finished_success) {
            free(rec);
            return 0;
        }
        free(rec);
    }
    return -4;
}

nanotls_conn* tls_core_connect(const char* host, int port) {
    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[8]; snprintf(port_str, sizeof(port_str), "%d", port);
    if (getaddrinfo(host, port_str, &hints, &res) != 0) return NULL;
    struct sockaddr_in addr = *(struct sockaddr_in *)res->ai_addr;
    freeaddrinfo(res);

    return tls_core_connect_addr(&addr, host);
}

int tls_core_send(nanotls_conn* conn, const void* data, int len) {
    if (len > 16384) return -1;
    
    if (conn->is_tls12) {
        int clen = 8 + len + 16;
        uint8_t *enc = malloc(5 + clen); if (!enc) return -1;
        
        uint64_t seq = conn->client_seq++;
        enc[5] = (seq >> 56) & 0xff; enc[6] = (seq >> 48) & 0xff;
        enc[7] = (seq >> 40) & 0xff; enc[8] = (seq >> 32) & 0xff;
        enc[9] = (seq >> 24) & 0xff; enc[10] = (seq >> 16) & 0xff;
        enc[11] = (seq >> 8) & 0xff; enc[12] = seq & 0xff;
        
        uint8_t iv[12];
        memcpy(iv, conn->client_iv, 4);
        memcpy(iv + 4, enc + 5, 8);
        
        uint8_t ad[13];
        memcpy(ad, enc + 5, 8);
        ad[8] = 0x17;
        ad[9] = 0x03; ad[10] = 0x03;
        ad[11] = (len >> 8) & 0xff; ad[12] = len & 0xff;
        
        uint8_t tag[16];
        aes_gcm_encrypt_ks(conn->client_key_w, conn->ks_rounds, iv, ad, 13, data, len, enc + 13, tag);

        enc[0] = 0x17; enc[1] = 0x03; enc[2] = 0x03;
        enc[3] = (clen >> 8) & 0xff; enc[4] = clen & 0xff;
        memcpy(enc + 13 + len, tag, 16);

        int ret = write(conn->fd, enc, 5 + clen);
        free(enc);
        return ret;
    }

    uint8_t *enc = malloc(len + 64); if (!enc) return -1;
    uint8_t tag[16], iv[12];
    uint8_t *buf = malloc(len + 1); if (!buf) { free(enc); return -1; }
    memcpy(buf, data, len); buf[len]=0x17;
    tls13_xor_iv(conn->client_iv, conn->client_seq++, iv);
    uint8_t ad[5]; ad[0]=0x17; ad[1]=0x03; ad[2]=0x03; int clen=len+1+16; ad[3]=clen>>8; ad[4]=clen&0xff;

    if (conn->ks_rounds) {
        aes_gcm_encrypt_ks(conn->client_key_w, conn->ks_rounds, iv, ad, 5, buf, len + 1, enc + 5, tag);
    } else {
        chacha20_poly1305_encrypt(conn->client_key, iv, ad, 5, buf, len + 1, enc + 5, tag);
    }
    enc[0]=0x17; enc[1]=0x03; enc[2]=0x03; enc[3]=(clen>>8); enc[4]=(clen&0xff);
    memcpy(enc + 5 + len + 1, tag, 16);
    int ret = write(conn->fd, enc, 5 + clen);
    free(buf); free(enc);
    return ret;
}



int tls_core_recv(nanotls_conn* conn, void* buf, int len) {
    if (conn->is_quic) {
        quic_conn *qconn = (quic_conn *)conn->quic_conn_ptr;
        quic_stream *s0 = quic_find_stream(qconn, 0);
        
        if (s0 && s0->rx_buf_len > 0) {
            int to_copy = s0->rx_buf_len;
            if (to_copy > len) to_copy = len;
            memcpy(buf, s0->rx_buf, to_copy);
            if (to_copy < s0->rx_buf_len) {
                memmove(s0->rx_buf, s0->rx_buf + to_copy, s0->rx_buf_len - to_copy);
            }
            s0->rx_buf_len -= to_copy;
            return to_copy;
        }
        
        uint8_t pkt[4096], plain[4096];
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        
        quic_check_pto(qconn);
        int n = recvfrom(qconn->fd, pkt, sizeof(pkt), 0, (struct sockaddr *)&from, &fromlen);
        if (n > 0) {
            uint8_t hdr2 = pkt[0];
            if (!(hdr2 & 0x80)) {
                int consumed2 = 0;
                quic_decrypt_1rtt(qconn, pkt, n,
                                  qconn->s_app_key,
                                  qconn->s_app_iv,
                                  qconn->s_app_hp,
                                  plain, &consumed2);
            }
        }
        
        if (s0 && s0->rx_buf_len > 0) {
            int to_copy = s0->rx_buf_len;
            if (to_copy > len) to_copy = len;
            memcpy(buf, s0->rx_buf, to_copy);
            if (to_copy < s0->rx_buf_len) {
                memmove(s0->rx_buf, s0->rx_buf + to_copy, s0->rx_buf_len - to_copy);
            }
            s0->rx_buf_len -= to_copy;
            return to_copy;
        }
        
        if (qconn->is_closed || (s0 && s0->fin_received)) {
            return -1;
        }
        
        return 0;
    }

    if (!conn->is_h2) {
        // HTTP/1.1 path: read a record and return it.
        // Loop so we transparently skip TLS 1.3 post-handshake messages
        // (NewSessionTicket / KeyUpdate, inner content type 0x16) and CCS (0x14).
      while (1) {
        uint8_t head[5], iv[12];
        if (read_full(conn->fd, head, 5) <= 0) return -1;
        int rlen = (head[3] << 8) | head[4];
        if (rlen <= 16 || rlen > 20000) return -1;
        uint8_t *rec = malloc(rlen); if (!rec) return -1;
        if (read_full(conn->fd, rec, rlen) <= 0) { free(rec); return -1; }

        int dlen;
        if (conn->is_tls12) {
            if (rlen < 24) { free(rec); return -1; }
            memcpy(iv, conn->server_iv, 4);
            memcpy(iv + 4, rec, 8);

            uint64_t seq = conn->server_seq++;
            uint8_t ad[13];
            ad[0] = (seq >> 56) & 0xff; ad[1] = (seq >> 48) & 0xff;
            ad[2] = (seq >> 40) & 0xff; ad[3] = (seq >> 32) & 0xff;
            ad[4] = (seq >> 24) & 0xff; ad[5] = (seq >> 16) & 0xff;
            ad[6] = (seq >> 8) & 0xff;  ad[7] = seq & 0xff;
            ad[8] = head[0];
            ad[9] = 0x03; ad[10] = 0x03;
            dlen = rlen - 8 - 16;
            ad[11] = (dlen >> 8) & 0xff; ad[12] = dlen & 0xff;

            int decrypt_res = aes_128_gcm_decrypt(conn->server_key, iv, ad, 13, rec + 8, dlen, buf, rec + rlen - 16);
            free(rec);
            if (decrypt_res < 0) return -1;
            // TLS 1.2: outer record type IS the content type
            if (head[0] == 0x15) return -1;     // alert
            if (head[0] == 0x16) continue;       // handshake (e.g. NewSessionTicket) — skip
            return dlen;
        } else {
            tls13_xor_iv(conn->server_iv, conn->server_seq++, iv);
            uint8_t ad[5]; ad[0] = head[0]; ad[1] = head[1]; ad[2] = head[2]; ad[3] = head[3]; ad[4] = head[4];

            int dec_res;
            if (conn->ks_rounds) {
                dec_res = aes_gcm_decrypt_ks(conn->server_key_w, conn->ks_rounds, iv, ad, 5, rec, rlen - 16, buf, rec + rlen - 16);
            } else {
                dec_res = chacha20_poly1305_decrypt(conn->server_key, iv, ad, 5, rec, rlen - 16, buf, rec + rlen - 16);
            }

            free(rec);
            if (dec_res < 0) return -1;
            dlen = dec_res; while (dlen > 0 && ((uint8_t*)buf)[dlen-1] == 0) dlen--; if (dlen > 0) dlen--;
            uint8_t type = ((uint8_t*)buf)[dlen];
            if (type == 0x15) return -1;        // alert
            if (type == 0x16) {                  // handshake (NewSessionTicket / KeyUpdate)
                uint8_t *m = (uint8_t*)buf; int mp = 0;
                while (mp + 4 <= dlen) {
                    int ml = (m[mp+1]<<16)|(m[mp+2]<<8)|m[mp+3];
                    if (mp + 4 + ml > dlen) break;
                    if (m[mp] == 0x04) tls13_store_ticket(conn, m + mp, 4 + ml);
                    mp += 4 + ml;
                }
                continue;                        // skip, read next record
            }
            if (type == 0x14) continue;          // CCS — skip
            return dlen;
        }
      }
    } else {
        // HTTP/2 path: Parse from conn->hs_buf queue
        while (1) {
            // First, try to parse a frame from the existing hs_buf queue
            if (conn->hs_buf_len >= 9) {
                int f_len = (conn->hs_buf[0] << 16) | (conn->hs_buf[1] << 8) | conn->hs_buf[2];
                uint8_t f_type = conn->hs_buf[3];
                uint8_t f_flags = conn->hs_buf[4];
                
                // Safety check: if frame type is invalid, it might be HTTP/1.x plaintext fallback
                if (f_type > 0x09) {
                    int ret_len = (conn->hs_buf_len < len) ? conn->hs_buf_len : len;
                    memcpy(buf, conn->hs_buf, ret_len);
                    conn->hs_buf_len = 0;
                    return ret_len;
                }
                
                if (conn->hs_buf_len >= 9 + f_len) {
#ifdef DEBUG
                    debug("  [h2] Frame type=0x%02x, len=%d, flags=0x%02x\n", f_type, f_len, f_flags);
#endif
                    if (f_type == 0x00 || f_type == 0x01) { // DATA or HEADERS
                        int cpy_len = (f_len < len) ? f_len : len;
                        memcpy(buf, conn->hs_buf + 9, cpy_len);
                        
                        // Shift queue
                        int consumed = 9 + f_len;
                        memmove(conn->hs_buf, conn->hs_buf + consumed, conn->hs_buf_len - consumed);
                        conn->hs_buf_len -= consumed;
                        return cpy_len;
                    } else if (f_type == 0x04) { // SETTINGS
                        if (!(f_flags & 0x01)) { // Not ACK
                            uint8_t ack[] = "\x00\x00\x00\x04\x01\x00\x00\x00\x00";
                            tls_core_send(conn, ack, 9);
                        }
                    } else if (f_type == 0x07) { // GOAWAY
                        uint32_t err = (conn->hs_buf[13] << 24) | (conn->hs_buf[14] << 16) | (conn->hs_buf[15] << 8) | conn->hs_buf[16];
                        debug("  [h2] GOAWAY received! Error=0x%08x\n", err);
                        conn->hs_buf_len = 0;
                        return -1;
                    }
                    
                    // Shift processed non-DATA/HEADERS frame
                    int consumed = 9 + f_len;
                    memmove(conn->hs_buf, conn->hs_buf + consumed, conn->hs_buf_len - consumed);
                    conn->hs_buf_len -= consumed;
                    continue; // Check next frame in queue
                }
            }
            
            // Read next TLS record from socket and decrypt into temp buffer
            uint8_t head[5], iv[12];
            if (read_full(conn->fd, head, 5) <= 0) return -1;
            int rlen = (head[3] << 8) | head[4];
            if (rlen <= 16 || rlen > 20000) return -1;
            uint8_t *rec = malloc(rlen); if (!rec) return -1;
            if (read_full(conn->fd, rec, rlen) <= 0) { free(rec); return -1; }
            
            uint8_t *dec_buf = malloc(rlen);
            if (!dec_buf) { free(rec); return -1; }
            
            int dlen;
            if (conn->is_tls12) {
                if (rlen < 24) { free(rec); free(dec_buf); return -1; }
                memcpy(iv, conn->server_iv, 4);
                memcpy(iv + 4, rec, 8);
                
                uint64_t seq = conn->server_seq++;
                uint8_t ad[13];
                ad[0] = (seq >> 56) & 0xff; ad[1] = (seq >> 48) & 0xff;
                ad[2] = (seq >> 40) & 0xff; ad[3] = (seq >> 32) & 0xff;
                ad[4] = (seq >> 24) & 0xff; ad[5] = (seq >> 16) & 0xff;
                ad[6] = (seq >> 8) & 0xff;  ad[7] = seq & 0xff;
                ad[8] = head[0];
                ad[9] = 0x03; ad[10] = 0x03;
                dlen = rlen - 8 - 16;
                ad[11] = (dlen >> 8) & 0xff; ad[12] = dlen & 0xff;
                
                int decrypt_res = aes_128_gcm_decrypt(conn->server_key, iv, ad, 13, rec + 8, dlen, dec_buf, rec + rlen - 16);
                if (decrypt_res < 0) { free(rec); free(dec_buf); return -1; }
            } else {
                tls13_xor_iv(conn->server_iv, conn->server_seq++, iv);
                uint8_t ad[5]; ad[0] = head[0]; ad[1] = head[1]; ad[2] = head[2]; ad[3] = head[3]; ad[4] = head[4];

                int dec_res;
                if (conn->ks_rounds) {
                    dec_res = aes_gcm_decrypt_ks(conn->server_key_w, conn->ks_rounds, iv, ad, 5, rec, rlen - 16, dec_buf, rec + rlen - 16);
                } else {
                    dec_res = chacha20_poly1305_decrypt(conn->server_key, iv, ad, 5, rec, rlen - 16, dec_buf, rec + rlen - 16);
                }

                if (dec_res < 0) { free(rec); free(dec_buf); return -1; }
                dlen = dec_res; while (dlen > 0 && dec_buf[dlen-1] == 0) dlen--; if (dlen > 0) dlen--;
            }
            
            uint8_t type = conn->is_tls12 ? head[0] : dec_buf[dlen];
            
#ifdef DEBUG
            debug("[nanotls] Recv Record: type=0x%02x, payload_len=%d\n", type, dlen);
#endif
            free(rec);
            
            if (type == 0x15) { // Alert
                debug("[nanotls] Received Alert!\n");
                free(dec_buf);
                return -1;
            }

            if (type == 0x16 && !conn->is_tls12) { // post-handshake (NewSessionTicket)
                uint8_t *m = dec_buf; int mp = 0;
                while (mp + 4 <= dlen) {
                    int ml = (m[mp+1]<<16)|(m[mp+2]<<8)|m[mp+3];
                    if (mp + 4 + ml > dlen) break;
                    if (m[mp] == 0x04) tls13_store_ticket(conn, m + mp, 4 + ml);
                    mp += 4 + ml;
                }
            }

            if (type == 0x17) {
                // Append decrypted record data to connection buffer queue
                if (conn->hs_buf_len + dlen <= (int)sizeof(conn->hs_buf)) {
                    memcpy(conn->hs_buf + conn->hs_buf_len, dec_buf, dlen);
                    conn->hs_buf_len += dlen;
                } else {
                    debug("[nanotls] hs_buf queue overflow!\n");
                    free(dec_buf);
                    return -1;
                }
            }
            free(dec_buf);
        }
    }
}

static const uint8_t *find_hs_msg(const uint8_t *plain, int plain_len,
                                  uint8_t want_type, int *msglen) {
    int off = 0;
    while (off + 4 <= plain_len) {
        uint8_t  type  = plain[off];
        int      mlen  = ((int)plain[off+1] << 16) |
                         ((int)plain[off+2] <<  8) |
                          (int)plain[off+3];
        if (type == want_type) {
            *msglen = mlen + 4;
            return plain + off;
        }
        off += 4 + mlen;
    }
    return NULL;
}

static int extract_crypto_frames(const uint8_t *plain, int plain_len,
                                 uint8_t *out, int max_out) {
    int off = 0, written = 0;
    while (off < plain_len) {
        int vl = 0;
        uint64_t ftype = quic_parse_varint(plain + off, plain_len - off, &vl);
        if (vl == 0) break;
        off += vl;
        if (ftype == 0x00 || ftype == 0x01) { /* PADDING/PING */ continue; }
        if (ftype <= 0x03) { /* ACK */
            quic_parse_varint(plain + off, plain_len - off, &vl); off += vl; /* largest acked */
            quic_parse_varint(plain + off, plain_len - off, &vl); off += vl; /* delay */
            uint64_t cnt = quic_parse_varint(plain + off, plain_len - off, &vl); off += vl;
            quic_parse_varint(plain + off, plain_len - off, &vl); off += vl; /* first range */
            for (uint64_t i = 0; i < cnt; i++) {
                quic_parse_varint(plain + off, plain_len - off, &vl); off += vl;
                quic_parse_varint(plain + off, plain_len - off, &vl); off += vl;
            }
            continue;
        }
        if (ftype == 0x06) { /* CRYPTO */
            quic_parse_varint(plain + off, plain_len - off, &vl); off += vl; /* offset */
            uint64_t len = quic_parse_varint(plain + off, plain_len - off, &vl); off += vl;
            if (off + len > plain_len) break;
            if (written + len <= max_out) {
                memcpy(out + written, plain + off, len);
                written += (int)len;
            }
            off += len;
            continue;
        }
        off -= vl;
        int skipped = quic_skip_frame(plain + off, plain_len - off);
        if (skipped <= 0) break;
        off += skipped;
    }
    return written;
}

static void *nanotls_try_quic(struct sockaddr_in* addr, const char* host) {
    printf("[nanotls] Attempting HTTP/3 (QUIC) over UDP to %s...\n", host);

    quic_conn *conn = quic_connect(addr, host);
    if (!conn) {
        printf("[nanotls] HTTP/3 socket or connection setup failed.\n");
        return NULL;
    }

    uint8_t ch_buf[1024];
    int ch_len = tls13_client_hello(ch_buf, host,
                                    conn->dcid, conn->dcid_len,
                                    conn->scid, conn->scid_len,
                                    conn->pub_key);

    sha256_ctx_t transcript256;
    sha384_ctx_t transcript384;
    sha256_init(&transcript256);
    sha384_init(&transcript384);
    sha256_update(&transcript256, ch_buf, ch_len);
    sha384_update(&transcript384, ch_buf, ch_len);

    quic_send_initial(conn, host, ch_buf, ch_len, NULL, 0);

    uint8_t server_pub[32];
    uint8_t shared[32];
    uint8_t c_hs_key[32], c_hs_iv[12], c_hs_hp[32];
    uint8_t s_hs_key[32], s_hs_iv[12], s_hs_hp[32];

    int sh_done     = 0;
    int hs_done     = 0;
    int retry_count = 0;

    uint8_t pkt[4096], plain[4096];
    uint8_t crypto_data[16384];
    int crypto_fill = 0;
    struct sockaddr_in from;
    socklen_t fromlen;

    struct timeval tv;
    tv.tv_sec = 0; tv.tv_usec = 50000; // 50ms read timeout
    setsockopt(conn->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    uint64_t start_time = get_time_us();

    while (!hs_done) {
        if (get_time_us() - start_time > 800000) { // 800ms limit
            printf("[nanotls] HTTP/3 over QUIC handshake timed out (exceeded 800ms limit).\n");
            break;
        }
        quic_check_pto(conn);
        fromlen = sizeof(from);
        memset(pkt, 0, sizeof(pkt));
        int n = recvfrom(conn->fd, pkt, sizeof(pkt), 0,
                             (struct sockaddr *)&from, &fromlen);
        if (n <= 0) {
            continue;
        }

        uint8_t hdr = pkt[0];

        if ((hdr & 0xF0) == 0xF0) {
            if (retry_count++ > 2) { break; }
            uint8_t token[256]; int tlen = 0;
            if (quic_parse_retry(pkt, n, conn->dcid, &conn->dcid_len,
                                 token, &tlen) == 0) {
                sha256_init(&transcript256); sha384_init(&transcript384);
                ch_len = tls13_client_hello(ch_buf, host,
                                            conn->dcid, conn->dcid_len,
                                            conn->scid, conn->scid_len,
                                            conn->pub_key);
                sha256_update(&transcript256, ch_buf, ch_len);
                sha384_update(&transcript384, ch_buf, ch_len);
                conn->c_initial_pn = 1;
                quic_send_initial(conn, host, ch_buf, ch_len, token, tlen);
            }
            continue;
        }

        if ((hdr & 0x80) && ((hdr & 0x30) >> 4) == 0) {
            int consumed = 0;
            int plen = quic_decrypt_initial(conn, pkt, n, plain, &consumed);
            if (plen < 0) continue;

            int crypto_len = extract_crypto_frames(plain, plen, crypto_data, sizeof(crypto_data));
            if (crypto_len <= 0) {
                send_initial_ack(conn);
                continue;
            }

            int msglen = 0;
            const uint8_t *sh = find_hs_msg(crypto_data, crypto_len, 0x02, &msglen);
            if (sh && !sh_done) {
                if (!quic_parse_server_hello(sh, msglen, server_pub, &conn->cipher_suite)) {
                    quic_close(conn);
                    return NULL;
                }
                x25519(shared, conn->priv_key, server_pub);
                if (conn->cipher_suite == 0x1302) {
                    sha384_update(&transcript384, sh, msglen);
                    sha384_ctx_t tmp = transcript384;
                    uint8_t th[48]; sha384_final(&tmp, th);
                    quic_derive_handshake_secrets(conn, shared, th,
                                                 c_hs_key, c_hs_iv, c_hs_hp,
                                                 s_hs_key, s_hs_iv, s_hs_hp);
                } else {
                    sha256_update(&transcript256, sh, msglen);
                    sha256_ctx_t tmp = transcript256;
                    uint8_t th[32]; sha256_final(&tmp, th);
                    quic_derive_handshake_secrets(conn, shared, th,
                                                 c_hs_key, c_hs_iv, c_hs_hp,
                                                 s_hs_key, s_hs_iv, s_hs_hp);
                }
                sh_done = 1;
            }
            send_initial_ack(conn);
            continue;
        }

        if (sh_done && (hdr & 0x80) && ((hdr & 0x30) >> 4) == 2) {
            int consumed = 0;
            int plen = quic_decrypt_handshake(conn, pkt, n,
                                              s_hs_key, s_hs_iv, s_hs_hp,
                                              plain, &consumed);
            if (plen < 0) continue;

            int new_crypto = extract_crypto_frames(plain, plen,
                                                   crypto_data + crypto_fill,
                                                   (int)sizeof(crypto_data) - crypto_fill);
            crypto_fill += new_crypto;
            int parsed = 0;
            while (parsed + 4 <= crypto_fill) {
                uint8_t  mtype = crypto_data[parsed];
                int      mlen  = ((int)crypto_data[parsed+1] << 16) |
                                 ((int)crypto_data[parsed+2] <<  8) |
                                  (int)crypto_data[parsed+3];
                int total = 4 + mlen;
                if (parsed + total > crypto_fill) break;

                if (mtype != 0x14) {
                    if (conn->cipher_suite == 0x1302)
                        sha384_update(&transcript384, crypto_data + parsed, total);
                    else
                        sha256_update(&transcript256, crypto_data + parsed, total);
                }

                if (mtype == 0x14) {
                    if (conn->cipher_suite == 0x1302) {
                        sha384_update(&transcript384, crypto_data + parsed, total);
                        uint8_t th[48]; sha384_final(&transcript384, th);
                        quic_derive_application_secrets(conn, th);
                        quic_send_finished(conn, th, c_hs_key, c_hs_iv, c_hs_hp);
                    } else {
                        sha256_update(&transcript256, crypto_data + parsed, total);
                        uint8_t th[32]; sha256_final(&transcript256, th);
                        quic_derive_application_secrets(conn, th);
                        quic_send_finished(conn, th, c_hs_key, c_hs_iv, c_hs_hp);
                    }
                    hs_done = 1;
                }
                parsed += total;
            }
            if (parsed > 0 && parsed < crypto_fill) {
                memcpy(crypto_data, crypto_data + parsed, crypto_fill - parsed);
            }
            crypto_fill -= parsed;

            send_handshake_ack(conn, c_hs_key, c_hs_iv, c_hs_hp);
            continue;
        }
    }

    if (!hs_done) {
        quic_close(conn);
        return NULL;
    }

    printf("[nanotls] HTTP/3 over QUIC handshake successful!\n");
    return conn;
}

void tls_core_close(nanotls_conn* conn) {
    if (!conn) return;
    if (conn->is_quic) {
        if (conn->quic_conn_ptr) {
            quic_close((quic_conn *)conn->quic_conn_ptr);
        }
    } else {
        close(conn->fd);
    }
    free(conn);
}

int tls_core_init(void) { return 0; }
void tls_core_cleanup(void) {}

static nanotls_conn *tcp_try_connect(struct sockaddr_in *addr, const char *host) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return NULL;
    struct timeval tv; tv.tv_sec = 5; tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (connect(fd, (struct sockaddr *)addr, sizeof(*addr)) < 0) { close(fd); return NULL; }
    nanotls_conn *conn = malloc(sizeof(nanotls_conn));
    if (!conn) { close(fd); return NULL; }
    memset(conn, 0, sizeof(nanotls_conn)); conn->fd = fd;
    if (tls13_handshake(conn, host) < 0) { free(conn); close(fd); return NULL; }
    return conn;
}

nanotls_conn* tls_core_connect_addr(struct sockaddr_in* addr, const char* host) {
    int orig_tls13 = current_proto_tls13;
    int orig_tls12 = current_proto_tls12;
    char orig_alpn[32];
    int orig_alpn_len = current_alpn_len;
    int orig_mode_h2 = current_mode_h2;
    memcpy(orig_alpn, current_alpn, 32);

#define RESTORE_CONFIG() do { \
    current_proto_tls13 = orig_tls13; current_proto_tls12 = orig_tls12; \
    current_alpn_len = orig_alpn_len; current_mode_h2 = orig_mode_h2; \
    memcpy(current_alpn, orig_alpn, 32); } while(0)

    // 1. Try HTTP/3 over QUIC first if enabled
    if (current_proto_quic) {
        void *qconn = nanotls_try_quic(addr, host);
        if (qconn) {
            nanotls_conn *conn = malloc(sizeof(nanotls_conn));
            if (!conn) { quic_close((quic_conn *)qconn); RESTORE_CONFIG(); return NULL; }
            memset(conn, 0, sizeof(nanotls_conn));
            conn->is_quic = 1; conn->quic_conn_ptr = qconn;
            conn->sni_host = host; conn->fd = ((quic_conn *)qconn)->fd;
            RESTORE_CONFIG(); return conn;
        }
        printf("[nanotls] HTTP/3 over QUIC failed or was rejected. Falling back to HTTP/2...\n\n");
    }

    // 2. Try HTTP/2 over TCP/TLS if h2 mode configured
    if (orig_mode_h2) {
        current_alpn_len = 0;
        current_alpn[current_alpn_len++] = 2;
        current_alpn[current_alpn_len++] = 'h';
        current_alpn[current_alpn_len++] = '2';
        current_alpn[current_alpn_len] = '\0';
        current_mode_h2 = 1;
        printf("[nanotls] Attempting HTTP/2 over TCP/TLS to %s...\n", host);

        if (orig_tls13) {
            current_proto_tls13 = 1; current_proto_tls12 = orig_tls12;
            nanotls_conn *conn = tcp_try_connect(addr, host);
            if (conn && conn->is_h2) { RESTORE_CONFIG(); return conn; }
            if (conn) { close(conn->fd); free(conn); }
        }
        if (orig_tls12) {
            current_proto_tls13 = 0; current_proto_tls12 = 1;
            nanotls_conn *conn = tcp_try_connect(addr, host);
            if (conn && conn->is_h2) { RESTORE_CONFIG(); return conn; }
            if (conn) { close(conn->fd); free(conn); }
        }
        printf("[nanotls] HTTP/2 over TCP/TLS failed or was rejected. Falling back to HTTP/1.1...\n\n");
    }

    // 3. Fallback: Try HTTP/1.1
    current_alpn_len = 0;
    current_alpn[current_alpn_len++] = 8;
    memcpy(current_alpn + current_alpn_len, "http/1.1", 8);
    current_alpn_len += 8;
    current_alpn[current_alpn_len] = '\0';
    current_mode_h2 = 0;
    printf("[nanotls] Attempting HTTP/1.1 over TCP/TLS to %s...\n", host);

    if (orig_tls13) {
        current_proto_tls13 = 1; current_proto_tls12 = orig_tls12;
        nanotls_conn *conn = tcp_try_connect(addr, host);
        if (conn) { RESTORE_CONFIG(); return conn; }
    }
    if (orig_tls12) {
        current_proto_tls13 = 0; current_proto_tls12 = 1;
        nanotls_conn *conn = tcp_try_connect(addr, host);
        if (conn) { RESTORE_CONFIG(); return conn; }
    }

    RESTORE_CONFIG();
#undef RESTORE_CONFIG
    return NULL;
}

void tls_clear_headers(nanotls_conn *conn) {
    conn->headers_count = 0;
}

void tls_add_header(nanotls_conn *conn, const char *name, const char *value) {
    if (conn->headers_count >= 32) return;
    int idx = conn->headers_count++;
    strncpy(conn->headers[idx].name, name, sizeof(conn->headers[idx].name) - 1);
    conn->headers[idx].name[sizeof(conn->headers[idx].name) - 1] = '\0';
    strncpy(conn->headers[idx].value, value, sizeof(conn->headers[idx].value) - 1);
    conn->headers[idx].value[sizeof(conn->headers[idx].value) - 1] = '\0';
}

void tls_mode_impl(int count, ...) {
    current_alpn_len = 0;
    current_mode_h2 = 0;

    __builtin_va_list args;
    __builtin_va_start(args, count);
    
    for (int i = 0; i < count; i++) {
        const char *curr = __builtin_va_arg(args, const char *);
        if (strcmp(curr, "h2") == 0) {
            current_alpn[current_alpn_len++] = 2;
            current_alpn[current_alpn_len++] = 'h';
            current_alpn[current_alpn_len++] = '2';
            current_mode_h2 = 1;
        } else if (strcmp(curr, "http/1.1") == 0) {
            current_alpn[current_alpn_len++] = 8;
            memcpy(current_alpn + current_alpn_len, "http/1.1", 8);
            current_alpn_len += 8;
        } else if (strcmp(curr, "dot") == 0) {
            current_alpn[current_alpn_len++] = 3;
            memcpy(current_alpn + current_alpn_len, "dot", 3);
            current_alpn_len += 3;
        }
    }
    __builtin_va_end(args);
    current_alpn[current_alpn_len] = '\0';
}

void protocol_mode_impl(int count, ...) {
    current_proto_tls13 = 0;
    current_proto_tls12 = 0;
    current_proto_quic = 0;

    __builtin_va_list args;
    __builtin_va_start(args, count);
    
    for (int i = 0; i < count; i++) {
        const char *curr = __builtin_va_arg(args, const char *);
        if (strcmp(curr, "1.3") == 0 || strcmp(curr, "tls1.3") == 0 || strcmp(curr, "h2") == 0 || strcmp(curr, "http/1.1") == 0) {
            current_proto_tls13 = 1;
        }
        if (strcmp(curr, "1.2") == 0 || strcmp(curr, "tls1.2") == 0 || strcmp(curr, "h2") == 0 || strcmp(curr, "http/1.1") == 0) {
            current_proto_tls12 = 1;
        }
        if (strcmp(curr, "quic") == 0 || strcmp(curr, "h3") == 0) {
            current_proto_quic = 1;
        }
    }
    __builtin_va_end(args);
}

static void h2_encode_int(uint8_t *out, int *off, uint32_t val, int prefix_bits) {
    uint32_t mask = (1 << prefix_bits) - 1;
    if (val < mask) {
        out[(*off)++] |= (uint8_t)val;
    } else {
        out[(*off)++] |= (uint8_t)mask;
        val -= mask;
        while (val >= 128) {
            out[(*off)++] = (uint8_t)((val & 127) | 128);
            val >>= 7;
        }
        out[(*off)++] = (uint8_t)val;
    }
}

static void h2_add_header_literal(uint8_t *out, int *off, const char *name, const char *value, int name_idx) {
    if (name_idx > 0) {
        // Literal Header Field Without Indexing - Indexed Name (Prefix 0000 = 0x00, 4-bit index)
        out[*off] = 0x00;
        h2_encode_int(out, off, name_idx, 4);
    } else {
        // Literal Header Field Without Indexing - New Name (Index 0)
        out[*off] = 0x00;
        h2_encode_int(out, off, 0, 4);
        int nlen = strlen(name);
        out[*off] = 0; // Initialize byte for length
        h2_encode_int(out, off, nlen, 7);
        memcpy(out + *off, name, nlen); *off += nlen;
    }
    int vlen = strlen(value);
    out[*off] = 0; // Initialize byte for length
    h2_encode_int(out, off, vlen, 7);
    memcpy(out + *off, value, vlen); *off += vlen;
}

int tls_send_request(nanotls_conn *conn, const char *method, const char *path) {
    if (conn->is_quic) {
        quic_conn *qconn = (quic_conn *)conn->quic_conn_ptr;
        quic_clear_headers(qconn);
        for (int i = 0; i < conn->headers_count; i++) {
            quic_add_header(qconn, conn->headers[i].name, conn->headers[i].value);
        }
        send_http3_get(qconn, conn->sni_host ? conn->sni_host : "localhost", path, method, NULL, NULL);
        return 1;
    }

    if (!conn->is_h2) {
        char buf[8192];
        int rem = (int)sizeof(buf);
        int len = snprintf(buf, rem, "%s %s HTTP/1.1\r\n", method, path);
        if (len < 0 || len >= rem) return -1;
        int has_host = 0;
        for (int i = 0; i < conn->headers_count; i++) {
            int is_host = 1;
            for (int j = 0; conn->headers[i].name[j] || "host"[j]; j++) {
                char c1 = conn->headers[i].name[j];
                char c2 = "host"[j];
                if (c1 >= 'A' && c1 <= 'Z') c1 += 32;
                if (c1 != c2) { is_host = 0; break; }
            }
            if (is_host) has_host = 1;
            int n = snprintf(buf + len, rem - len, "%s: %s\r\n", conn->headers[i].name, conn->headers[i].value);
            if (n < 0 || n >= rem - len) return -1;
            len += n;
        }
        if (!has_host && conn->sni_host) {
            int n = snprintf(buf + len, rem - len, "Host: %s\r\n", conn->sni_host);
            if (n < 0 || n >= rem - len) return -1;
            len += n;
        }
        if (rem - len < 3) return -1;
        len += snprintf(buf + len, rem - len, "\r\n");
        return tls_core_send(conn, buf, len);
    } else {
        uint8_t buf[8192]; int off = 0;
        memcpy(buf + off, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24); off += 24;
        // 2. SETTINGS Frame (24 bytes payload)
        memcpy(buf + off, "\x00\x00\x18\x04\x00\x00\x00\x00\x00", 9); off += 9;
        memcpy(buf + off, "\x00\x01\x00\x01\x00\x00", 6); off += 6;
        memcpy(buf + off, "\x00\x02\x00\x00\x00\x00", 6); off += 6;
        memcpy(buf + off, "\x00\x04\x00\x60\x00\x00", 6); off += 6;
        memcpy(buf + off, "\x00\x06\x00\x04\x00\x00", 6); off += 6;
        
        // 3. WINDOW_UPDATE Frame (stream 0, increment 15663105 = 0x00EF0001)
        memcpy(buf + off, "\x00\x00\x04\x08\x00\x00\x00\x00\x00\x00\xEF\x00\x01", 13); off += 13;
        
        // 4. HEADERS Frame (Stream 1, End Headers, End Stream)
        int h_off = off; off += 9;
        
        // Pseudo-headers using HPACK static table references to match browser fingerprinting exactly
        if (strcmp(method, "GET") == 0) {
            buf[off++] = 0x82; // Indexed: :method: GET (Index 2)
        } else if (strcmp(method, "POST") == 0) {
            buf[off++] = 0x83; // Indexed: :method: POST (Index 3)
        } else {
            h2_add_header_literal(buf, &off, ":method", method, 0);
        }

        h2_add_header_literal(buf, &off, ":authority", conn->sni_host ? conn->sni_host : "localhost", 1); // Index 1
        
        buf[off++] = 0x87; // Indexed: :scheme: https (Index 7)
        
        if (strcmp(path, "/") == 0) {
            buf[off++] = 0x84; // Indexed: :path: / (Index 4)
        } else {
            h2_add_header_literal(buf, &off, ":path", path, 4); // Index 4
        }
        
        for (int i = 0; i < conn->headers_count; i++) {
            h2_add_header_literal(buf, &off, conn->headers[i].name, conn->headers[i].value, 0);
        }
        
        int h_len = off - h_off - 9;
        buf[h_off + 0] = (h_len >> 16) & 0xFF;
        buf[h_off + 1] = (h_len >> 8) & 0xFF;
        buf[h_off + 2] = h_len & 0xFF;
        buf[h_off + 3] = 0x01; // HEADERS
        buf[h_off + 4] = 0x05; // END_STREAM | END_HEADERS
        buf[h_off + 5] = 0x00; buf[h_off + 6] = 0x00; buf[h_off + 7] = 0x00; buf[h_off + 8] = 0x01; // Stream 1
        
#ifdef DEBUG
        debug("  [h2] Outgoing raw HTTP/2 payload bytes (%d bytes):\n", off);
        for (int i = 0; i < off; i++) {
            debug("%02x ", buf[i]);
            if ((i + 1) % 16 == 0) debug("\n");
        }
        if (off % 16 != 0) debug("\n");
#endif

        return tls_core_send(conn, buf, off);
    }
}
