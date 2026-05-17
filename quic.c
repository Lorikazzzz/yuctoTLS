#include "headers/includes.h"
#include "headers/quic.h"
#include "headers/crypto.h"

#include "headers/nanotls.h"


/* #undef printf */
/* #define printf(...) */

static const uint8_t initial_salt_v1[20] = {
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
    0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a
};

static const uint8_t sha256_empty[32] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55
};

static void quic_parse_frames(quic_conn *conn, uint8_t *payload, int len, int epoch);

static void quic_hkdf_expand_label(uint8_t *out, const uint8_t *secret, const char *label, uint16_t out_len) {
    uint8_t hkdf_label[64];
    int label_len = strlen(label);
    int off = 0;
    hkdf_label[off++] = out_len >> 8;
    hkdf_label[off++] = out_len & 0xFF;
    hkdf_label[off++] = (uint8_t)(label_len + 6);
    memcpy(hkdf_label + off, "tls13 ", 6); off += 6;
    memcpy(hkdf_label + off, label, label_len); off += label_len;
    hkdf_label[off++] = 0;
    hkdf_sha256_expand(secret, hkdf_label, off, out, out_len);
}

static void quic_hkdf_derive_secret(uint8_t *out, const uint8_t *secret, const char *label, const uint8_t *transcript_hash) {
    uint8_t hkdf_label[64];
    int label_len = strlen(label);
    int off = 0;
    hkdf_label[off++] = 0x00; hkdf_label[off++] = 0x20;
    hkdf_label[off++] = (uint8_t)(label_len + 6);
    memcpy(hkdf_label + off, "tls13 ", 6); off += 6;
    memcpy(hkdf_label + off, label, label_len); off += label_len;
    hkdf_label[off++] = 32;
    memcpy(hkdf_label + off, transcript_hash, 32); off += 32;
    hkdf_sha256_expand(secret, hkdf_label, off, out, 32);
}

uint64_t quic_parse_varint(const uint8_t *p, int max_len, int *len) {
    if (max_len < 1) return 0;
    uint8_t first = p[0];
    int type = first >> 6;
    if (type == 0) { *len = 1; return first & 0x3F; }
    if (type == 1) { if (max_len < 2) return 0; *len = 2; return ((uint64_t)(first & 0x3F) << 8) | p[1]; }
    if (type == 2) { if (max_len < 4) return 0; *len = 4; return ((uint64_t)(first & 0x3F) << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3]; }
    if (max_len < 8) return 0; *len = 8;
    return ((uint64_t)(first & 0x3F) << 56) | ((uint64_t)p[1] << 48) | ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32) | ((uint64_t)p[4] << 24) | ((uint32_t)p[5] << 16) | ((uint32_t)p[6] << 8) | p[7];
}

int put_varint(uint8_t *p, uint64_t val) {
    if (val < 64) { p[0] = (uint8_t)val; return 1; }
    else if (val < 16384) { p[0] = 0x40 | (uint8_t)(val >> 8); p[1] = (uint8_t)(val & 0xFF); return 2; }
    else if (val < 1073741824) { p[0] = 0x80 | (uint8_t)(val >> 24); p[1] = (uint8_t)((val >> 16) & 0xFF); p[2] = (uint8_t)((val >> 8) & 0xFF); p[3] = (uint8_t)(val & 0xFF); return 4; }
    else { p[0] = 0xC0 | (uint8_t)(val >> 56); p[1] = (uint8_t)((val >> 48) & 0xFF); p[2] = (uint8_t)((val >> 40) & 0xFF); p[3] = (uint8_t)((val >> 32) & 0xFF); p[4] = (uint8_t)((val >> 24) & 0xFF); p[5] = (uint8_t)((val >> 16) & 0xFF); p[6] = (uint8_t)((val >> 8) & 0xFF); p[7] = (uint8_t)(val & 0xFF); return 8; }
}

static void quic_derive_initial_secrets(const uint8_t *cid, int cid_len, const char *direction, uint8_t *key, uint8_t *iv, uint8_t *hp) {
    uint8_t initial_secret[32], traffic_secret[32];
    hkdf_sha256_extract(initial_salt_v1, 20, cid, cid_len, initial_secret);
    quic_hkdf_expand_label(traffic_secret, initial_secret, direction, 32);
    quic_hkdf_expand_label(key, traffic_secret, "quic key", 16);
    quic_hkdf_expand_label(iv,  traffic_secret, "quic iv",  12);
    quic_hkdf_expand_label(hp,  traffic_secret, "quic hp",  16);
}

void quic_derive_client_initial_secrets(const uint8_t *cid, int cid_len, uint8_t *key, uint8_t *iv, uint8_t *hp) { quic_derive_initial_secrets(cid, cid_len, "client in", key, iv, hp); }
void quic_derive_server_initial_secrets(const uint8_t *cid, int cid_len, uint8_t *key, uint8_t *iv, uint8_t *hp) { quic_derive_initial_secrets(cid, cid_len, "server in", key, iv, hp); }

void quic_derive_handshake_secrets(quic_conn *conn, const uint8_t *shared_secret, const uint8_t *transcript_hash, uint8_t *c_key, uint8_t *c_iv, uint8_t *c_hp, uint8_t *s_key, uint8_t *s_iv, uint8_t *s_hp) {
    uint8_t derived_secret[32], early_secret[32], zero[32] = {0};
    hkdf_sha256_extract(zero, 32, zero, 32, early_secret);
    quic_hkdf_derive_secret(derived_secret, early_secret, "derived", sha256_empty);
    hkdf_sha256_extract(derived_secret, 32, shared_secret, 32, conn->handshake_secret);
    quic_hkdf_derive_secret(conn->c_hs_secret, conn->handshake_secret, "c hs traffic", transcript_hash);
    uint8_t s_hs_secret[32];
    quic_hkdf_derive_secret(s_hs_secret, conn->handshake_secret, "s hs traffic", transcript_hash);
    quic_hkdf_expand_label(c_key, conn->c_hs_secret, "quic key", 16);
    quic_hkdf_expand_label(c_iv, conn->c_hs_secret, "quic iv", 12);
    quic_hkdf_expand_label(c_hp, conn->c_hs_secret, "quic hp", 16);
    quic_hkdf_expand_label(s_key, s_hs_secret, "quic key", 16);
    quic_hkdf_expand_label(s_iv, s_hs_secret, "quic iv", 12);
    quic_hkdf_expand_label(s_hp, s_hs_secret, "quic hp", 16);
}

void quic_derive_application_secrets(quic_conn *conn, const uint8_t *transcript_hash) {
    uint8_t derived_secret[32], zero[32] = {0};
    quic_hkdf_derive_secret(derived_secret, conn->handshake_secret, "derived", sha256_empty);
    hkdf_sha256_extract(derived_secret, 32, zero, 32, conn->master_secret);
    uint8_t c_secret[32], s_secret[32];
    quic_hkdf_derive_secret(c_secret, conn->master_secret, "c ap traffic", transcript_hash);
    quic_hkdf_derive_secret(s_secret, conn->master_secret, "s ap traffic", transcript_hash);
    quic_hkdf_expand_label(conn->c_app_key, c_secret, "quic key", 16);
    quic_hkdf_expand_label(conn->c_app_iv,  c_secret, "quic iv",  12);
    quic_hkdf_expand_label(conn->c_app_hp,  c_secret, "quic hp",  16);
    quic_hkdf_expand_label(conn->s_app_key, s_secret, "quic key", 16);
    quic_hkdf_expand_label(conn->s_app_iv,  s_secret, "quic iv",  12);
    quic_hkdf_expand_label(conn->s_app_hp,  s_secret, "quic hp",  16);
}

quic_conn *quic_connect(struct sockaddr_in *addr, const char *host) {
    (void)host; /* hostname is used during send_initial by caller */
    quic_conn *conn = malloc(sizeof(quic_conn));
    if (!conn) return NULL;
    memset(conn, 0, sizeof(quic_conn));
    conn->fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in local; memset(&local, 0, sizeof(local));
    local.sin_family = AF_INET; local.sin_addr.s_addr = 0; local.sin_port = 0;
    bind(conn->fd, (struct sockaddr *)&local, sizeof(local)); /* IPPROTO_UDP, 0=auto */
    if (conn->fd < 0) {
        printf("[quic] socket failed (fd=%d)\n", conn->fd);
        free(conn); return NULL;
    }
    /* 500ms receive timeout */
    struct timeval tv; tv.tv_sec = 0; tv.tv_usec = 500000;
    setsockopt(conn->fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    memcpy(&conn->addr, addr, sizeof(struct sockaddr_in));
    /* QUIC version and connection IDs */
    conn->version = QUIC_VERSION_1;
    conn->dcid_len = 20; bot_prng_generate_block(conn->dcid, 20);
    conn->original_dcid_len = 20; memcpy(conn->original_dcid, conn->dcid, 20);
    conn->scid_len = 20; bot_prng_generate_block(conn->scid, 20);
    /* Ephemeral x25519 keypair */
    bot_prng_generate_block(conn->priv_key, 32);
    x25519_base(conn->pub_key, conn->priv_key);
    /* Packet number counters */
    conn->c_initial_pn = 1; conn->c_hs_pn = 0; conn->c_app_pn = 0;
    conn->s_app_pn_next = 0; conn->s_initial_pn_max = 0; conn->s_hs_pn_max = 0;
    /* Stream state */
    conn->max_streams_bidi = 1000; conn->next_sid = 0;
    conn->h3_initialized = 0; conn->h3_headers_count = 0;
    conn->http_response_received = 0; conn->is_closed = 0;
    conn->token_len = 0;
    return conn;
}

void quic_send_initial_raw(quic_conn *conn, const uint8_t *payload, int plen, const uint8_t *token, int token_len) {
    uint8_t pkt[1500]; int off = 0;
    pkt[off++] = 0xC3; // 4-byte PN
    pkt[off++] = (uint8_t)(conn->version >> 24); pkt[off++] = (uint8_t)(conn->version >> 16); pkt[off++] = (uint8_t)(conn->version >> 8); pkt[off++] = (uint8_t)conn->version;
    pkt[off++] = conn->dcid_len; memcpy(pkt + off, conn->dcid, conn->dcid_len); off += conn->dcid_len;
    pkt[off++] = conn->scid_len; memcpy(pkt + off, conn->scid, conn->scid_len); off += conn->scid_len;
    if (token_len > 0) {
        if (token_len < 64) pkt[off++] = (uint8_t)token_len;
        else { pkt[off++] = 0x40 | (token_len >> 8); pkt[off++] = (token_len & 0xFF); }
        memcpy(pkt + off, token, token_len); off += token_len;
    } else pkt[off++] = 0;
    int len_pos = off; off += 2; int pn_pos = off;
    uint32_t cpn = (uint32_t)conn->c_initial_pn;
    pkt[off++] = (uint8_t)(cpn >> 24); pkt[off++] = (uint8_t)(cpn >> 16); pkt[off++] = (uint8_t)(cpn >> 8); pkt[off++] = (uint8_t)cpn;

    pkt[len_pos] = 0x40 | ((plen+4+16) >> 8); pkt[len_pos+1] = (plen+4+16) & 0xFF;
    uint8_t c_key[16], c_iv[12], c_hp[16];
    quic_derive_client_initial_secrets(conn->original_dcid, conn->original_dcid_len, c_key, c_iv, c_hp);
    uint8_t nonce[12]; memcpy(nonce, c_iv, 12); for (int i = 0; i < 8; i++) nonce[11-i] ^= (uint8_t)((uint64_t)cpn >> (i*8));
    aes_128_gcm_encrypt(c_key, nonce, pkt, pn_pos + 4, payload, plen, pkt + pn_pos + 4, pkt + pn_pos + 4 + plen);
    uint8_t mask[16]; aes_128_ecb_encrypt(c_hp, pkt + pn_pos + 4, mask);
    pkt[0] ^= (mask[0] & 0x0F); 
    pkt[pn_pos] ^= mask[1]; pkt[pn_pos+1] ^= mask[2]; pkt[pn_pos+2] ^= mask[3]; pkt[pn_pos+3] ^= mask[4];
    int final_len = pn_pos + 4 + plen + 16;
    sendto(conn->fd, pkt, final_len, 0, (struct sockaddr *)&conn->addr, sizeof(conn->addr));
    
    quic_add_to_sent_queue(conn, 0, conn->c_initial_pn, payload, plen);
    conn->c_initial_pn++;
}

void quic_send_initial(quic_conn *conn, const char *host, const uint8_t *ch_payload, int ch_len, const uint8_t *token, int token_len) {
    if (token_len > 0 && token_len <= 256) {
        memcpy(conn->token, token, token_len);
        conn->token_len = token_len;
    }
    uint8_t payload[1500]; int plen = 0;
    payload[plen++] = 0x06; payload[plen++] = 0; payload[plen++] = 0x40 | (ch_len >> 8); payload[plen++] = (ch_len & 0xFF);
    memcpy(payload + plen, ch_payload, ch_len); plen += ch_len;
    
    int dcid_len = conn->dcid_len;
    int scid_len = conn->scid_len;
    int token_len_varint = (token_len > 0) ? ((token_len < 64) ? 1 : 2) : 1;
    int pn_pos = 1 + 4 + 1 + dcid_len + 1 + scid_len + token_len_varint + token_len + 2;
    int target_plen = 1200 - pn_pos - 4 - 16;
    if (target_plen < plen) target_plen = plen;
    while (plen < target_plen) payload[plen++] = 0x00;

    quic_send_initial_raw(conn, payload, plen, token, token_len);
}

void send_1rtt_ack(quic_conn *conn);

int quic_decrypt_initial(quic_conn *conn, uint8_t *pkt, int len, uint8_t *out, int *consumed_len) {
    if (len < 5) return -1;
    uint8_t s_key[16], s_iv[12], s_hp[16];
    quic_derive_server_initial_secrets(conn->original_dcid, conn->original_dcid_len, s_key, s_iv, s_hp);
    int off = 5;
    uint8_t dcid_len = pkt[off++]; off += dcid_len;
    uint8_t scid_len = pkt[off++]; off += scid_len;
    int l = 0;
    uint64_t tlen = quic_parse_varint(pkt + off, len - off, &l); off += l + (int)tlen;
    int plen = (int)quic_parse_varint(pkt + off, len - off, &l); off += l;
    if (consumed_len) *consumed_len = off + plen;
    
    uint8_t mask[16]; aes_128_ecb_encrypt(s_hp, pkt + off + 4, mask);
    uint8_t first = pkt[0] ^ (mask[0] & 0x0F);
    int pn_len = (first & 0x03) + 1; uint32_t pn = 0;
    for (int i = 0; i < pn_len; i++) { uint8_t b = pkt[off+i] ^ mask[1+i]; pn = (pn << 8) | b; }
    
    uint8_t nonce[12]; memcpy(nonce, s_iv, 12); for (int i = 0; i < 8; i++) nonce[11-i] ^= (uint8_t)((uint64_t)pn >> (i*8));
    uint8_t saved_first = pkt[0]; pkt[0] = first;
    uint8_t pn_bytes[4]; for(int i=0; i<pn_len; i++) { pn_bytes[i] = pkt[off+i]; pkt[off+i] ^= mask[1+i]; }
    
    int ret = aes_128_gcm_decrypt(s_key, nonce, pkt, off + pn_len, pkt + off + pn_len, plen - pn_len - 16, out, pkt + off + plen - 16);
    pkt[0] = saved_first; for(int i=0; i<pn_len; i++) pkt[off+i] = pn_bytes[i];

    if (ret >= 0) {
        printf("[quic-demo] Decrypted Initial (%d bytes)\n", ret);
        if (pn > conn->s_initial_pn_max) conn->s_initial_pn_max = pn;
        quic_add_received_pn(conn, 0, pn);
        if (scid_len > 0 && scid_len <= 20) {
            conn->dcid_len = scid_len; memcpy(conn->dcid, pkt + 5 + 1 + dcid_len + 1, scid_len);
        }
    } else {
        printf("[quic-error] Initial Decrypt Failed!\n");
    }
    return ret;
}

int quic_decrypt_handshake(quic_conn *conn, uint8_t *pkt, int len, const uint8_t *s_key, const uint8_t *s_iv, const uint8_t *s_hp, uint8_t *out, int *consumed_len) {
    if (len < 7) return -1;
    // Parse header precisely: 1(first) + 4(ver) + 1(dcid_len) + dcid + 1(scid_len) + scid + varint(pktlen)
    int off = 5;
    int dcid_len = pkt[off++];          // read DCID length
    if (off + dcid_len > len) return -1;
    off += dcid_len;                    // skip DCID
    int scid_len = pkt[off++];          // read SCID length
    if (off + scid_len > len) return -1;
    off += scid_len;                    // skip SCID
    int l = 0;
    int plen = (int)quic_parse_varint(pkt + off, len - off, &l); off += l;
    if (consumed_len) *consumed_len = off + plen;
    uint8_t saved_first = pkt[0];                              // save MASKED byte BEFORE unmasking
    uint8_t mask[16]; aes_128_ecb_encrypt(s_hp, pkt + off + 4, mask);
    pkt[0] ^= (mask[0] & 0x0F); int pn_len = (pkt[0] & 0x03) + 1; uint32_t pn = 0;
    uint8_t pn_bytes[4];
    for(int i=0; i<pn_len; i++) { pn_bytes[i] = pkt[off+i]; pkt[off+i] ^= mask[1+i]; pn = (pn << 8) | pkt[off+i]; }
    uint8_t nonce[12]; memcpy(nonce, s_iv, 12); for (int i = 0; i < 4; i++) nonce[11-i] ^= (uint8_t)(pn >> (i*8));
    if (pn > conn->s_hs_pn_max) conn->s_hs_pn_max = pn;
    int ret = aes_128_gcm_decrypt(s_key, nonce, pkt, off + pn_len, pkt + off + pn_len, plen - pn_len - 16, out, pkt + off + plen - 16);
    if (ret >= 0) {
        printf("[quic-demo] Decrypted Handshake (%d bytes)\n", ret);
        quic_add_received_pn(conn, 2, pn);
    } else {
        printf("[quic-error] Handshake Decrypt Failed! PN %u, Plen %d\n", pn, plen);
    }
    pkt[0] = saved_first; for(int i=0; i<pn_len; i++) pkt[off+i] = pn_bytes[i];  // restore original
    return ret;
}

static void quic_parse_frames(quic_conn *conn, uint8_t *payload, int len, int epoch) {
    int off = 0;
    while (off < len) {
        uint8_t type = payload[off++];
        if (type == 0x00 || type == 0x01) continue;
        if (type == 0x02 || type == 0x03) { // ACK
            int l = 0;
            uint64_t largest_acked = quic_parse_varint(payload + off, len - off, &l); off += l;
            uint64_t ack_delay = quic_parse_varint(payload + off, len - off, &l); off += l;
            uint64_t range_count = quic_parse_varint(payload + off, len - off, &l); off += l;
            uint64_t first_ack_range = quic_parse_varint(payload + off, len - off, &l); off += l;

            uint64_t curr_pn = largest_acked;
            for (uint64_t p = 0; p <= first_ack_range; p++) {
                quic_handle_packet_acked(conn, epoch, curr_pn - p, ack_delay);
            }
            if (largest_acked >= first_ack_range) {
                curr_pn = largest_acked - first_ack_range;
            }

            for (uint64_t i = 0; i < range_count; i++) {
                uint64_t gap = quic_parse_varint(payload + off, len - off, &l); off += l;
                uint64_t rlen = quic_parse_varint(payload + off, len - off, &l); off += l;

                if (curr_pn >= gap + 2) {
                    uint64_t next_range_end = curr_pn - gap - 2;
                    for (uint64_t p = 0; p <= rlen; p++) {
                        if (next_range_end >= p) {
                            quic_handle_packet_acked(conn, epoch, next_range_end - p, ack_delay);
                        }
                    }
                    if (next_range_end >= rlen) {
                        curr_pn = next_range_end - rlen;
                    }
                }
            }
            if (type == 0x03) {
                quic_parse_varint(payload + off, len - off, &l); off += l;
                quic_parse_varint(payload + off, len - off, &l); off += l;
                quic_parse_varint(payload + off, len - off, &l); off += l;
            }
            continue;
        }
        if (type >= 0x08 && type <= 0x0f) { // STREAM
            int l = 0; uint64_t sid = quic_parse_varint(payload + off, len - off, &l); off += l;
            if (type & 0x04) { quic_parse_varint(payload + off, len - off, &l); off += l; }
            uint64_t slen = len - off; if (type & 0x02) { slen = quic_parse_varint(payload + off, len - off, &l); off += l; }
            
            quic_stream *s = quic_find_stream(conn, sid);
            if (s) {
                if (type & 0x01) { s->fin_received = 1; }
                
                quic_check_flow_control(conn, s, slen);
                
                if (s->is_unidirectional) {
                    int so = 0;
                    if (!s->type_read) {
                        int type_len = 0;
                        uint64_t utype = quic_parse_varint(payload + off, (int)slen, &type_len);
                        if (type_len > 0) {
                            s->type = utype;
                            s->type_read = 1;
                            so += type_len;
                            printf("[http3] Unidirectional stream %llu type resolved to 0x%02llx\n",
                                       (unsigned long long)sid, (unsigned long long)utype);
                        }
                    }
                    if (s->type_read) {
                        if (s->type == 0x02) { // QPACK Encoder
                            qpack_parse_encoder_instructions(conn, payload + off + so, (int)slen - so);
                        } else {
                            printf("[http3] Skipping unidirectional stream %llu data (%d bytes)\n",
                                       (unsigned long long)sid, (int)slen - so);
                        }
                    }
                } else {
                    int so = 0;
                    while (so < (int)slen) {
                        if (s->h3_state == 0) {
                            int fl = 0, ll = 0;
                            uint64_t ftype = quic_parse_varint(payload + off + so, (int)slen - so, &fl);
                            if (fl == 0) break;
                            so += fl;
                            uint64_t flen = quic_parse_varint(payload + off + so, (int)slen - so, &ll);
                            if (ll == 0) { so -= fl; break; }
                            so += ll;

                            s->h3_frame_type = ftype;
                            s->h3_frame_rem = flen;
                            if (ftype == 0x01) { // HEADERS
                                printf("[http3] Stream %llu: HEADERS (%llu bytes):\n",
                                           (unsigned long long)sid, (unsigned long long)flen);
                                s->h3_state = 1; s->h3_buf_len = 0;
                            } else if (ftype == 0x00) { // DATA
                                printf("[http3] Stream %llu: DATA (%llu bytes):\n",
                                           (unsigned long long)sid, (unsigned long long)flen);
                                s->h3_state = 2;
                            } else {
                                s->h3_state = 3; // skip
                            }
                        } else if (s->h3_state == 1) { // HEADERS
                            uint64_t chunk = (s->h3_frame_rem < (uint64_t)((int)slen - so)) ? s->h3_frame_rem : (uint64_t)((int)slen - so);
                            if (s->h3_buf_len + (int)chunk < (int)sizeof(s->h3_buf)) {
                                memcpy(s->h3_buf + s->h3_buf_len, payload + off + so, (int)chunk);
                                s->h3_buf_len += (int)chunk;
                            }
                            so += (int)chunk; s->h3_frame_rem -= chunk;
                            if (s->h3_frame_rem == 0) {
                                decode_qpack_headers(conn, s->h3_buf, s->h3_buf_len);
                                s->h3_state = 0;
                            }
                        } else if (s->h3_state == 2) { // DATA
                            uint64_t total_chunk = (s->h3_frame_rem < (uint64_t)((int)slen - so)) ? s->h3_frame_rem : (uint64_t)((int)slen - so);
                            uint64_t printed = 0;
                            while (printed < total_chunk) {
                                char pbuf[1500];
                                int to_print = (int)(total_chunk - printed);
                                if (to_print > 1500) to_print = 1500;
                                for (int i = 0; i < to_print; i++) {
                                    uint8_t b = payload[off + so + (int)printed + i];
                                    pbuf[i] = (b == 0) ? '.' : b;
                                }
                                write(1, pbuf, to_print);
                                
                                // Store programmatically in the stream RX buffer
                                if (s->rx_buf_len + to_print < (int)sizeof(s->rx_buf)) {
                                    memcpy(s->rx_buf + s->rx_buf_len, payload + off + so + (int)printed, to_print);
                                    s->rx_buf_len += to_print;
                                }
                                
                                printed += to_print;
                            }
                            so += (int)total_chunk; s->h3_frame_rem -= total_chunk;
                            if (s->h3_frame_rem == 0) { printf("\n"); s->h3_state = 0; }
                            conn->http_response_received = 1;
                            if (s->fin_received || conn->is_closed) {
                                printf("\n[1rtt] Stream %llu finished! Done (http_ok=%d fin=%d closed=%d)\n",
                                           (unsigned long long)sid, conn->http_response_received, s->fin_received, conn->is_closed);
                            }
                        } else { // SKIP
                            uint64_t chunk = (s->h3_frame_rem < (uint64_t)((int)slen - so)) ? s->h3_frame_rem : (uint64_t)((int)slen - so);
                            so += (int)chunk; s->h3_frame_rem -= chunk;
                            if (s->h3_frame_rem == 0) s->h3_state = 0;
                        }
                    }
                }
            }
            off += (int)slen; continue;
        }
        if (type == 0x1c || type == 0x1d) { // CONNECTION_CLOSE
            int l=0; uint64_t err = quic_parse_varint(payload+off, len-off, &l); off+=l;
            if (type == 0x1c) { quic_parse_varint(payload+off, len-off, &l); off+=l; }
            uint64_t rlen = quic_parse_varint(payload+off, len - off, &l); off += l;
            printf("[http3-demo] CONNECTION_CLOSE (Error 0x%x, Reason: ", (int)err);
            for(int i=0; i<(int)rlen; i++) printf("%c", payload[off+i]);
            printf(")\n");
            conn->is_closed = 1; // [ÇakalMOD] Mark connection as closed
            off += (int)rlen; continue;
        }
        
        int skipped = quic_skip_frame(payload + off - 1, len - off + 1);
        if (skipped > 0) {
            off += skipped - 1;
            continue;
        }
        off = len;
    }
}

int quic_decrypt_1rtt(quic_conn *conn, uint8_t *pkt, int len, const uint8_t *s_key, const uint8_t *s_iv, const uint8_t *s_hp, uint8_t *out, int *consumed_len) {
    int dcid_len = conn->scid_len, pn_pos = 1 + dcid_len;
    uint8_t mask[16]; aes_128_ecb_encrypt(s_hp, pkt + pn_pos + 4, mask);
    pkt[0] ^= (mask[0] & 0x1F); int pn_len = (pkt[0] & 0x03) + 1; uint32_t pn_tr = 0;
    for (int i = 0; i < pn_len; i++) { pkt[pn_pos+i] ^= mask[1+i]; pn_tr = (pn_tr << 8) | pkt[pn_pos+i]; }
    uint64_t exp = conn->s_app_pn_next, win = 1ULL << (pn_len * 8), msk = win - 1, pn = (exp & ~msk) | pn_tr;
    if (pn + win / 2 <= exp) pn += win; else if (pn > exp + win / 2 && pn >= win) pn -= win;
    uint8_t nonce[12]; memcpy(nonce, s_iv, 12); for (int i = 0; i < 8; i++) nonce[11-i] ^= (uint8_t)(pn >> (i*8));
    int ret = aes_128_gcm_decrypt(s_key, nonce, pkt, pn_pos + pn_len, pkt + pn_pos + pn_len, len - pn_pos - pn_len - 16, out, pkt + len - 16);
    if (consumed_len) *consumed_len = len;
    if (ret >= 0) {
        conn->s_app_pn_next = pn + 1;
        quic_add_received_pn(conn, 3, pn);
        quic_parse_frames(conn, out, ret, 1);
        send_1rtt_ack(conn);
        printf("[quic-demo] Decrypted 1-RTT (PN %llu, %d bytes)\n", (unsigned long long)pn, ret);
    } else {
        printf("[quic-error] 1-RTT Decrypt Failed! PN_TR %u, Len %d\n", pn_tr, len);
    }
    return ret;
}

int quic_parse_retry(uint8_t *pkt, int len, uint8_t *new_dcid, int *new_dcid_len, uint8_t *token, int *token_len) {
    if (len < 6 || (pkt[0] & 0xF0) != 0xF0) return -1;
    int off = 5 + pkt[5] + 1;
    if (new_dcid) { *new_dcid_len = pkt[off]; memcpy(new_dcid, pkt + off + 1, pkt[off]); }
    off += pkt[off] + 1; if (token) { *token_len = len - off - 16; memcpy(token, pkt + off, *token_len); }
    return 0;
}

int quic_parse_server_hello(const uint8_t *sh, int len, uint8_t *server_pub_key) {
    if (len < 40) { printf("[quic-err] SH too short (%d)\n", len); return 0; }
    if (sh[0] != 0x02) { printf("[quic-err] SH wrong type (0x%02x)\n", sh[0]); return 0; }
    // sh[38] = session_id_length; cipher suite is right after session_id
    int sid_len = sh[38];
    int cipher_off = 38 + 1 + sid_len;
    if (cipher_off + 2 > len) { printf("[quic-err] SH too short for cipher\n"); return 0; }
    uint16_t cipher = (sh[cipher_off] << 8) | sh[cipher_off + 1];
    printf("[quic-demo] Server selected cipher: 0x%04x\n", cipher);
    if (cipher != 0x1301) {
        printf("[quic-err] Unsupported cipher 0x%04x (need TLS_AES_128_GCM_SHA256)\n", cipher);
        return 0;
    }
    int off = cipher_off + 2 + 1; // skip Cipher(2) + Compression(1)
    if (off + 2 > len) { printf("[quic-err] SH too short for ext len\n"); return 0; }
    int e_len = (sh[off]<<8)|sh[off+1]; off += 2; int end = off + e_len;
    if (end > len) { printf("[quic-err] SH ext len out of bounds (%d > %d)\n", end, len); return 0; }
    while (off + 4 <= end) {
        uint16_t type = (sh[off]<<8)|sh[off+1], vlen = (sh[off+2]<<8)|sh[off+3]; off += 4;
        if (type == 0x0033) {
            uint16_t group = (sh[off]<<8)|sh[off+1];
            printf("[quic-demo] Found Key Share! Group: 0x%04x\n", group);
            if (group != 0x001d) {
                printf("[quic-err] Server selected unsupported group 0x%04x (expected x25519)\n", group);
                return 0;
            }
            memcpy(server_pub_key, sh + off + 4, 32); return 1;
        }
        off += vlen;
    }
    printf("[quic-err] Key Share NOT found in SH!\n");
    return 0;
}

void quic_send_handshake_raw(quic_conn *conn, const uint8_t *payload, int plen, const uint8_t *c_hs_key, const uint8_t *c_hs_iv, const uint8_t *c_hs_hp) {
    uint8_t pkt[2048]; int off = 0;
    pkt[off++] = 0xE3; // Handshake, 4-byte PN
    pkt[off++] = (conn->version >> 24); pkt[off++] = (conn->version >> 16);
    pkt[off++] = (conn->version >> 8);  pkt[off++] = conn->version;
    pkt[off++] = conn->dcid_len; memcpy(pkt + off, conn->dcid, conn->dcid_len); off += conn->dcid_len;
    pkt[off++] = conn->scid_len; memcpy(pkt + off, conn->scid, conn->scid_len); off += conn->scid_len;
    int len_pos = off; off += 2;
    int pn_pos = off;
    uint32_t cpn = (uint32_t)conn->c_hs_pn;
    pkt[off++] = (cpn >> 24); pkt[off++] = (cpn >> 16); pkt[off++] = (cpn >> 8); pkt[off++] = cpn;
    pkt[len_pos] = 0x40 | ((plen + 4 + 16) >> 8);
    pkt[len_pos + 1] = (plen + 4 + 16) & 0xFF;
    uint8_t nonce[12]; memcpy(nonce, c_hs_iv, 12);
    for (int i = 0; i < 4; i++) nonce[11 - i] ^= (uint8_t)(cpn >> (i * 8));
    uint8_t tag[16];
    aes_128_gcm_encrypt(c_hs_key, nonce, pkt, off, payload, plen, pkt + off, tag);
    memcpy(pkt + off + plen, tag, 16);
    // Header protection: sample starts 4 bytes after start of PN
    uint8_t mask[16]; aes_128_ecb_encrypt(c_hs_hp, pkt + pn_pos + 4, mask);
    pkt[0] ^= (mask[0] & 0x0F);
    pkt[pn_pos]   ^= mask[1]; pkt[pn_pos+1] ^= mask[2];
    pkt[pn_pos+2] ^= mask[3]; pkt[pn_pos+3] ^= mask[4];
    sendto(conn->fd, pkt, off + plen + 16, 0, (struct sockaddr *)&conn->addr, sizeof(conn->addr));

    quic_add_to_sent_queue(conn, 2, conn->c_hs_pn, payload, plen);
    conn->c_hs_pn++;
}

void quic_send_finished(quic_conn *conn, const uint8_t *transcript_hash, const uint8_t *c_hs_key, const uint8_t *c_hs_iv, const uint8_t *c_hs_hp) {
    memcpy(conn->c_hs_key, c_hs_key, 16);
    memcpy(conn->c_hs_iv, c_hs_iv, 12);
    memcpy(conn->c_hs_hp, c_hs_hp, 16);

    uint8_t f_key[32], v_data[32];
    quic_hkdf_expand_label(f_key, conn->c_hs_secret, "finished", 32);
    hmac_sha256(f_key, 32, transcript_hash, 32, v_data);

    uint8_t hs_msg[36];
    hs_msg[0] = 0x14; hs_msg[1] = 0; hs_msg[2] = 0; hs_msg[3] = 32;
    memcpy(hs_msg + 4, v_data, 32);

    uint8_t payload[128]; int plen = 0;
    int ack_len = quic_build_ack_frame(conn, 2, payload, sizeof(payload));
    plen += ack_len;

    payload[plen++] = 0x06;                           // CRYPTO frame type
    plen += put_varint(payload + plen, 0);            // offset = 0
    plen += put_varint(payload + plen, 36);           // length = 36
    memcpy(payload + plen, hs_msg, 36); plen += 36;  // TLS Finished message

    quic_send_handshake_raw(conn, payload, plen, c_hs_key, c_hs_iv, c_hs_hp);
}

void quic_send_1rtt(quic_conn *conn, const uint8_t *payload, int plen) {
    uint8_t pkt[8192]; int off = 0;
    // Short header: spin=0, reserved=0, key_phase=0, PN_len=4 → 0x43
    pkt[off++] = 0x43;
    memcpy(pkt + off, conn->dcid, conn->dcid_len); off += conn->dcid_len;
    int pn_pos = off;
    uint32_t cpn = (uint32_t)conn->c_app_pn;
    pkt[off++] = (cpn >> 24); pkt[off++] = (cpn >> 16); pkt[off++] = (cpn >> 8); pkt[off++] = cpn;
    uint8_t nonce[12]; memcpy(nonce, conn->c_app_iv, 12);
    for (int i = 0; i < 8; i++) nonce[11 - i] ^= (uint8_t)(conn->c_app_pn >> (i * 8));
    uint8_t tag[16];
    aes_128_gcm_encrypt(conn->c_app_key, nonce, pkt, off, payload, plen, pkt + off, tag);
    memcpy(pkt + off + plen, tag, 16);
    // HP: sample 16 bytes starting 4 bytes after PN start
    uint8_t mask[16]; aes_128_ecb_encrypt(conn->c_app_hp, pkt + pn_pos + 4, mask);
    pkt[0]       ^= (mask[0] & 0x1F);
    pkt[pn_pos]   ^= mask[1]; pkt[pn_pos+1] ^= mask[2];
    pkt[pn_pos+2] ^= mask[3]; pkt[pn_pos+3] ^= mask[4];
    sendto(conn->fd, pkt, off + plen + 16, 0, (struct sockaddr *)&conn->addr, sizeof(conn->addr));
    quic_add_to_sent_queue(conn, 3, conn->c_app_pn, payload, plen);
    conn->c_app_pn++;
}

void send_1rtt_ack(quic_conn *conn) {
    uint8_t payload[256];
    int plen = quic_build_ack_frame(conn, 3, payload, sizeof(payload));
    if (plen > 0) {
        quic_send_1rtt(conn, payload, plen);
    }
}

void send_initial_ack(quic_conn *conn) {
    uint8_t payload[256];
    int plen = quic_build_ack_frame(conn, 0, payload, sizeof(payload));
    if (plen <= 0) return;
    
    uint8_t pkt[512]; int off = 0; uint8_t c_key[16], c_iv[12], c_hp[16];
    quic_derive_client_initial_secrets(conn->original_dcid, conn->original_dcid_len, c_key, c_iv, c_hp);
    pkt[off++] = 0xC1;
    pkt[off++] = (conn->version >> 24); pkt[off++] = (conn->version >> 16); pkt[off++] = (conn->version >> 8); pkt[off++] = conn->version;
    pkt[off++] = conn->dcid_len; memcpy(pkt + off, conn->dcid, conn->dcid_len); off += conn->dcid_len;
    pkt[off++] = conn->scid_len; memcpy(pkt + off, conn->scid, conn->scid_len); off += conn->scid_len;
    pkt[off++] = 0;
    int len_pos = off; off += 2; int pn_pos = off; pkt[off++] = (conn->c_initial_pn >> 8); pkt[off++] = (conn->c_initial_pn & 0xFF);
    pkt[len_pos] = 0x40 | ((plen+2+16) >> 8); pkt[len_pos+1] = (plen+2+16) & 0xFF;
    uint8_t nonce[12]; memcpy(nonce, c_iv, 12); nonce[11] ^= (conn->c_initial_pn & 0xFF); nonce[10] ^= (conn->c_initial_pn >> 8);
    uint8_t tag[16]; aes_128_gcm_encrypt(c_key, nonce, pkt, off, payload, plen, pkt + off, tag); memcpy(pkt + off + plen, tag, 16);
    uint8_t mask[16]; aes_128_ecb_encrypt(c_hp, pkt + off + 2, mask);
    pkt[0] ^= (mask[0] & 0x0F); pkt[pn_pos] ^= mask[1]; pkt[pn_pos+1] ^= mask[2];
    sendto(conn->fd, pkt, off + plen + 16, 0, (struct sockaddr *)&conn->addr, sizeof(conn->addr));
    conn->c_initial_pn++;
}

void send_handshake_ack(quic_conn *conn, const uint8_t *c_hs_key, const uint8_t *c_hs_iv, const uint8_t *c_hs_hp) {
    uint8_t payload[256];
    int plen = quic_build_ack_frame(conn, 2, payload, sizeof(payload));
    if (plen <= 0) return;
    
    uint8_t pkt[512]; int off = 0;
    pkt[off++] = 0xE1;
    pkt[off++] = (conn->version >> 24); pkt[off++] = (conn->version >> 16); pkt[off++] = (conn->version >> 8); pkt[off++] = conn->version;
    pkt[off++] = conn->dcid_len; memcpy(pkt + off, conn->dcid, conn->dcid_len); off += conn->dcid_len;
    pkt[off++] = conn->scid_len; memcpy(pkt + off, conn->scid, conn->scid_len); off += conn->scid_len;
    int len_pos = off; off += 2; int pn_pos = off; pkt[off++] = (conn->c_hs_pn >> 8); pkt[off++] = (conn->c_hs_pn & 0xFF);
    pkt[len_pos] = 0x40 | ((plen+2+16) >> 8); pkt[len_pos+1] = (plen+2+16) & 0xFF;
    uint8_t nonce[12]; memcpy(nonce, c_hs_iv, 12); nonce[11] ^= (conn->c_hs_pn & 0xFF); nonce[10] ^= (conn->c_hs_pn >> 8);
    uint8_t tag[16]; aes_128_gcm_encrypt(c_hs_key, nonce, pkt, off, payload, plen, pkt + off, tag); memcpy(pkt + off + plen, tag, 16);
    uint8_t mask[16]; aes_128_ecb_encrypt(c_hs_hp, pkt + off + 2, mask);
    pkt[0] ^= (mask[0] & 0x0F); pkt[pn_pos] ^= mask[1]; pkt[pn_pos+1] ^= mask[2];
    sendto(conn->fd, pkt, off + plen + 16, 0, (struct sockaddr *)&conn->addr, sizeof(conn->addr));
    conn->c_hs_pn++;
}

int quic_skip_frame(const uint8_t *buf, int len) {
    if (len < 1) return -1;
    int lt = 0; uint64_t type = quic_parse_varint(buf, len, &lt); if (lt == 0) return -1;
    int off = lt, l = 0; if (type <= 0x01) return off;
    if (type <= 0x03) {
        quic_parse_varint(buf+off, len-off, &l); off+=l;
        quic_parse_varint(buf+off, len-off, &l); off+=l;
        uint64_t cnt = quic_parse_varint(buf+off, len-off, &l); off+=l;
        quic_parse_varint(buf+off, len-off, &l); off+=l;
        for(uint64_t i=0; i<cnt; i++) {
            quic_parse_varint(buf+off, len-off, &l); off+=l;
            quic_parse_varint(buf+off, len-off, &l); off+=l;
        }
        if (type == 0x03) {
            quic_parse_varint(buf+off, len-off, &l); off+=l;
            quic_parse_varint(buf+off, len-off, &l); off+=l;
            quic_parse_varint(buf+off, len-off, &l); off+=l;
        }
        return off;
    }
    if (type == 0x04) { for(int i=0; i<3; i++) { quic_parse_varint(buf+off, len-off, &l); off+=l; } return off; }
    if (type == 0x05) { for(int i=0; i<2; i++) { quic_parse_varint(buf+off, len-off, &l); off+=l; } return off; }
    if (type == 0x06) { quic_parse_varint(buf+off, len-off, &l); off+=l; uint64_t cl = quic_parse_varint(buf+off, len-off, &l); return off+l+(int)cl; }
    if (type == 0x07) { uint64_t tl = quic_parse_varint(buf+off, len-off, &l); off+=l; return off+(int)tl; }
    if (type >= 0x08 && type <= 0x0f) { quic_parse_varint(buf+off, len-off, &l); off+=l; if (type & 0x04) { quic_parse_varint(buf+off, len-off, &l); off+=l; } if (type & 0x02) { uint64_t dl = quic_parse_varint(buf+off, len-off, &l); return off+l+(int)dl; } return len; }
    if (type <= 0x15) { quic_parse_varint(buf+off, len-off, &l); return off+l; }
    if (type <= 0x1d) { quic_parse_varint(buf+off, len-off, &l); off+=l; if (type == 0x1c) { quic_parse_varint(buf+off, len-off, &l); off+=l; } uint64_t rl = quic_parse_varint(buf+off, len-off, &l); return off+l+(int)rl; }
    if (type == 0x1e) return off; return -1;
}

static int put_qpack_int(uint8_t *p, uint8_t prefix_bits, uint64_t val) {
    uint8_t mask = (1 << prefix_bits) - 1;
    if (val < mask) { p[0] |= (uint8_t)val; return 1; }
    p[0] |= mask; val -= mask; int off = 1; while (val >= 128) { p[off++] = (uint8_t)(0x80 | (val & 0x7F)); val >>= 7; }
    p[off++] = (uint8_t)val; return off;
}

void auto_add_header(uint8_t *qpack, int *qp, const char *name, const char *value) {
    int nlen = (int)strlen(name), vlen = (int)strlen(value);
    qpack[*qp] = 0x20; *qp += put_qpack_int(qpack + *qp, 3, nlen); memcpy(qpack + *qp, name, nlen); *qp += nlen;
    qpack[*qp] = 0x00; *qp += put_qpack_int(qpack + *qp, 7, vlen); memcpy(qpack + *qp, value, vlen); *qp += vlen;
}

void quic_clear_headers(quic_conn *conn) {
    conn->h3_headers_count = 0;
}

void quic_add_header(quic_conn *conn, const char *name, const char *value) {
    if (conn->h3_headers_count >= 32) return;
    int idx = conn->h3_headers_count++;
    strncpy(conn->h3_headers[idx].name, name, sizeof(conn->h3_headers[idx].name) - 1);
    conn->h3_headers[idx].name[sizeof(conn->h3_headers[idx].name) - 1] = '\0';
    strncpy(conn->h3_headers[idx].value, value, sizeof(conn->h3_headers[idx].value) - 1);
    conn->h3_headers[idx].value[sizeof(conn->h3_headers[idx].value) - 1] = '\0';
}

int send_http3_get(quic_conn *conn, const char *host, const char *path, const char *method, const char *ua, const char *lang) {
    uint8_t payload[4096]; int pos = 0;
    if (!conn->h3_initialized) {
        uint8_t ctrl[256]; int cp = 0; 
        ctrl[cp++] = 0x00; // Control stream type
        ctrl[cp++] = 0x04; // SETTINGS frame type
        uint8_t sdata[128]; int sp = 0;
        sp += put_varint(sdata+sp, 0x01); sp += put_varint(sdata+sp, 65536);   // QPACK_MAX_TABLE_CAPACITY
        sp += put_varint(sdata+sp, 0x06); sp += put_varint(sdata+sp, 262144);  // MAX_HEADER_LIST_SIZE
        sp += put_varint(sdata+sp, 0x07); sp += put_varint(sdata+sp, 100);     // QPACK_BLOCKED_STREAMS (mvfst requires this)
        sp += put_varint(sdata+sp, 0x08); sp += put_varint(sdata+sp, 1);       // ENABLE_CONNECT_PROTOCOL
        cp += put_varint(ctrl+cp, sp); memcpy(ctrl+cp, sdata, sp); cp += sp;
        payload[pos++] = 0x0A; pos += put_varint(payload + pos, 2); pos += put_varint(payload + pos, cp); memcpy(payload + pos, ctrl, cp); pos += cp;
        payload[pos++] = 0x0A; pos += put_varint(payload + pos, 6); pos += put_varint(payload + pos, 1); payload[pos++] = 0x02;
        payload[pos++] = 0x0A; pos += put_varint(payload + pos, 10); pos += put_varint(payload + pos, 1); payload[pos++] = 0x03;
        quic_send_1rtt(conn, payload, pos); pos = 0; conn->h3_initialized = 1;
    }
    uint8_t qpack[2048]; int qp = 0; qpack[qp++] = 0x00; qpack[qp++] = 0x00;
    auto_add_header(qpack, &qp, ":method", method ? method : "GET");
    auto_add_header(qpack, &qp, ":scheme", "https");
    auto_add_header(qpack, &qp, ":authority", host);
    auto_add_header(qpack, &qp, ":path", path);
    for (int i = 0; i < conn->h3_headers_count; i++) {
        auto_add_header(qpack, &qp, conn->h3_headers[i].name, conn->h3_headers[i].value);
    }
    
    uint8_t frame[2048]; int fp = 0; frame[fp++] = 0x01; fp += put_varint(frame + fp, qp); memcpy(frame + fp, qpack, qp); fp += qp;

    uint8_t spkt[2048]; int spk = 0;
    int sent_count = 0;
    if (spk + fp + 10 < 1200) { // Stay under safe MTU
        uint64_t sid = conn->next_sid; conn->next_sid += 4;
        spkt[spk++] = 0x0B; spk += put_varint(spkt + spk, sid); spk += put_varint(spkt + spk, fp); memcpy(spkt + spk, frame, fp); spk += fp;
        sent_count++;
    }
    quic_send_1rtt(conn, spkt, spk); return sent_count;
}

void parse_1rtt_frames(quic_conn *conn, const uint8_t *data, int len) { quic_parse_frames(conn, (uint8_t *)data, len, 1); }
void quic_close(quic_conn *conn) { if (conn) { close(conn->fd); free(conn); } }

uint64_t get_time_us(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000ULL + tv.tv_usec;
}

void quic_add_received_pn(quic_conn *conn, int epoch, uint64_t pn) {
    if (epoch < 0 || epoch > 3) return;
    int count = conn->rx_packets[epoch].count;
    quic_ack_range *ranges = conn->rx_packets[epoch].ranges;
    
    // 1. Check if it fits into any existing range or can extend it
    for (int i = 0; i < count; i++) {
        if (pn >= ranges[i].start && pn <= ranges[i].end) return; // already tracked
        if (pn == ranges[i].start - 1) {
            ranges[i].start = pn;
            // Check if we can merge with the previous range
            if (i > 0 && ranges[i-1].end >= ranges[i].start - 1) {
                ranges[i-1].end = ranges[i].end;
                // Remove ranges[i]
                for (int j = i; j < count - 1; j++) ranges[j] = ranges[j+1];
                conn->rx_packets[epoch].count--;
            }
            return;
        }
        if (pn == ranges[i].end + 1) {
            ranges[i].end = pn;
            // Check if we can merge with the next range
            if (i < count - 1 && ranges[i+1].start <= ranges[i].end + 1) {
                ranges[i].end = ranges[i+1].end;
                // Remove ranges[i+1]
                for (int j = i + 1; j < count - 1; j++) ranges[j] = ranges[j+1];
                conn->rx_packets[epoch].count--;
            }
            return;
        }
    }
    
    // 2. Insert new range in sorted order
    if (count >= 32) return; // limit to 32 ranges to prevent overflow
    int insert_pos = 0;
    while (insert_pos < count && ranges[insert_pos].start < pn) {
        insert_pos++;
    }
    for (int j = count; j > insert_pos; j--) {
        ranges[j] = ranges[j-1];
    }
    ranges[insert_pos].start = pn;
    ranges[insert_pos].end = pn;
    conn->rx_packets[epoch].count++;
}

int quic_build_ack_frame(quic_conn *conn, int epoch, uint8_t *payload, int max_len) {
    if (epoch < 0 || epoch > 3) return 0;
    int count = conn->rx_packets[epoch].count;
    if (count == 0) return 0;
    
    quic_ack_range *ranges = conn->rx_packets[epoch].ranges;
    int plen = 0;
    payload[plen++] = 0x02; // ACK frame type
    
    // Largest Acknowledged is the end of the highest range
    uint64_t largest_acked = ranges[count-1].end;
    plen += put_varint(payload + plen, largest_acked);
    plen += put_varint(payload + plen, 0); // ACK Delay
    
    // Range Count
    uint64_t range_count = count - 1;
    plen += put_varint(payload + plen, range_count);
    
    // First ACK Range
    uint64_t first_ack_range = ranges[count-1].end - ranges[count-1].start;
    plen += put_varint(payload + plen, first_ack_range);
    
    // Followed by gaps and ranges in descending order
    for (int i = count - 2; i >= 0; i--) {
        // Gap = (start of next range) - (end of this range) - 2
        uint64_t gap = ranges[i+1].start - ranges[i].end - 2;
        // Range Length = (end of this range) - (start of this range)
        uint64_t rlen = ranges[i].end - ranges[i].start;
        
        plen += put_varint(payload + plen, gap);
        plen += put_varint(payload + plen, rlen);
    }
    return plen;
}

void quic_add_to_sent_queue(quic_conn *conn, int epoch, uint64_t pn, const uint8_t *payload, int plen) {
    if (plen <= 0 || plen > 2048) return;
    quic_sent_packet *p = malloc(sizeof(quic_sent_packet));
    if (!p) return;
    p->pn = pn;
    p->epoch = epoch;
    p->sent_time = get_time_us();
    memcpy(p->payload, payload, plen);
    p->plen = plen;
    p->next = conn->sent_queue;
    conn->sent_queue = p;
    printf("[quic-sent] Saved packet PN %llu (epoch %d, %d bytes) to Sent Queue\n",
               (unsigned long long)pn, epoch, plen);
}

void quic_handle_packet_acked(quic_conn *conn, int epoch, uint64_t pn, uint64_t ack_delay) {
    quic_sent_packet *prev = NULL;
    quic_sent_packet *curr = conn->sent_queue;
    while (curr) {
        if (curr->epoch == epoch && curr->pn == pn) {
            if (prev) {
                prev->next = curr->next;
            } else {
                conn->sent_queue = curr->next;
            }
            
            uint64_t rtt = get_time_us() - curr->sent_time;
            if (rtt > ack_delay) rtt -= ack_delay;
            
            if (conn->srtt == 0) {
                conn->srtt = rtt;
                conn->rttvar = rtt / 2;
            } else {
                conn->rttvar = (3 * conn->rttvar + (conn->srtt > rtt ? (conn->srtt - rtt) : (rtt - conn->srtt))) / 4;
                conn->srtt = (7 * conn->srtt + rtt) / 8;
            }
            printf("[quic-rtt] Packet %llu ACKed. RTT: %llu us, SRTT: %llu us, RTTVAR: %llu us\n",
                       (unsigned long long)pn, (unsigned long long)rtt, (unsigned long long)conn->srtt, (unsigned long long)conn->rttvar);
            
            free(curr);
            return;
        }
        prev = curr;
        curr = curr->next;
    }
}

void quic_check_pto(quic_conn *conn) {
    uint64_t now = get_time_us();
    uint64_t pto_us = conn->srtt + 4 * conn->rttvar;
    if (pto_us == 0) pto_us = 300000;
    
    quic_sent_packet *curr = conn->sent_queue;
    while (curr) {
        if (now - curr->sent_time > pto_us) {
            printf("[quic-pto] PTO EXPIRED for packet PN %llu (epoch %d)! Retransmitting...\n",
                       (unsigned long long)curr->pn, curr->epoch);
            
            if (curr->epoch == 0) {
                quic_send_initial_raw(conn, curr->payload, curr->plen, conn->token, conn->token_len);
            } else if (curr->epoch == 2) {
                quic_send_handshake_raw(conn, curr->payload, curr->plen, conn->c_hs_key, conn->c_hs_iv, conn->c_hs_hp);
            } else if (curr->epoch == 3) {
                quic_send_1rtt(conn, curr->payload, curr->plen);
            }
            
            quic_sent_packet *to_free = curr;
            curr = curr->next;
            
            quic_sent_packet *p = conn->sent_queue;
            if (p == to_free) {
                conn->sent_queue = p->next;
            } else {
                while (p && p->next != to_free) p = p->next;
                if (p) p->next = to_free->next;
            }
            free(to_free);
        } else {
            curr = curr->next;
        }
    }
}

quic_stream *quic_find_stream(quic_conn *conn, uint64_t stream_id) {
    for (int i = 0; i < conn->streams_count; i++) {
        if (conn->streams[i].stream_id == stream_id && conn->streams[i].is_active) {
            return &conn->streams[i];
        }
    }
    if (conn->streams_count < 32) {
        int idx = conn->streams_count++;
        quic_stream *s = &conn->streams[idx];
        memset(s, 0, sizeof(quic_stream));
        s->stream_id = stream_id;
        s->is_active = 1;
        s->max_rx_data = 5 * 1024 * 1024;
        if ((stream_id & 0x02) != 0) {
            s->is_unidirectional = 1;
        } else {
            s->is_unidirectional = 0;
        }
        return s;
    }
    return NULL;
}

void quic_check_flow_control(quic_conn *conn, quic_stream *s, uint64_t bytes) {
    conn->rx_data += bytes;
    if (s) {
        s->rx_data += bytes;
    }
    
    if (conn->max_rx_data == 0) {
        conn->max_rx_data = 10 * 1024 * 1024;
    }
    if (conn->rx_data > conn->max_rx_data / 2) {
        conn->max_rx_data *= 2;
        printf("[quic-fc] Sending MAX_DATA: %llu bytes\n", (unsigned long long)conn->max_rx_data);
        uint8_t frame[16]; int fp = 0;
        frame[fp++] = 0x10;
        fp += put_varint(frame + fp, conn->max_rx_data);
        quic_send_1rtt(conn, frame, fp);
    }
    
    if (s) {
        if (s->max_rx_data == 0) {
            s->max_rx_data = 5 * 1024 * 1024;
        }
        if (s->rx_data > s->max_rx_data / 2) {
            s->max_rx_data *= 2;
            printf("[quic-fc] Stream %llu: Sending MAX_STREAM_DATA: %llu bytes\n",
                       (unsigned long long)s->stream_id, (unsigned long long)s->max_rx_data);
            uint8_t frame[32]; int fp = 0;
            frame[fp++] = 0x11;
            fp += put_varint(frame + fp, s->stream_id);
            fp += put_varint(frame + fp, s->max_rx_data);
            quic_send_1rtt(conn, frame, fp);
        }
    }
}
