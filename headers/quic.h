#ifndef QUIC_H
#define QUIC_H

#include "includes.h"

#ifdef __cplusplus
extern "C" {
#endif

#define QUIC_VERSION_1 0x00000001

typedef struct {
    uint64_t start;
    uint64_t end;
} quic_ack_range;

typedef struct quic_sent_packet {
    uint64_t pn;
    int epoch;
    uint64_t sent_time;
    uint8_t payload[2048];
    int plen;
    struct quic_sent_packet *next;
} quic_sent_packet;

typedef struct {
    char name[256];
    char value[512];
} qpack_dynamic_entry;

typedef struct {
    uint64_t stream_id;
    int is_active;
    int is_unidirectional;
    uint64_t type;
    int type_read;
    uint64_t rx_data;
    uint64_t max_rx_data;
    
    uint64_t h3_frame_type;
    uint64_t h3_frame_rem;
    int h3_state;
    uint8_t h3_buf[8192];
    int h3_buf_len;
    int fin_received;
    
    // Custom programmatic RX data buffer
    uint8_t rx_buf[65536];
    int rx_buf_len;
    int rx_buf_off;
} quic_stream;

typedef struct {
    int fd;
    struct sockaddr_in addr;
    uint32_t version;
    uint8_t dcid[20];
    int dcid_len;
    uint8_t scid[20];
    int scid_len;
    uint8_t original_dcid[20];
    int original_dcid_len;
    uint8_t priv_key[32];
    uint8_t pub_key[32];
    uint8_t handshake_secret[48];
    uint8_t c_hs_secret[48];
    uint8_t master_secret[48];
    uint16_t cipher_suite;
    uint8_t s_app_key[32], s_app_iv[12], s_app_hp[32];
    uint8_t c_app_key[32], c_app_iv[12], c_app_hp[32];
    uint64_t s_app_pn_next;
    uint64_t c_app_pn;       /* next client 1-RTT packet number to send */
    uint64_t s_initial_pn_max;
    uint64_t s_hs_pn_max;

    int h3_initialized;
    uint64_t next_sid;
    uint64_t max_streams_bidi;  // [ÇakalMOD] Server limit for bidirectional streams

    uint8_t token[256];
    int token_len;
    uint8_t server_scid[20];
    int server_scid_len;

    uint64_t c_initial_pn;
    uint64_t c_hs_pn;
    int http_response_received; // [ÇakalMOD] HTTP yanıtının geldiğini doğrulayan bayrak
    
    // Custom Headers
    struct {
        char name[128];
        char value[256];
    } h3_headers[32];
    int h3_headers_count;
    int is_closed; // [ÇakalMOD] Track if connection is closed by server
    
    // RTT & Timer estimation
    uint64_t srtt;
    uint64_t rttvar;
    
    // Handshake keys persistence
    uint8_t c_hs_key[32], c_hs_iv[12], c_hs_hp[32];
    
    // Received packet range tracking
    struct {
        quic_ack_range ranges[32];
        int count;
    } rx_packets[4]; // epoch indexed
    
    // Sent Queue
    quic_sent_packet *sent_queue;
    
    // Flow Control
    uint64_t rx_data;
    uint64_t max_rx_data;
    
    // QPACK Dynamic Table
    struct {
        qpack_dynamic_entry entries[256];
        int head;
        int tail;
        int count;
        uint64_t insert_count;
    } qpack_dyn;
    
    // Structured Stream Multiplexing Map
    quic_stream streams[32];
    int streams_count;
} quic_conn;

int put_varint(uint8_t *p, uint64_t val);
uint64_t quic_parse_varint(const uint8_t *p, int max_len, int *len);
quic_conn *quic_connect(struct sockaddr_in *addr, const char *host);
void quic_send_initial(quic_conn *conn, const char *host, const uint8_t *ch_payload, int ch_len, const uint8_t *token, int token_len);
void quic_derive_client_initial_secrets(const uint8_t *cid, int cid_len, uint8_t *key, uint8_t *iv, uint8_t *hp);
void quic_derive_server_initial_secrets(const uint8_t *cid, int cid_len, uint8_t *key, uint8_t *iv, uint8_t *hp);
int quic_decrypt_initial(quic_conn *conn, uint8_t *pkt, int len, uint8_t *out, int *consumed_len);
int quic_decrypt_handshake(quic_conn *conn, uint8_t *pkt, int len, const uint8_t *s_key, const uint8_t *s_iv, const uint8_t *s_hp, uint8_t *out, int *consumed_len);
int quic_decrypt_1rtt(quic_conn *conn, uint8_t *pkt, int len, const uint8_t *s_key, const uint8_t *s_iv, const uint8_t *s_hp, uint8_t *out, int *consumed_len);
int quic_parse_server_hello(const uint8_t *sh, int len, uint8_t *server_pub_key, uint16_t *cipher_out);
void quic_derive_handshake_secrets(quic_conn *conn, const uint8_t *shared_secret, const uint8_t *transcript_hash, uint8_t *c_key, uint8_t *c_iv, uint8_t *c_hp, uint8_t *s_key, uint8_t *s_iv, uint8_t *s_hp);
void quic_derive_application_secrets(quic_conn *conn, const uint8_t *transcript_hash);
void quic_send_finished(quic_conn *conn, const uint8_t *transcript_hash, const uint8_t *c_hs_key, const uint8_t *c_hs_iv, const uint8_t *c_hs_hp);
void quic_send_1rtt(quic_conn *conn, const uint8_t *payload, int plen);
int quic_skip_frame(const uint8_t *buf, int len);
void quic_close(quic_conn *conn);

// Header management
void quic_add_header(quic_conn *conn, const char *name, const char *value);
void quic_clear_headers(quic_conn *conn);
int quic_parse_retry(uint8_t *pkt, int len, uint8_t *new_dcid, int *new_dcid_len, uint8_t *token, int *token_len);

void send_initial_ack(quic_conn *conn);
void send_handshake_ack(quic_conn *conn, const uint8_t *c_hs_key, const uint8_t *c_hs_iv, const uint8_t *c_hs_hp);
void send_1rtt_ack(quic_conn *conn);

int send_http3_get(quic_conn *conn, const char *host, const char *path, const char *method, const char *ua, const char *lang);
void parse_1rtt_frames(quic_conn *conn, const uint8_t *data, int len);
extern const char *qpack_static[];
#define QPACK_DYNAMIC_MAX 256

void huffman_decode(const uint8_t *in, int len, char *out, int max_out);
void decode_qpack_headers(quic_conn *conn, const uint8_t *data, int len);

void quic_add_received_pn(quic_conn *conn, int epoch, uint64_t pn);
int quic_build_ack_frame(quic_conn *conn, int epoch, uint8_t *payload, int max_len);
void quic_add_to_sent_queue(quic_conn *conn, int epoch, uint64_t pn, const uint8_t *payload, int plen);
void quic_handle_packet_acked(quic_conn *conn, int epoch, uint64_t pn, uint64_t ack_delay);
void quic_check_pto(quic_conn *conn);
void qpack_parse_encoder_instructions(quic_conn *conn, const uint8_t *data, int len);
uint64_t get_time_us(void);

quic_stream *quic_find_stream(quic_conn *conn, uint64_t stream_id);
void quic_check_flow_control(quic_conn *conn, quic_stream *s, uint64_t bytes);
void quic_send_initial_raw(quic_conn *conn, const uint8_t *payload, int plen, const uint8_t *token, int token_len);
void quic_send_handshake_raw(quic_conn *conn, const uint8_t *payload, int plen, const uint8_t *c_hs_key, const uint8_t *c_hs_iv, const uint8_t *c_hs_hp);

#ifdef __cplusplus
}
#endif

#endif
