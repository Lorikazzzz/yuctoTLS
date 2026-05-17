#ifndef NANOTLS_H
#define NANOTLS_H

#include "includes.h"
#include "nanotls.h"
#include "crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HS_CLIENT_HELLO      0x01
#define HS_SERVER_HELLO      0x02
#define HS_ENCRYPTED_EXT     0x08
#define HS_CERTIFICATE       0x0b
#define HS_CERT_VERIFY       0x0f
#define HS_FINISHED          0x14

typedef struct {
    char name[64];
    char value[256];
} tls_http_header;

typedef struct nanotls_conn {
    int fd;
    uint8_t master_secret[48];
    uint8_t c_app_key[32], c_app_iv[12];
    uint8_t s_app_key[32], s_app_iv[12];
    uint64_t c_pn, s_pn;
    uint8_t handshake_secret[48];
    uint8_t client_secret[48];
    uint8_t server_secret[48];
    uint8_t client_key[32];
    uint8_t server_key[32];
    uint8_t client_iv[12];
    uint8_t server_iv[12];
    uint64_t client_seq;
    uint64_t server_seq;

    sha256_ctx_t transcript_ctx;
    sha384_ctx_t transcript_ctx_384;
    uint8_t client_random[32];
    uint8_t server_random[32];

    tls_http_header headers[32];
    int headers_count;
    int is_h2;
    int is_tls12;
    int server_ccs_received;
    uint16_t cipher_suite;
    const char *alpn_str;
    int alpn_len;
    const char *sni_host;
    uint8_t hs_buf[131072];
    int hs_buf_len;
    
    // Transparent QUIC fallback support
    int is_quic;
    void *quic_conn_ptr;
} nanotls_conn;

void tls_clear_headers(nanotls_conn *conn);
void tls_add_header(nanotls_conn *conn, const char *name, const char *value);
int tls_send_request(nanotls_conn *conn, const char *method, const char *path);
#define _NANOTLS_NUM_ARGS(...) (sizeof((const char*[]){__VA_ARGS__})/sizeof(const char*))
#define tls_mode(...) tls_mode_impl(_NANOTLS_NUM_ARGS(__VA_ARGS__), __VA_ARGS__)
void tls_mode_impl(int count, ...);

#define protocol_mode(...) protocol_mode_impl(_NANOTLS_NUM_ARGS(__VA_ARGS__), __VA_ARGS__)
void protocol_mode_impl(int count, ...);


int tls13_client_hello(uint8_t *ch, const char *host, const uint8_t *dcid, int dcid_len, const uint8_t *scid, int scid_len, const uint8_t *pub_key);

void tls13_expand_label(const uint8_t *secret, const char *label, const uint8_t *hash, size_t hlen, uint8_t *out, int out_len);
void tls13_derive_secret(const uint8_t *prk, const char *label, const uint8_t *hash, size_t hlen, uint8_t *out);
void tls13_xor_iv(uint8_t *iv, uint64_t seq, uint8_t *out);
int tls13_handshake(nanotls_conn *conn, const char *host);

nanotls_conn* tls_core_connect(const char* host, int port);
nanotls_conn* tls_core_connect_addr(struct sockaddr_in *addr, const char *host);
int tls_core_send(nanotls_conn* conn, const void* data, int len);
int tls_core_recv(nanotls_conn* conn, void* buf, int len);
void tls_core_close(nanotls_conn* conn);
int tls_core_init(void);

#ifdef __cplusplus
}
#endif

#endif
