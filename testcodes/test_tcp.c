#include "headers/nanotls.h"
#include "headers/includes.h"

static void add_chrome_headers(nanotls_conn *conn) {
    tls_clear_headers(conn);
    tls_add_header(conn, "user-agent",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36");
    tls_add_header(conn, "accept", "*/*");
    tls_add_header(conn, "accept-encoding", "identity");
}

static int run(const char *label, const char *ip, const char *host, const char *path,
               int use_quic, int use_h2, int use_tls13, int use_tls12) {
    printf("\n================ %s ================\n", label);

    /* Configure protocol + ALPN exactly as requested */
    if (use_quic)            protocol_mode("quic");
    else if (use_tls13 && use_tls12) protocol_mode("1.3", "1.2");
    else if (use_tls13)      protocol_mode("1.3");
    else                     protocol_mode("1.2");

    if (use_quic)            tls_mode("h3");
    else if (use_h2)         tls_mode("h2");
    else                     tls_mode("http/1.1");

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);
    addr.sin_addr.s_addr = inet_addr(ip);

    nanotls_conn *conn = tls_core_connect_addr(&addr, host);
    if (!conn) { printf("[%s] CONNECT FAILED\n", label); return 1; }

    const char *proto = conn->is_quic ? "HTTP/3 QUIC"
                      : conn->is_h2   ? "HTTP/2 TLS"
                                      : "HTTP/1.1 TLS";
    const char *tlsv = conn->is_tls12 ? "TLS1.2" : "TLS1.3";
    printf("[%s] connected: %s (%s, cipher=0x%04x)\n", label, proto, tlsv, conn->cipher_suite);

    add_chrome_headers(conn);
    tls_send_request(conn, "GET", path);

    char buf[65536];
    int total = 0, n;
    int fd = conn->fd;
    while (1) {
        struct timeval tv = { 2, 0 };
        fd_set rf; FD_ZERO(&rf); FD_SET(fd, &rf);
        if (select(fd + 1, &rf, NULL, NULL, &tv) <= 0) break;
        n = tls_core_recv(conn, buf, sizeof(buf) - 1);
        if (n <= 0) break;
        if (total == 0) {
            buf[n] = 0;
            /* print just the first ~300 bytes of the body/headers */
            printf("---- first bytes ----\n%.300s\n---------------------\n", buf);
        }
        total += n;
        if (total > 200000) break;
    }
    printf("[%s] total received: %d bytes\n", label, total);
    tls_core_close(conn);
    return 0;
}

int main(int argc, char **argv) {
    const char *ip   = argc > 1 ? argv[1] : "134.209.246.126";
    const char *host = argc > 2 ? argv[2] : "tls3.peet.ws";
    const char *path = argc > 3 ? argv[3] : "/api/clean";

    printf("Target: %s (%s)  path=%s\n", host, ip, path);
    tls_core_init();

    run("H2 / TLS1.3",       ip, host, path, 0, 1, 1, 0);
    run("H2 / TLS1.2",       ip, host, path, 0, 1, 0, 1);
    run("HTTP1.1 / TLS1.3",  ip, host, path, 0, 0, 1, 0);
    run("HTTP1.1 / TLS1.2",  ip, host, path, 0, 0, 0, 1);

    printf("\nAll protocol/TLS combinations exercised.\n");
    return 0;
}
