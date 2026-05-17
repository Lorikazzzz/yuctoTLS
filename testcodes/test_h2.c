#include "headers/nanotls.h"
#include "headers/includes.h"

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Usage: %s <ip> <host> <path>\n", argv[0]);
        exit(1);
    }

    const char *ip = argv[1];
    const char *host = argv[2];
    const char *path = argv[3];

    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║  Unified Multi-Protocol Auto-Negotiator (nanotls)\n");
    printf("╚══════════════════════════════════════════════════╝\n");
    printf("[init] target=%s  ip=%s  path=%s\n\n", host, ip, path);

    tls_core_init();
    protocol_mode("quic", "1.3", "1.2");
    tls_mode("h2", "http/1.1");

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);
    addr.sin_addr.s_addr = inet_addr(ip);

    // This single call will transparently try:
    // 1. HTTP/3 over QUIC/UDP (with 800ms handshake limit)
    // 2. HTTP/2 over TCP/TLS (TLS 1.3 -> TLS 1.2)
    // 3. HTTP/1.1 over TCP/TLS (TLS 1.3 -> TLS 1.2)
    nanotls_conn *conn = tls_core_connect_addr(&addr, host);
    if (!conn) {
        printf("[negotiation] FATAL: Protocol fallback exhausted without success.\n");
        exit(1);
    }

    if (conn->is_quic) {
        printf("[negotiation] Active Connection: HTTP/3 (QUIC/UDP)\n");
    } else if (conn->is_h2) {
        printf("[negotiation] Active Connection: HTTP/2 over TCP/TLS\n");
    } else {
        printf("[negotiation] Active Connection: HTTP/1.1 over TCP/TLS\n");
    }

    // Synchronize request headers
    tls_clear_headers(conn);
    tls_add_header(conn, "upgrade-insecure-requests", "1");
    tls_add_header(conn, "user-agent",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/147.0.0.0 Safari/537.36");
    tls_add_header(conn, "accept",
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8,"
        "application/signed-exchange;v=b3;q=0.7");
    tls_add_header(conn, "sec-ch-ua",
        "\"Google Chrome\";v=\"147\", \"Not.A/Brand\";v=\"8\", \"Chromium\";v=\"147\"");
    tls_add_header(conn, "sec-ch-ua-mobile", "?0");
    tls_add_header(conn, "sec-ch-ua-platform", "\"Linux\"");
    tls_add_header(conn, "sec-fetch-site", "none");
    tls_add_header(conn, "sec-fetch-mode", "navigate");
    tls_add_header(conn, "sec-fetch-user", "?1");
    tls_add_header(conn, "sec-fetch-dest", "document");
    tls_add_header(conn, "accept-encoding", "identity");
    tls_add_header(conn, "accept-language",
        "en-US,en;q=0.9,tr-TR;q=0.8,tr;q=0.7");
    tls_add_header(conn, "priority", "u=0, i");

    printf("[negotiation] Sending request to %s...\n", path);
    tls_send_request(conn, "GET", path);

    printf("══════════════════ RECEIVED PAYLOAD ══════════════════\n");
    char *response = malloc(65536);
    int total_bytes = 0;
    
    if (response) {
        int fd = conn->fd;
        int timeouts = 0;
        while (1) {
            struct timeval tv;
            tv.tv_sec = conn->is_quic ? 0 : 2;
            tv.tv_usec = conn->is_quic ? 100000 : 0; // 100ms for QUIC, 2s for TCP
            
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(fd, &rfds);
            
            int select_res = select(fd + 1, &rfds, NULL, NULL, &tv);
            if (select_res <= 0) {
                if (conn->is_quic && timeouts++ < 15) {
                    // Non-blocking UDP read loop requires slightly more grace
                    int n = tls_core_recv(conn, response, 65535);
                    if (n > 0) {
                        total_bytes += n;
                        response[n] = '\0';
                        printf("[frame] Received %d bytes\n", n);
                        printf("%s", response);
                        timeouts = 0;
                    }
                    usleep(10000);
                    continue;
                }
                break;
            }
            timeouts = 0;
            
            int n = tls_core_recv(conn, response, 65535);
            if (n < 0) {
                break;
            }
            if (n > 0) {
                total_bytes += n;
                response[n] = '\0';
                printf("[frame] Received %d bytes\n", n);
                
                int is_printable = 1;
                for (int i = 0; i < n; i++) {
                    char c = response[i];
                    if ((c < 32 || c > 126) && c != '\n' && c != '\r' && c != '\t') {
                        is_printable = 0;
                        break;
                    }
                }
                if (is_printable) {
                    printf("%s", response);
                } else {
                    printf("  [Binary Payload]\n");
                }
            } else {
                usleep(5000);
            }
        }
        free(response);
    }

    printf("\n══════════════════════════════════════════════════════\n");
    printf("[info] Total received payload: %d bytes\n\n", total_bytes);

    tls_core_close(conn);
    printf("[negotiation] Protocol auto-negotiation and transaction finished successfully!\n");
    return 0;
}
