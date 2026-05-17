#include "headers/nanotls.h"
#include "headers/includes.h"

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: test_quic <ip> <host> [path]\n");
        printf("  Example: test_quic 205.185.123.167 tls.peet.ws /api/all\n");
        exit(1);
    }
    const char *ip   = argv[1];
    const char *host = argv[2];
    const char *path = (argc >= 4) ? argv[3] : "/";

    printf("╔══════════════════════════════════════════════════╗\n");
    printf("║  QUIC TLS 1.3 / HTTP3 Test (nanotls-wrapped)     \n");
    printf("╚══════════════════════════════════════════════════╝\n");
    printf("[init] target=%s  ip=%s  path=%s\n\n", host, ip, path);

    tls_core_init();

    // Configure purely for QUIC/HTTP3 exclusively
    protocol_mode("quic");
    tls_mode("h3");

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);
    addr.sin_addr.s_addr = inet_addr(ip);

    // Establish pure HTTP/3 QUIC connection
    nanotls_conn *conn = tls_core_connect_addr(&addr, host);
    if (!conn) {
        printf("[FATAL] Transparent QUIC connection failed.\n");
        exit(1);
    }

    printf("[negotiation] Active Connection: HTTP/3 (QUIC/UDP)\n");

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

    printf("[negotiation] Sending HTTP/3 GET request to %s...\n", path);
    tls_send_request(conn, "GET", path);

    printf("══════════════════ RECEIVED PAYLOAD ══════════════════\n");
    char *response = malloc(65536);
    int total_bytes = 0;
    
    if (response) {
        int fd = conn->fd;
        int timeouts = 0;
        while (1) {
            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 100000; // 100ms
            
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(fd, &rfds);
            
            int select_res = select(fd + 1, &rfds, NULL, NULL, &tv);
            if (select_res <= 0) {
                if (timeouts++ < 15) {
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
    printf("[negotiation] QUIC transaction finished successfully!\n");
    return 0;
}
