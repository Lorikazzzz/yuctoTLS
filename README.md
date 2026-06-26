# yoctoTLS

A dependency-free HTTP/3 (QUIC), HTTP/2 and HTTP/1.1 client library in C, with a
Chrome-accurate TLS/QUIC fingerprint, post-quantum key exchange (X25519MLKEM768),
and hardware-accelerated bulk crypto.

> Originally AI-generated. This fork fixes the security/correctness bugs, swaps the
> broken post-quantum code for the audited PQClean reference, adds TLS 1.3 session
> resumption, and hardware-accelerates AES-GCM / ChaCha20. See
> [CHANGELOG.md](CHANGELOG.md) for the full list of changes.

### Features
- HTTP/3 over QUIC, HTTP/2 and HTTP/1.1 with transparent fallback
- TLS 1.3 + TLS 1.2, Chrome-accurate JA3/JA4 fingerprint (incl. session resumption)
- X25519MLKEM768 post-quantum hybrid key exchange (FIPS 203 / PQClean)
- AES-128/256-GCM at multi-Gbit/s (AES-NI + PCLMULQDQ), 4-way SIMD ChaCha20
- No external dependencies — builds with `make`

### Build
```sh
make            # static + shared library
make test       # build the example clients (test_h2, test_quic)
./test_h2 <ip> <host> <path>
```

---

## Table of Contents
1. [Library Core & Lifecycle](#1-library-core--lifecycle)
2. [Protocol & TLS Configuration](#2-protocol--tls-configuration)
3. [Connection Management](#3-connection-management)
4. [HTTP Transaction & Header Management](#4-http-transaction--header-management)
5. [Data Flow (Read/Write)](#5-data-flow-readwrite)
6. [Complete Code Examples](#6-complete-code-examples)

---

## 1. Library Core & Lifecycle

### `tls_core_init`
```c
int tls_core_init(void);
```
* **Purpose**: Initializes the core global security states, cryptographic resources, pseudo-random number generators (PRNG), and network subsystems.
* **Arguments**: None.
* **Returns**: `0` on success, or a negative error code on failure.
* **Usage**: Must be invoked exactly once at the entry point of your application before calling any other library API.

---

### `tls_core_cleanup`
```c
void tls_core_cleanup(void);
```
* **Purpose**: Performs clean termination of global cryptographical contexts and cleans up any allocated memory/resources.
* **Usage**: Call at the termination point of your application.

---

## 2. Protocol & TLS Configuration

These functions control the runtime priorities, fallback order, and active negotiation modes of your secure client sessions.

### `protocol_mode`
```c
void protocol_mode(const char *mode1, ...);
```
* **Purpose**: Configures which cryptographic transport protocol versions are allowed and their order of preference.
* **Arguments**:
  * A null-terminated list of strings representing the enabled transport layers:
    * `"quic"`: Enables HTTP/3 over QUIC.
    * `"1.3"`: Enables TLS 1.3 over TCP.
    * `"1.2"`: Enables TLS 1.2 over TCP.
  * The final parameter must be a terminating `NULL` (or call helper with up to 3 arguments).
* **Usage Example**:
  ```c
  // Allow all, preferring QUIC first, then falling back to TLS 1.3, then TLS 1.2
  protocol_mode("quic", "1.3", "1.2");
  ```
  ```c
  // Exclusively restrict to QUIC (HTTP/3) with no fallback allowed
  protocol_mode("quic");
  ```

---

### `tls_mode`
```c
void tls_mode(const char *mode1, ...);
```
* **Purpose**: Configures the acceptable Application-Layer Protocol Negotiation (ALPN) modes and fallback order.
* **Arguments**:
  * A list of strings representing the enabled ALPN modes:
    * `"h2"`: Advertises HTTP/2 support in TCP/TLS ClientHello.
    * `"http/1.1"`: Advertises HTTP/1.1 support.
    * `"h3"`: Configures HTTP/3 support (used exclusively in QUIC modes).
* **Usage Example**:
  ```c
  // Prefer HTTP/2 but fallback to HTTP/1.1 if HTTP/2 is rejected by the server
  tls_mode("h2", "http/1.1");
  ```

---

## 3. Connection Management

### `tls_core_connect_addr`
```c
nanotls_conn* tls_core_connect_addr(struct sockaddr_in* addr, const char* host);
```
* **Purpose**: The master connection negotiator. It transparently attempts to connect to the target endpoint, executing the entire fallback sequence programmatically based on your configured `protocol_mode` and `tls_mode`.
* **Arguments**:
  * `addr`: A pointer to a standard `struct sockaddr_in` containing the destination IP and port (`443`).
  * `host`: The destination hostname (used for Server Name Indication / SNI verification).
* **Returns**: A pointer to an initialized `nanotls_conn` handle on success, or `NULL` if all fallback options were exhausted without success.
* **Fallback Behavior Under the Hood**:
  1. **Phase 1 (UDP/QUIC)**: If `"quic"` is enabled, it initiates a high-performance UDP socket. It runs a custom handshake loop with a **50ms socket read timeout** and **800ms total elapsed cap**. If successful, it returns a QUIC connection handle.
  2. **Phase 2 (HTTP/2 over TCP)**: If QUIC times out or fails, and `"h2"` is enabled, it establishes a TCP socket. It performs a TLS 1.3 handshake preferring ALPN `"h2"`. If the server rejects or fails post-quantum groups, it immediately retries exclusively using a TLS 1.2 handshake.
  3. **Phase 3 (HTTP/1.1 over TCP)**: If HTTP/2 is rejected or unavailable, it degrades the ALPN advertisement exclusively to `"http/1.1"`, retrying TLS 1.3 followed by TLS 1.2 to secure the TCP stream.

---

### `tls_core_close`
```c
void tls_core_close(nanotls_conn* conn);
```
* **Purpose**: Cleanly terminates a connection, releasing socket file descriptors, active cryptographic streams, and session handles.
* **Arguments**:
  * `conn`: A pointer to the active `nanotls_conn` connection handle.
* **Behavior**:
  * For **QUIC Connections**: Transmits a cryptographic connection close frame and closes the UDP socket.
  * For **TCP/TLS Connections**: Closes the underlying secure TCP socket cleanly.

---

## 4. HTTP Transaction & Header Management

### `tls_clear_headers`
```c
void tls_clear_headers(nanotls_conn* conn);
```
* **Purpose**: Empties the current request header table associated with the connection.
* **Arguments**:
  * `conn`: A pointer to the active `nanotls_conn` handle.
* **Usage**: Invoke prior to building a new request to prevent header leakage from previous requests.

---

### `tls_add_header`
```c
void tls_add_header(nanotls_conn* conn, const char* name, const char* value);
```
* **Purpose**: Appends a custom HTTP request header to the transaction table.
* **Arguments**:
  * `conn`: A pointer to the active `nanotls_conn` handle.
  * `name`: The HTTP header key string (e.g. `"User-Agent"`).
  * `value`: The header value string.
* **Usage Example**:
  ```c
  tls_add_header(conn, "accept", "application/json");
  ```

---

### `tls_send_request`
```c
int tls_send_request(nanotls_conn *conn, const char *method, const char *path);
```
* **Purpose**: Transmits a formatted HTTP request over the active secure connection.
* **Arguments**:
  * `conn`: A pointer to the active `nanotls_conn` handle.
  * `method`: The HTTP method string (e.g. `"GET"`, `"POST"`).
  * `path`: The target endpoint URL path (e.g. `"/api/all"`, `"/index.html"`).
* **Returns**: `1` on success, or a non-positive code on transport failures.
* **Dynamic Routing Under the Hood**:
  * **HTTP/3 over QUIC**: Synchronizes the transaction headers and invokes HTTP/3 QPACK frame builders on Stream `0`.
  * **HTTP/2**: Translates custom request headers into HPACK binary compressed headers using your pre-configured Akamai H2 fingerprint (`1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p`) for high-security evasion.
  * **HTTP/1.1**: Serializes the headers into a plain-text HTTP/1.1 message block and sends it.

---

## 5. Data Flow (Read/Write)

### `tls_core_recv`
```c
int tls_core_recv(nanotls_conn* conn, void* buf, int len);
```
* **Purpose**: Reads incoming application payload bytes securely.
* **Arguments**:
  * `conn`: A pointer to the active `nanotls_conn` handle.
  * `buf`: A pre-allocated memory buffer to receive the data.
  * `len`: The maximum number of bytes to read.
* **Returns**: The number of decrypted payload bytes copied to `buf` on success, `0` if no data is currently ready (non-blocking), or `-1` if the stream or connection is closed.
* **Usage Guide**:
  * In **QUIC/HTTP-3 Mode**: Drains decrypted payload bytes from the programmatic stream `rx_buf` accumulated during the asynchronous decryption of 1-RTT network packets.
  * In **TCP/TLS Mode**: Decrypts the next incoming application record chunk and copies it to the buffer.

---

## 6. Complete Code Examples

### Example 1: Multi-Protocol Auto-Negotiator & Fallback
This example shows how to configure a connection that starts at HTTP/3, and falls back automatically if the target server restricts or blocks UDP/QUIC traffic:

```c
#include "headers/nanotls.h"
#include "headers/includes.h"

int main(int argc, char *argv[]) {
    // 1. Initialize global system
    tls_core_init();

    // 2. Configure fallbacks
    protocol_mode("quic", "1.3", "1.2"); // Prefer QUIC -> TLS 1.3 -> TLS 1.2
    tls_mode("h2", "http/1.1");          // Prefer H2 ALPN -> HTTP 1.1

    // Setup Target Address (example: Cloudflare or WAF endpoint)
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(443);
    addr.sin_addr.s_addr = inet_addr("142.251.157.119");

    // 3. Connect (Automatically handles QUIC timeout and TCP/TLS exclusive fallback)
    nanotls_conn *conn = tls_core_connect_addr(&addr, "www.google.com");
    if (!conn) {
        printf("Connection failed.\n");
        return 1;
    }

    // Log the active negotiated protocol
    if (conn->is_quic) {
        printf("Negotiated: HTTP/3 (QUIC)\n");
    } else if (conn->is_h2) {
        printf("Negotiated: HTTP/2 over TLS\n");
    } else {
        printf("Negotiated: HTTP/1.1 over TLS\n");
    }

    // 4. Set Headers & Send GET Request
    tls_clear_headers(conn);
    tls_add_header(conn, "user-agent", "yoctoTLS Client v1.0");
    tls_send_request(conn, "GET", "/");

    // 5. Read Loop
    char response[65536];
    int n;
    while (1) {
        n = tls_core_recv(conn, response, sizeof(response) - 1);
        if (n < 0) {
            break; // Connection closed
        }
        if (n > 0) {
            response[n] = '\0';
            printf("%s", response);
        } else {
            usleep(10000); // Wait for non-blocking data
        }
    }

    // 6. Cleanup
    tls_core_close(conn);
    tls_core_cleanup();
    return 0;
}
```
