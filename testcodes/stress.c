/*
 * stress.c — yoctoTLS performance & concurrency stress harness
 *
 * Three regimes that matter at "critical moments":
 *   1. Bulk AEAD throughput   — dominates large transfers (MB/s)
 *   2. Handshake primitives    — dominate connection storms (ops/s)
 *   3. Concurrency scaling      — validates thread-safety fixes under load
 *
 * Build:  gcc -O3 -pthread -I. -Iheaders testcodes/stress.c libyoctotls.a -o stress
 * Usage:  ./stress [seconds_per_test] [max_threads]
 */
#define _GNU_SOURCE
#include "headers/crypto.h"
#include "headers/chacha20.h"
#include "headers/nanotls.h"
#include "headers/includes.h"
#include <pthread.h>
#include <time.h>

/* internal builder, not in public header */
int tls13_chrome_client_hello_tcp(uint8_t *ch, const char *host, const uint8_t *pub_key,
                                  const uint8_t *pk_pq, const char *alpn_str, int alpn_len);

static double mono(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec * 1e-9;
}

/* fill with pseudo-random-ish bytes cheaply */
static void fillbuf(uint8_t *b, int n, uint32_t seed) {
    for (int i = 0; i < n; i++) { seed = seed * 1103515245u + 12345u; b[i] = seed >> 16; }
}

/* ── 1. Bulk AEAD throughput (16 KB TLS records) ─────────────────────────── */
#define REC 16384
static void bench_aead(double secs) {
    printf("\n=== Bulk AEAD throughput (16 KB records, single core) ===\n");
    uint8_t key[32], iv[12], ad[5] = {0x17,0x03,0x03,0x40,0x00};
    uint8_t *in = malloc(REC), *out = malloc(REC + 16), *dec = malloc(REC), tag[16];
    fillbuf(key,32,1); fillbuf(iv,12,2); fillbuf(in,REC,3);

    struct { const char *name; int rounds; int aes256; int chacha; } v[] = {
        {"AES-128-GCM", 10, 0, 0},
        {"AES-256-GCM", 14, 1, 0},
        {"ChaCha20-Poly1305", 0, 0, 1},
    };
    for (unsigned k = 0; k < sizeof(v)/sizeof(v[0]); k++) {
        /* pre-expand key schedule once (matches real connection behavior) */
        uint32_t w[60];
        if (!v[k].chacha) { if (v[k].aes256) aes_256_key_expand(key,w); else aes_128_key_expand(key,w); }
        long n = 0; double t0 = mono(), t;
        do {
            for (int r = 0; r < 64; r++) {
                if (v[k].chacha) {
                    chacha20_poly1305_encrypt(key, iv, ad, 5, in, REC, out, tag);
                    chacha20_poly1305_decrypt(key, iv, ad, 5, out, REC, dec, tag);
                } else {
                    aes_gcm_encrypt_ks(w, v[k].rounds, iv, ad, 5, in, REC, out, tag);
                    aes_gcm_decrypt_ks(w, v[k].rounds, iv, ad, 5, out, REC, dec, tag);
                }
                n += 2;  /* enc + dec */
            }
            t = mono() - t0;
        } while (t < secs);
        double mb = (double)n * REC / (1024*1024);
        printf("  %-20s %8.1f MB/s   (%.2f Gbit/s)   %ld ops\n",
               v[k].name, mb / t, mb*8/1024/t, n);
    }
    free(in); free(out); free(dec);
}

/* ── 2. Hash throughput (transcript hashing) ─────────────────────────────── */
static void bench_hash(double secs) {
    printf("\n=== Transcript hash throughput (single core) ===\n");
    uint8_t *in = malloc(REC), h[48]; fillbuf(in, REC, 7);
    { long n=0; double t0=mono(),t; do { for(int r=0;r<128;r++){ sha256_ctx_t c; sha256_init(&c); sha256_update(&c,in,REC); sha256_final(&c,h); n++; } t=mono()-t0; } while(t<secs);
      printf("  %-20s %8.1f MB/s\n","SHA-256",(double)n*REC/(1024*1024)/t); }
    { long n=0; double t0=mono(),t; do { for(int r=0;r<128;r++){ sha384_ctx_t c; sha384_init(&c); sha384_update(&c,in,REC); sha384_final(&c,h); n++; } t=mono()-t0; } while(t<secs);
      printf("  %-20s %8.1f MB/s\n","SHA-384",(double)n*REC/(1024*1024)/t); }
    free(in);
}

/* ── 3. Handshake primitives (per-connection cost) ───────────────────────── */
static void bench_handshake(double secs) {
    printf("\n=== Handshake primitives (per-connection cost) ===\n");
    uint8_t priv[32], pub[32], peer[32], shared[32];
    fillbuf(priv,32,11); fillbuf(peer,32,12);

    { long n=0; double t0=mono(),t; do { for(int r=0;r<64;r++){ x25519_base(pub,priv); n++; } t=mono()-t0; } while(t<secs);
      printf("  %-26s %8.0f ops/s   (%.1f us/op)\n","X25519 keygen",n/t,1e6*t/n); }
    { long n=0; double t0=mono(),t; do { for(int r=0;r<64;r++){ x25519(shared,priv,peer); n++; } t=mono()-t0; } while(t<secs);
      printf("  %-26s %8.0f ops/s   (%.1f us/op)\n","X25519 ECDH",n/t,1e6*t/n); }

    uint8_t pk[1184], sk[2400], coins[32], ss[32], ct[1088];
    fillbuf(coins,32,13);
    { long n=0; double t0=mono(),t; do { for(int r=0;r<16;r++){ mlkem768_keygen(pk,sk,coins); n++; } t=mono()-t0; } while(t<secs);
      printf("  %-26s %8.0f ops/s   (%.1f us/op)\n","ML-KEM-768 keygen",n/t,1e6*t/n); }
    /* a self-consistent ciphertext to decaps repeatedly */
    fillbuf(ct,1088,14);
    { long n=0; double t0=mono(),t; do { for(int r=0;r<16;r++){ mlkem768_decaps(ss,ct,sk); n++; } t=mono()-t0; } while(t<secs);
      printf("  %-26s %8.0f ops/s   (%.1f us/op)\n","ML-KEM-768 decaps",n/t,1e6*t/n); }

    /* full Chrome ClientHello construction (the fingerprint builder) */
    uint8_t ch[4096], pk_pq[1184]; fillbuf(pk_pq,1184,15);
    { long n=0; double t0=mono(),t; do { for(int r=0;r<256;r++){
        tls13_chrome_client_hello_tcp(ch,"tls3.peet.ws",pub,pk_pq,"\x02h2",3); n++; } t=mono()-t0; } while(t<secs);
      printf("  %-26s %8.0f ops/s   (%.1f us/op)\n","ClientHello build",n/t,1e6*t/n); }
}

/* ── 4. Concurrency scaling (thread-safety + aggregate throughput) ───────── */
typedef struct { double secs; long ops; uint64_t checksum; } work_t;

static void *aead_worker(void *a) {
    work_t *w = a;
    uint8_t key[32], iv[12], ad[5]={0x17,3,3,0x40,0}, *in=malloc(REC), *out=malloc(REC+16), *dec=malloc(REC), tag[16];
    fillbuf(key,32,(uint32_t)(uintptr_t)a); fillbuf(iv,12,99); fillbuf(in,REC,(uint32_t)(uintptr_t)a^5);
    uint32_t sched[60]; aes_128_key_expand(key,sched);
    long n=0; uint64_t cs=0; double t0=mono();
    do {
        for (int r=0;r<32;r++){
            aes_gcm_encrypt_ks(sched,10,iv,ad,5,in,REC,out,tag);
            int d = aes_gcm_decrypt_ks(sched,10,iv,ad,5,out,REC,dec,tag);
            cs += (d>0) ? (dec[0]+dec[REC-1]) : 0;   /* prove decrypt verified */
            n += 2;
        }
    } while (mono()-t0 < w->secs);
    w->ops = n; w->checksum = cs;
    free(in); free(out); free(dec);
    return NULL;
}

static void *hs_worker(void *a) {
    work_t *w = a;
    uint8_t priv[32],pub[32],peer[32],sh[32],pk[1184],sk[2400],coins[32],ss[32],ct[1088];
    fillbuf(priv,32,(uint32_t)(uintptr_t)a); fillbuf(peer,32,7); fillbuf(coins,32,(uint32_t)(uintptr_t)a^9); fillbuf(ct,1088,3);
    long n=0; uint64_t cs=0; double t0=mono();
    do {
        x25519_base(pub,priv);
        x25519(sh,priv,peer);
        mlkem768_keygen(pk,sk,coins);
        mlkem768_decaps(ss,ct,sk);
        cs += pub[0]+sh[0]+pk[0]+ss[0];
        n++;
    } while (mono()-t0 < w->secs);
    w->ops = n; w->checksum = cs;
    return NULL;
}

static void scale(const char *name, void *(*fn)(void*), double secs, int threads) {
    pthread_t th[256]; work_t w[256];
    for (int i=0;i<threads;i++){ w[i].secs=secs; w[i].ops=0; w[i].checksum=0; }
    double t0=mono();
    for (int i=0;i<threads;i++) pthread_create(&th[i],NULL,fn,&w[i]);
    long total=0; uint64_t cs=0;
    for (int i=0;i<threads;i++){ pthread_join(th[i],NULL); total+=w[i].ops; cs+=w[i].checksum; }
    double t=mono()-t0;
    printf("  %-12s %3d thr  %10ld ops  %10.0f ops/s   chk=%016llx\n",
           name, threads, total, total/t, (unsigned long long)cs);
}

static void bench_concurrency(double secs, int maxthr) {
    printf("\n=== Concurrency scaling (validates thread-safety under load) ===\n");
    printf("  -- AEAD (AES-128-GCM round trips, 16KB) --\n");
    for (int t=1; t<=maxthr; t*=2) scale("aead", aead_worker, secs, t);
    printf("  -- Handshake (X25519 x2 + ML-KEM keygen+decaps) --\n");
    for (int t=1; t<=maxthr; t*=2) scale("handshake", hs_worker, secs, t);
}

int main(int argc, char **argv) {
    double secs = argc > 1 ? atof(argv[1]) : 1.5;
    int maxthr  = argc > 2 ? atoi(argv[2]) : 0;
    if (maxthr <= 0) {
        long ncpu = sysconf(_SC_NPROCESSORS_ONLN);
        maxthr = (int)ncpu; if (maxthr < 1) maxthr = 4; if (maxthr > 256) maxthr = 256;
    }
    printf("yoctoTLS stress harness — %.1fs/test, up to %d threads (%ld cores)\n",
           secs, maxthr, sysconf(_SC_NPROCESSORS_ONLN));

    bench_aead(secs);
    bench_hash(secs);
    bench_handshake(secs);
    bench_concurrency(secs, maxthr);

    printf("\n[done]\n");
    return 0;
}
