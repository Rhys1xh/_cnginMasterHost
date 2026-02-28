/*
 * _cnginMasterHost HTTP/2 + kTLS Server - FINAL FIXED VERSION
 * No header conflicts - we use only linux/tcp.h and define what we need
 * Initially started at September 2025, now ready to release! Going to implement proper epoll mapping soon!
 * Ive built this for educational learning purposes only, i would'nt trust this server to run my backend. Just saying..
 * Compile: gcc -O3 -march=native -flto -pthread -o killer-httpd killer-httpd.c -luring
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <sys/sendfile.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/uio.h>        /* For writev */
#include <netinet/in.h>     /* For sockaddr_in (this is safe) */
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>

/* IMPORTANT: Only include linux/tcp.h, NOT netinet/tcp.h */
#include <linux/tcp.h>

/* kTLS headers */
#include <linux/tls.h>

/* io_uring */
#include <liburing.h>

/* Define the missing TCP socket options that would come from netinet/tcp.h */
#ifndef TCP_NODELAY
#define TCP_NODELAY 1
#endif
#ifndef TCP_DEFER_ACCEPT
#define TCP_DEFER_ACCEPT 9
#endif
#ifndef TCP_QUICKACK
#define TCP_QUICKACK 12
#endif
#ifndef TCP_FASTOPEN
#define TCP_FASTOPEN 23
#endif
#ifndef TCP_FASTOPEN_CONNECT
#define TCP_FASTOPEN_CONNECT 30
#endif

/* Define SOL_TCP if not defined */
#ifndef SOL_TCP
#define SOL_TCP IPPROTO_TCP
#endif

/* Configuration */
#define PORT 8443
#define MAX_EVENTS 262144
#define THREAD_COUNT 8
#define IO_URING_ENTRIES 32768
#define MAX_HTTP2_FRAMES 128
#define MAX_STREAMS 1000
#define HPACK_TABLE_SIZE 4096

/* HTTP/2 Frame Types */
#define HTTP2_DATA        0x0
#define HTTP2_HEADERS     0x1
#define HTTP2_PRIORITY    0x2
#define HTTP2_RST_STREAM  0x3
#define HTTP2_SETTINGS    0x4
#define HTTP2_PUSH_PROMISE 0x5
#define HTTP2_PING        0x6
#define HTTP2_GOAWAY      0x7
#define HTTP2_WINDOW_UPDATE 0x8
#define HTTP2_CONTINUATION 0x9

/* HTTP/2 Settings */
#define HTTP2_SETTINGS_HEADER_TABLE_SIZE 0x1
#define HTTP2_SETTINGS_ENABLE_PUSH 0x2
#define HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS 0x3
#define HTTP2_SETTINGS_INITIAL_WINDOW_SIZE 0x4
#define HTTP2_SETTINGS_MAX_FRAME_SIZE 0x5
#define HTTP2_SETTINGS_MAX_HEADER_LIST_SIZE 0x6

/* HTTP/2 Error Codes */
#define HTTP2_ERROR_NO_ERROR 0x0
#define HTTP2_ERROR_PROTOCOL 0x1
#define HTTP2_ERROR_INTERNAL 0x2
#define HTTP2_ERROR_FLOW_CONTROL 0x3
#define HTTP2_ERROR_SETTINGS_TIMEOUT 0x4
#define HTTP2_ERROR_STREAM_CLOSED 0x5
#define HTTP2_ERROR_FRAME_SIZE 0x6
#define HTTP2_ERROR_REFUSED_STREAM 0x7
#define HTTP2_ERROR_CANCEL 0x8
#define HTTP2_ERROR_COMPRESSION 0x9
#define HTTP2_ERROR_CONNECT 0xa
#define HTTP2_ERROR_ENHANCE_YOUR_CALM 0xb
#define HTTP2_ERROR_INADEQUATE_SECURITY 0xc
#define HTTP2_ERROR_HTTP_1_1_REQUIRED 0xd

/* HPACK Header Types */
#define HPACK_INDEXED 0x80
#define HPACK_LITERAL_INCREMENTAL 0x40
#define HPACK_LITERAL_INDEXED 0x00
#define HPACK_LITERAL_NEVER_INDEX 0x10
#define HPACK_CONTEXT_UPDATE 0x20

/* kTLS Crypto Info Structure */
struct ktls_crypto_info {
    struct tls12_crypto_info_aes_gcm_128 crypto_info;
    int tx_enabled;
    int rx_enabled;
};

/* HTTP/2 Stream State */
typedef struct {
    uint32_t stream_id;
    uint32_t window_size;
    uint8_t state;  /* 0: idle, 1: open, 2: half-closed, 3: closed */
    char *headers;
    size_t headers_len;
    int fd;  /* For file transfer */
    off_t file_offset;
    size_t file_size;
} http2_stream_t;

/* HTTP/2 Connection */
typedef struct {
    uint32_t settings[6];
    uint32_t window_size;
    http2_stream_t streams[MAX_STREAMS];
    int stream_count;
    uint32_t last_stream_id;
    uint8_t *hpack_table;
    size_t hpack_table_size;
    int hpack_table_used;
} http2_conn_t;

/* Connection Structure with kTLS and HTTP/2 */
typedef struct {
    int fd;
    int tls_fd;
    struct ktls_crypto_info ktls;
    http2_conn_t http2;
    struct io_uring *ring;
    time_t last_active;
    uint8_t *read_buf;
    size_t read_len;
    uint8_t *write_buf;
    size_t write_len;
    int using_http2;
    int peer_settings[6];
    struct sockaddr_in client_addr;
    char client_ip[INET_ADDRSTRLEN];
} killer_conn_t;

/* Thread Pool with io_uring */
typedef struct {
    pthread_t thread;
    int epoll_fd;
    struct io_uring ring;
    killer_conn_t **connections;
    int stop;
    int cpu_id;
} killer_thread_t;

/* Global state */
killer_thread_t threads[THREAD_COUNT];
int listen_fds[THREAD_COUNT];

/* ==================== HPACK Implementation ==================== */

/* Static HPACK Table (from RFC 7541) */
static const char *hpack_static_table[][2] = {
    {":authority", ""},
    {":method", "GET"},
    {":method", "POST"},
    {":path", "/"},
    {":path", "/index.html"},
    {":scheme", "http"},
    {":scheme", "https"},
    {":status", "200"},
    {":status", "204"},
    {":status", "206"},
    {":status", "304"},
    {":status", "400"},
    {":status", "404"},
    {":status", "500"},
    {"accept-charset", ""},
    {"accept-encoding", "gzip, deflate"},
    {"accept-language", ""},
    {"accept-ranges", ""},
    {"accept", ""},
    {"access-control-allow-origin", ""},
    {"age", ""},
    {"allow", ""},
    {"authorization", ""},
    {"cache-control", ""},
    {"content-disposition", ""},
    {"content-encoding", ""},
    {"content-language", ""},
    {"content-length", ""},
    {"content-location", ""},
    {"content-range", ""},
    {"content-type", ""},
    {"cookie", ""},
    {"date", ""},
    {"etag", ""},
    {"expect", ""},
    {"expires", ""},
    {"from", ""},
    {"host", ""},
    {"if-match", ""},
    {"if-modified-since", ""},
    {"if-none-match", ""},
    {"if-range", ""},
    {"if-unmodified-since", ""},
    {"last-modified", ""},
    {"link", ""},
    {"location", ""},
    {"max-forwards", ""},
    {"proxy-authenticate", ""},
    {"proxy-authorization", ""},
    {"range", ""},
    {"referer", ""},
    {"refresh", ""},
    {"retry-after", ""},
    {"server", "KillerHTTPd/kTLS"},
    {"set-cookie", ""},
    {"strict-transport-security", ""},
    {"transfer-encoding", ""},
    {"user-agent", ""},
    {"vary", ""},
    {"via", ""},
    {"www-authenticate", ""}
};

/* Encode integer in HPACK format */
static int hpack_encode_int(uint8_t *buf, uint32_t value, uint8_t prefix) {
    uint8_t mask = (1 << prefix) - 1;
    int pos = 0;
    
    if (value < mask) {
        buf[pos++] = value;
        return pos;
    }
    
    buf[pos++] = mask;
    value -= mask;
    
    while (value >= 128) {
        buf[pos++] = (value & 0x7F) | 0x80;
        value >>= 7;
    }
    buf[pos++] = value;
    
    return pos;
}

/* Encode header in HPACK format */
static int hpack_encode_header(uint8_t *buf, const char *name, const char *value) {
    uint8_t *p = buf;
    size_t name_len = strlen(name);
    size_t value_len = strlen(value);
    
    /* Try static table first */
    for (int i = 0; i < 61; i++) {
        if (strcmp(hpack_static_table[i][0], name) == 0) {
            if (strcmp(hpack_static_table[i][1], value) == 0) {
                /* Indexed header */
                *p++ = HPACK_INDEXED | (i + 1);
                return p - buf;
            } else if (hpack_static_table[i][1][0] == '\0') {
                /* Literal with indexed name */
                *p++ = HPACK_LITERAL_INCREMENTAL | (i + 1);
                p += hpack_encode_int(p, value_len, 7);
                memcpy(p, value, value_len);
                p += value_len;
                return p - buf;
            }
        }
    }
    
    /* New name - literal with incremental indexing */
    *p++ = HPACK_LITERAL_INCREMENTAL;
    p += hpack_encode_int(p, name_len, 7);
    memcpy(p, name, name_len);
    p += name_len;
    p += hpack_encode_int(p, value_len, 7);
    memcpy(p, value, value_len);
    p += value_len;
    
    return p - buf;
}

/* ==================== HTTP/2 Framing ==================== */

/* Build HTTP/2 frame header */
static void http2_build_frame(uint8_t *frame, uint32_t length, uint8_t type, 
                               uint8_t flags, uint32_t stream_id) {
    frame[0] = (length >> 16) & 0xFF;
    frame[1] = (length >> 8) & 0xFF;
    frame[2] = length & 0xFF;
    frame[3] = type;
    frame[4] = flags;
    frame[5] = (stream_id >> 24) & 0xFF;
    frame[6] = (stream_id >> 16) & 0xFF;
    frame[7] = (stream_id >> 8) & 0xFF;
    frame[8] = stream_id & 0xFF;
}

/* Send HTTP/2 SETTINGS frame */
static int http2_send_settings(killer_conn_t *conn) {
    uint8_t frame[9 + 6 * 6];
    
    uint8_t *payload = frame + 9;
    int pos = 0;
    
    /* Max concurrent streams */
    payload[pos++] = (HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS >> 8) & 0xFF;
    payload[pos++] = HTTP2_SETTINGS_MAX_CONCURRENT_STREAMS & 0xFF;
    payload[pos++] = (MAX_STREAMS >> 24) & 0xFF;
    payload[pos++] = (MAX_STREAMS >> 16) & 0xFF;
    payload[pos++] = (MAX_STREAMS >> 8) & 0xFF;
    payload[pos++] = MAX_STREAMS & 0xFF;
    
    /* Initial window size (64KB) */
    payload[pos++] = (HTTP2_SETTINGS_INITIAL_WINDOW_SIZE >> 8) & 0xFF;
    payload[pos++] = HTTP2_SETTINGS_INITIAL_WINDOW_SIZE & 0xFF;
    payload[pos++] = (65536 >> 24) & 0xFF;
    payload[pos++] = (65536 >> 16) & 0xFF;
    payload[pos++] = (65536 >> 8) & 0xFF;
    payload[pos++] = 65536 & 0xFF;
    
    /* Max frame size (16MB) */
    payload[pos++] = (HTTP2_SETTINGS_MAX_FRAME_SIZE >> 8) & 0xFF;
    payload[pos++] = HTTP2_SETTINGS_MAX_FRAME_SIZE & 0xFF;
    payload[pos++] = (16777215 >> 24) & 0xFF;
    payload[pos++] = (16777215 >> 16) & 0xFF;
    payload[pos++] = (16777215 >> 8) & 0xFF;
    payload[pos++] = 16777215 & 0xFF;
    
    http2_build_frame(frame, pos, HTTP2_SETTINGS, 0, 0);
    
    return write(conn->fd, frame, 9 + pos);
}

/* Send HTTP/2 HEADERS frame */
static int http2_send_headers(killer_conn_t *conn, uint32_t stream_id, 
                               int status, const char *content_type, size_t content_len) {
    uint8_t headers[1024];
    uint8_t frame[9 + sizeof(headers) + 32];
    int pos = 0;
    
    char status_str[8];
    snprintf(status_str, sizeof(status_str), "%d", status);
    pos += hpack_encode_header(headers + pos, ":status", status_str);
    
    pos += hpack_encode_header(headers + pos, "content-type", content_type);
    
    char len_str[16];
    snprintf(len_str, sizeof(len_str), "%zu", content_len);
    pos += hpack_encode_header(headers + pos, "content-length", len_str);
    
    pos += hpack_encode_header(headers + pos, "server", "KillerHTTPd/kTLS");
    
    http2_build_frame(frame, pos, HTTP2_HEADERS, 0x4, stream_id);
    memcpy(frame + 9, headers, pos);
    
    return write(conn->fd, frame, 9 + pos);
}

/* Send HTTP/2 DATA frame */
static int http2_send_data(killer_conn_t *conn, uint32_t stream_id, 
                            const void *data, size_t len, int end_stream) {
    uint8_t header[9];
    uint8_t flags = end_stream ? 0x1 : 0x0;
    
    http2_build_frame(header, len, HTTP2_DATA, flags, stream_id);
    
    struct iovec iov[2] = {
        {.iov_base = header, .iov_len = 9},
        {.iov_base = (void*)data, .iov_len = len}
    };
    
    return writev(conn->fd, iov, 2);
}

/* Parse HTTP/2 frame */
static int http2_parse_frame(killer_conn_t *conn, uint8_t *data, size_t len) {
    if (len < 9) return -1;
    
    uint32_t length = (data[0] << 16) | (data[1] << 8) | data[2];
    uint8_t type = data[3];
    uint8_t flags = data[4];
    uint32_t stream_id = (data[5] << 24) | (data[6] << 16) | (data[7] << 8) | data[8];
    stream_id &= 0x7FFFFFFF;
    
    if (9 + length > len) return -1;
    
    switch (type) {
        case HTTP2_SETTINGS:
            if (!(flags & 0x1)) {
                uint8_t ack[9];
                http2_build_frame(ack, 0, HTTP2_SETTINGS, 0x1, 0);
                write(conn->fd, ack, 9);
                printf("Received SETTINGS, sent ACK\n");
            }
            break;
            
        case HTTP2_HEADERS:
            printf("Received HEADERS for stream %u\n", stream_id);
            if (stream_id % 2 == 1) {
                /* Serve a simple HTML response */
                char response[] = "<html><body>"
                                 "<h1>🚀 Killer HTTP/2 + kTLS Server</h1>"
                                 "<p>Connection from: %s:%d</p>"
                                 "<p>HTTP/2 is working!</p>"
                                 "</body></html>";
                
                char html[512];
                snprintf(html, sizeof(html), response, 
                         conn->client_ip, ntohs(conn->client_addr.sin_port));
                
                http2_send_headers(conn, stream_id, 200, "text/html", strlen(html));
                http2_send_data(conn, stream_id, html, strlen(html), 1);
            }
            break;
            
        case HTTP2_DATA:
            printf("Received DATA for stream %u\n", stream_id);
            break;
            
        case HTTP2_PING:
            if (!(flags & 0x1)) {
                uint8_t pong[9 + 8];
                memcpy(pong + 9, data + 9, 8);
                http2_build_frame(pong, 8, HTTP2_PING, 0x1, stream_id);
                write(conn->fd, pong, sizeof(pong));
                printf("PING/PONG\n");
            }
            break;
            
        case HTTP2_GOAWAY:
            printf("GOAWAY received\n");
            return -1;
            
        case HTTP2_WINDOW_UPDATE:
            if (length >= 4) {
                uint32_t increment = (data[9] << 24) | (data[10] << 16) | 
                                     (data[11] << 8) | data[12];
                conn->http2.window_size += increment;
                printf("WINDOW_UPDATE: +%u = %u\n", increment, conn->http2.window_size);
            }
            break;
            
        default:
            printf("Unknown frame type %u\n", type);
    }
    
    return 9 + length;
}

/* ==================== kTLS Setup (Simplified) ==================== */

/* Initialize kTLS on socket (simplified for demo) */
static int ktls_init(int fd) {
    int ret;
    
    /* First set TLS ULP */
    if (setsockopt(fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls")) < 0) {
        printf("kTLS not available - continuing without encryption\n");
        return -1;
    }
    
    printf("✅ kTLS ULP set on socket %d\n", fd);
    return 0;
}

/* ==================== Connection Handling ==================== */

/* Handle HTTP/2 connection */
static void handle_http2_connection(killer_conn_t *conn) {
    uint8_t buffer[65536];
    
    /* Send initial SETTINGS */
    http2_send_settings(conn);
    
    printf("📡 HTTP/2 connection from %s:%d\n", 
           conn->client_ip, ntohs(conn->client_addr.sin_port));
    
    while (1) {
        ssize_t bytes = read(conn->fd, buffer, sizeof(buffer));
        if (bytes <= 0) {
            if (bytes == 0) {
                printf("Connection closed\n");
            } else if (errno != EAGAIN) {
                perror("read");
            }
            break;
        }
        
        size_t pos = 0;
        while (pos < bytes) {
            int consumed = http2_parse_frame(conn, buffer + pos, bytes - pos);
            if (consumed <= 0) break;
            pos += consumed;
        }
    }
}

/* Accept connection and setup kTLS */
static void handle_new_connection(killer_thread_t *thread, int listen_fd) {
    struct sockaddr_in addr;
    socklen_t addrlen = sizeof(addr);
    
    int client_fd = accept4(listen_fd, (struct sockaddr*)&addr, &addrlen, 
                             SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (client_fd < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            perror("accept4");
        }
        return;
    }
    
    /* Set TCP optimizations */
    int flag = 1;
    setsockopt(client_fd, SOL_TCP, TCP_NODELAY, &flag, sizeof(flag));
    setsockopt(client_fd, SOL_TCP, TCP_DEFER_ACCEPT, &flag, sizeof(flag));
    setsockopt(client_fd, SOL_SOCKET, SO_KEEPALIVE, &flag, sizeof(flag));
    
    /* Increase socket buffers */
    int buf_size = 4 * 1024 * 1024;
    setsockopt(client_fd, SOL_SOCKET, SO_RCVBUF, &buf_size, sizeof(buf_size));
    setsockopt(client_fd, SOL_SOCKET, SO_SNDBUF, &buf_size, sizeof(buf_size));
    
    /* Create connection object */
    killer_conn_t *conn = calloc(1, sizeof(killer_conn_t));
    if (!conn) {
        close(client_fd);
        return;
    }
    
    conn->fd = client_fd;
    conn->ring = &thread->ring;
    conn->read_buf = malloc(65536);
    conn->write_buf = malloc(65536);
    conn->http2.window_size = 65535;
    memcpy(&conn->client_addr, &addr, sizeof(addr));
    inet_ntop(AF_INET, &addr.sin_addr, conn->client_ip, sizeof(conn->client_ip));
    
    if (!conn->read_buf || !conn->write_buf) {
        free(conn->read_buf);
        free(conn->write_buf);
        free(conn);
        close(client_fd);
        return;
    }
    
    /* Add to epoll */
    struct epoll_event ev = {
        .events = EPOLLIN | EPOLLET | EPOLLRDHUP,
        .data.ptr = conn
    };
    
    if (epoll_ctl(thread->epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) < 0) {
        perror("epoll_ctl");
        free(conn->read_buf);
        free(conn->write_buf);
        free(conn);
        close(client_fd);
        return;
    }
    
    printf("🔌 New connection from %s:%d (fd=%d)\n", 
           conn->client_ip, ntohs(addr.sin_port), client_fd);
    
    /* Try to setup kTLS */
    if (ktls_init(client_fd) == 0) {
        conn->using_http2 = 1;
        /* Handle HTTP/2 in the same thread for simplicity */
        handle_http2_connection(conn);
    } else {
        /* Fallback to plain HTTP/1.1 */
        char msg[512];
        snprintf(msg, sizeof(msg),
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/html\r\n"
                "\r\n"
                "<html><body>"
                "<h1>Killer HTTP Server</h1>"
                "<p>kTLS not available, but server is running!</p>"
                "<p>Your IP: %s:%d</p>"
                "</body></html>\r\n",
                conn->client_ip, ntohs(addr.sin_port));
        
        write(client_fd, msg, strlen(msg));
    }
    
    /* Cleanup */
    epoll_ctl(thread->epoll_fd, EPOLL_CTL_DEL, client_fd, NULL);
    close(client_fd);
    free(conn->read_buf);
    free(conn->write_buf);
    free(conn);
    
    printf("👋 Connection closed\n");
}

/* ==================== Worker Thread ==================== */

static void* worker_thread_func(void *arg) {
    killer_thread_t *thread = (killer_thread_t*)arg;
    struct epoll_event events[MAX_EVENTS];
    cpu_set_t cpuset;
    
    /* Pin thread to specific CPU */
    CPU_ZERO(&cpuset);
    CPU_SET(thread->cpu_id % CPU_SETSIZE, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    
    /* Initialize io_uring */
    if (io_uring_queue_init(IO_URING_ENTRIES, &thread->ring, 0) < 0) {
        perror("io_uring_queue_init");
        return NULL;
    }
    
    /* Create epoll instance */
    thread->epoll_fd = epoll_create1(EPOLL_CLOEXEC);
    if (thread->epoll_fd < 0) {
        perror("epoll_create1");
        return NULL;
    }
    
    /* Add listener to epoll */
    struct epoll_event ev = {
        .events = EPOLLIN | EPOLLET,
        .data.fd = listen_fds[thread->cpu_id]
    };
    if (epoll_ctl(thread->epoll_fd, EPOLL_CTL_ADD, listen_fds[thread->cpu_id], &ev) < 0) {
        perror("epoll_ctl add listener");
        return NULL;
    }
    
    printf("🧵 Thread %d started on CPU %d\n", thread->cpu_id, thread->cpu_id);
    
    /* Event loop */
    while (!thread->stop) {
        int nfds = epoll_wait(thread->epoll_fd, events, MAX_EVENTS, 1000);
        
        for (int i = 0; i < nfds; i++) {
            if (events[i].data.fd == listen_fds[thread->cpu_id]) {
                /* New connection - accept all pending */
                while (1) {
                    handle_new_connection(thread, listen_fds[thread->cpu_id]);
                    if (errno == EAGAIN || errno == EWOULDBLOCK)
                        break;
                }
            }
        }
        
        /* Process io_uring completions */
        struct io_uring_cqe *cqe;
        unsigned head;
        io_uring_for_each_cqe(&thread->ring, head, cqe) {
            io_uring_cqe_seen(&thread->ring, cqe);
        }
    }
    
    io_uring_queue_exit(&thread->ring);
    close(thread->epoll_fd);
    return NULL;
}

/* ==================== Main ==================== */

static void signal_handler(int sig) {
    printf("\n⚠️  Shutting down...\n");
    for (int i = 0; i < THREAD_COUNT; i++) {
        threads[i].stop = 1;
    }
}

static void print_banner(void) {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════╗\n");
    printf("║     KILLER HTTP/2 + kTLS SERVER v2.0                    ║\n");
    printf("║     \"The One Without Header Conflicts\"                  ║\n");
    printf("╚══════════════════════════════════════════════════════════╝\n\n");
}

int main(void) {
    struct rlimit rl;
    
    print_banner();
    
    /* Increase file descriptor limit */
    rl.rlim_cur = 1048576;
    rl.rlim_max = 1048576;
    if (setrlimit(RLIMIT_NOFILE, &rl) < 0) {
        printf("⚠️  Could not increase FD limit - run as root for max performance\n");
    } else {
        printf("✅ File descriptor limit increased to 1,048,576\n");
    }
    
    /* Check kTLS availability */
    int test_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (test_fd >= 0) {
        if (setsockopt(test_fd, SOL_TCP, TCP_ULP, "tls", sizeof("tls")) < 0) {
            printf("⚠️  kTLS not available - run: sudo modprobe tls\n");
        } else {
            printf("✅ kTLS available - encryption can be in kernel space\n");
        }
        close(test_fd);
    }
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    /* Create SO_REUSEPORT listeners */
    for (int i = 0; i < THREAD_COUNT; i++) {
        listen_fds[i] = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (listen_fds[i] < 0) {
            perror("socket");
            return 1;
        }
        
        int opt = 1;
        setsockopt(listen_fds[i], SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        setsockopt(listen_fds[i], SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
        
        /* Enable TCP Fast Open */
        int qlen = 5;
        setsockopt(listen_fds[i], SOL_TCP, TCP_FASTOPEN, &qlen, sizeof(qlen));
        
        struct sockaddr_in addr = {
            .sin_family = AF_INET,
            .sin_port = htons(PORT),
            .sin_addr = { INADDR_ANY }
        };
        
        if (bind(listen_fds[i], (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("bind");
            printf("   Port %d might be in use\n", PORT);
            return 1;
        }
        
        if (listen(listen_fds[i], 65535) < 0) {
            perror("listen");
            return 1;
        }
        
        printf("✅ Listener %d on port %d (SO_REUSEPORT + TCP_FASTOPEN)\n", i, PORT);
    }
    
    /* Start threads */
    for (int i = 0; i < THREAD_COUNT; i++) {
        threads[i].cpu_id = i;
        threads[i].stop = 0;
        if (pthread_create(&threads[i].thread, NULL, worker_thread_func, &threads[i]) != 0) {
            perror("pthread_create");
            return 1;
        }
    }
    
    printf("\n🚀 Server running with %d threads\n", THREAD_COUNT);
    printf("📡 Listening on port %d\n", PORT);
    printf("🔧 Features:\n");
    printf("   • HTTP/2 ready (use curl --http2)\n");
    printf("   • kTLS ready (if module loaded)\n");
    printf("   • io_uring async I/O\n");
    printf("   • SO_REUSEPORT kernel load balancing\n");
    printf("   • TCP Fast Open\n");
    printf("\n📝 Test commands:\n");
    printf("   curl -v http://localhost:%d/\n", PORT);
    printf("   curl --http2 -v http://localhost:%d/\n", PORT);
    printf("   curl --http2-prior-knowledge -v http://localhost:%d/\n", PORT);
    printf("\nPress Ctrl+C to stop\n\n");
    
    /* Wait for threads */
    for (int i = 0; i < THREAD_COUNT; i++) {
        pthread_join(threads[i].thread, NULL);
    }
    
    /* Cleanup */
    for (int i = 0; i < THREAD_COUNT; i++) {
        close(listen_fds[i]);
    }
    
    printf("✅ Server shutdown complete\n");
    return 0;
}