/*
 * test_nbd.c - Unit tests for the NBD protocol server
 *
 * Tests nbd_bind() and nbd_serve() by running the full handshake + DISC
 * flow with a mock iSCSI target (socketpair) and a real NBD TCP client
 * (child process).
 *
 * Test structure:
 *   - socketpair(sv) acts as the iSCSI connection
 *   - nbd_bind() creates the NBD listening socket
 *   - Parent: spawns an nbd_serve pthread (nbd server) and acts as the
 *     iSCSI mock target on sv[1]
 *   - Child: connects to the NBD port and performs the NBD protocol
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "../src/daemon/nbd.h"
#include "../src/daemon/scsi.h"
#include "../src/daemon/pdu.h"
#include "../src/daemon/session.h"
#include "../src/daemon/connection.h"
#include "../src/shared/iscsi_protocol.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#define TEST(name) \
    do { printf("  %-56s", name); fflush(stdout); } while (0)
#define PASS()  printf("PASS\n")
#define FAIL(msg) \
    do { printf("FAIL: %s\n", msg); failures++; } while (0)

static int failures = 0;

/* -----------------------------------------------------------------------
 * NBD protocol wire constants (for the test client)
 * ----------------------------------------------------------------------- */

#define NBD_MAGIC            UINT64_C(0x4e42444d41474943)
#define NBD_IHAVEOPT         UINT64_C(0x49484156454f5054)
#define NBD_REQUEST_MAGIC    UINT32_C(0x25609513)
#define NBD_RESPONSE_MAGIC   UINT32_C(0x67446698)

#define NBD_FLAG_C_FIXED_NEWSTYLE 0x00000001u
#define NBD_FLAG_C_NO_ZEROES      0x00000002u

#define NBD_OPT_EXPORT_NAME  1u
#define NBD_OPT_GO           7u

#define NBD_CMD_READ    0u
#define NBD_CMD_WRITE   1u
#define NBD_CMD_DISC    2u

/* -----------------------------------------------------------------------
 * Byte-order helpers (for the NBD client side in tests)
 * ----------------------------------------------------------------------- */

static void tp_put64be(uint8_t *b, uint64_t v)
{
    b[0]=(uint8_t)(v>>56); b[1]=(uint8_t)(v>>48);
    b[2]=(uint8_t)(v>>40); b[3]=(uint8_t)(v>>32);
    b[4]=(uint8_t)(v>>24); b[5]=(uint8_t)(v>>16);
    b[6]=(uint8_t)(v>> 8); b[7]=(uint8_t)(v);
}
static void tp_put32be(uint8_t *b, uint32_t v)
{
    b[0]=(uint8_t)(v>>24); b[1]=(uint8_t)(v>>16);
    b[2]=(uint8_t)(v>> 8); b[3]=(uint8_t)(v);
}
static void tp_put16be(uint8_t *b, uint16_t v)
{
    b[0]=(uint8_t)(v>>8); b[1]=(uint8_t)(v);
}
static uint64_t tp_get64be(const uint8_t *b)
{
    return ((uint64_t)b[0]<<56)|((uint64_t)b[1]<<48)|
           ((uint64_t)b[2]<<40)|((uint64_t)b[3]<<32)|
           ((uint64_t)b[4]<<24)|((uint64_t)b[5]<<16)|
           ((uint64_t)b[6]<< 8)| (uint64_t)b[7];
}
static uint32_t tp_get32be(const uint8_t *b)
{
    return ((uint32_t)b[0]<<24)|((uint32_t)b[1]<<16)|
           ((uint32_t)b[2]<< 8)| (uint32_t)b[3];
}

static int tp_write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n <= 0) return -1;
        p += (size_t)n; len -= (size_t)n;
    }
    return 0;
}
static int tp_read_all(int fd, void *buf, size_t len)
{
    uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n <= 0) return -1;
        p += (size_t)n; len -= (size_t)n;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * iSCSI mock target helpers (reuse pattern from test_scsi.c)
 * ----------------------------------------------------------------------- */

/*
 * Read one length-prefixed PDU from fd, return the ITT from bytes [16..19].
 */
static uint32_t mock_drain_cmd_get_itt(int fd)
{
    uint8_t lbuf[4];
    if ((ssize_t)sizeof(lbuf) != recv(fd, lbuf, 4, 0)) return 0xFFFFFFFF;
    uint32_t total = ((uint32_t)lbuf[0]<<24)|((uint32_t)lbuf[1]<<16)|
                     ((uint32_t)lbuf[2]<< 8)| (uint32_t)lbuf[3];
    if (total < 48) return 0xFFFFFFFF;
    uint8_t *buf = malloc(total);
    if (!buf) return 0xFFFFFFFF;
    ssize_t n = recv(fd, buf, total, 0);
    uint32_t itt = (n == (ssize_t)total)
                   ? ntohl(*(uint32_t *)(buf + 16))
                   : 0xFFFFFFFF;
    free(buf);
    return itt;
}

/*
 * Send a Data-In PDU with the S-bit (status embedded) on fd.
 * Simulates the iSCSI target responding to a SCSI read command.
 * Uses a raw 48-byte buffer to match the wire format precisely.
 */
static int mock_send_data_in(int fd, uint32_t itt, uint8_t status,
                               const uint8_t *data, uint32_t data_len)
{
    uint8_t hdr[48];
    memset(hdr, 0, 48);
    hdr[0] = ISCSI_OP_SCSI_DATA_IN | 0x80;
    hdr[1] = ISCSI_FLAG_FINAL | 0x01;   /* F-bit + S-bit */
    hdr[3] = status;
    iscsi_dlength_set(hdr + 5, data_len);
    *(uint32_t *)(hdr + 16) = htonl(itt);   /* ITT */
    *(uint32_t *)(hdr + 24) = htonl(1);     /* StatSN */

    iscsi_pdu_t pdu;
    memset(&pdu, 0, sizeof(pdu));
    memcpy(&pdu.hdr, hdr, 48);
    if (data && data_len)
        pdu_set_data_ref(&pdu, data, data_len);
    return pdu_send(fd, &pdu, 0, 0);
}

/* -----------------------------------------------------------------------
 * Session / connection factory
 * ----------------------------------------------------------------------- */

static iscsi_session_t *make_sess(void)
{
    iscsi_session_t *s = session_create(SESS_TYPE_NORMAL,
                                        "iqn.2024-01.io.test:init",
                                        "iqn.2024-01.io.test:target",
                                        "127.0.0.1:3260");
    if (!s) return NULL;
    s->state = SESS_STATE_LOGGED_IN;
    s->tsih  = 1;
    s->params.initial_r2t        = 1;
    s->params.immediate_data     = 1;
    s->params.first_burst_length = 65536;
    s->params.max_burst_length   = 262144;
    return s;
}

static iscsi_conn_t *make_conn(int fd)
{
    iscsi_conn_t *c = calloc(1, sizeof(*c));
    if (!c) return NULL;
    c->fd           = fd;
    c->state        = CONN_STATE_LOGGED_IN;
    c->cid          = 1;
    c->exp_statsn   = 0;
    c->max_send_dsl = 8192;
    c->max_recv_dsl = 262144;
    return c;
}

/* -----------------------------------------------------------------------
 * Thread argument for nbd_serve
 * ----------------------------------------------------------------------- */

typedef struct {
    iscsi_session_t *sess;
    iscsi_conn_t    *conn;
    uint8_t          lun_raw[8];
    int              listen_fd;
    int              result;   /* filled in by thread: 0 = ok, -1 = error */
} nbd_serve_arg_t;

static void *nbd_serve_thread(void *arg)
{
    nbd_serve_arg_t *a = arg;
    a->result = nbd_serve(a->sess, a->conn, a->lun_raw, a->listen_fd);
    return NULL;
}

/* -----------------------------------------------------------------------
 * Test 1: nbd_bind() returns a valid listening fd and port
 * ----------------------------------------------------------------------- */

static void test_nbd_bind(void)
{
    TEST("nbd_bind: returns fd and loopback port");

    int port = 0;
    int fd = nbd_bind(&port);
    if (fd < 0) { FAIL("nbd_bind returned -1"); return; }
    if (port < 1024 || port > 65535) {
        close(fd);
        FAIL("port out of range");
        return;
    }

    /* Verify it's actually listening by connecting to it */
    int cfd = socket(AF_INET, SOCK_STREAM, 0);
    if (cfd < 0) { close(fd); FAIL("socket"); return; }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons((uint16_t)port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    int connected = (connect(cfd, (struct sockaddr *)&addr, sizeof(addr)) == 0);
    close(cfd);
    close(fd);

    if (!connected) { FAIL("connect to bound port failed"); return; }
    PASS();
}

/* -----------------------------------------------------------------------
 * Test 2: full handshake (NBD_OPT_EXPORT_NAME) + DISC
 *
 * Parent:  iSCSI mock target (sv[1]) + joins nbd_serve thread
 * nbd_serve thread: runs the NBD server
 * Child:   NBD client — connects, handshakes, sends DISC
 * ----------------------------------------------------------------------- */

static void test_handshake_disc(void)
{
    TEST("nbd_serve: EXPORT_NAME handshake + DISC");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { FAIL("socketpair"); return; }

    int port = 0;
    int listen_fd = nbd_bind(&port);
    if (listen_fd < 0) { close(sv[0]); close(sv[1]); FAIL("nbd_bind"); return; }

    iscsi_session_t *sess = make_sess();
    iscsi_conn_t    *conn = make_conn(sv[0]);
    if (!sess || !conn) {
        close(sv[0]); close(sv[1]); close(listen_fd);
        free(conn); if (sess) session_destroy(sess);
        FAIL("alloc"); return;
    }

    uint8_t lun_raw[8] = {0};

    /* Start nbd_serve in a thread */
    nbd_serve_arg_t arg = {
        .sess      = sess,
        .conn      = conn,
        .listen_fd = listen_fd,
        .result    = -1,
    };
    memcpy(arg.lun_raw, lun_raw, 8);

    pthread_t tid;
    if (pthread_create(&tid, NULL, nbd_serve_thread, &arg) != 0) {
        close(sv[0]); close(sv[1]); close(listen_fd);
        free(conn); session_destroy(sess);
        FAIL("pthread_create"); return;
    }

    /* Fork: child is the NBD client */
    pid_t pid = fork();
    if (pid < 0) {
        pthread_cancel(tid); pthread_join(tid, NULL);
        close(sv[0]); close(sv[1]);
        free(conn); session_destroy(sess);
        FAIL("fork"); return;
    }

    if (pid == 0) {
        /* ---- Child: NBD client ---- */
        close(sv[0]); close(sv[1]);

        /* Connect to the NBD server */
        int cfd = socket(AF_INET, SOCK_STREAM, 0);
        if (cfd < 0) _exit(1);
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family      = AF_INET;
        addr.sin_port        = htons((uint16_t)port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (connect(cfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) _exit(1);

        /* Read server greeting: NBDMAGIC (8) + IHAVEOPT (8) + flags (2) */
        uint8_t greeting[18];
        if (tp_read_all(cfd, greeting, 18) != 0) _exit(1);
        if (tp_get64be(greeting) != NBD_MAGIC) _exit(1);
        if (tp_get64be(greeting + 8) != NBD_IHAVEOPT) _exit(1);

        /* Send client flags */
        uint8_t cflags[4];
        tp_put32be(cflags, NBD_FLAG_C_FIXED_NEWSTYLE | NBD_FLAG_C_NO_ZEROES);
        if (tp_write_all(cfd, cflags, 4) != 0) _exit(1);

        /* Send NBD_OPT_EXPORT_NAME with empty name */
        uint8_t opt[16];
        tp_put64be(opt,     NBD_IHAVEOPT);
        tp_put32be(opt + 8, NBD_OPT_EXPORT_NAME);
        tp_put32be(opt + 12, 0);  /* zero-length name = default export */
        if (tp_write_all(cfd, opt, 16) != 0) _exit(1);

        /* Read export size (8) + transmission flags (2). No zeroes padding
         * because we negotiated NBD_FLAG_C_NO_ZEROES. */
        uint8_t expinfo[10];
        if (tp_read_all(cfd, expinfo, 10) != 0) _exit(1);
        uint64_t export_size = tp_get64be(expinfo);
        /* Expected: 2000 blocks * 512 bytes = 1024000 (mock READ CAPACITY) */
        if (export_size != (uint64_t)2000 * 512) _exit(1);

        /* Send NBD_CMD_DISC */
        uint8_t disc[28];
        memset(disc, 0, 28);
        tp_put32be(disc,     NBD_REQUEST_MAGIC);
        /* flags = 0, type = NBD_CMD_DISC, handle = 0, offset = 0, length = 0 */
        tp_put16be(disc + 6, (uint16_t)NBD_CMD_DISC);
        if (tp_write_all(cfd, disc, 28) != 0) _exit(1);

        close(cfd);
        _exit(0);
    }

    /* ---- Parent: iSCSI mock target on sv[1] ---- */
    /* sv[0] is used by conn (nbd_serve thread); sv[1] is our mock target end. */

    /*
     * nbd_serve() calls scsi_read_capacity10() before accept().
     * The SCSI command arrives on sv[1] (the target side).
     * Respond with: last_lba=1999 (2000 blocks), block_size=512.
     */
    uint32_t itt = mock_drain_cmd_get_itt(sv[1]);
    uint8_t cap_data[8] = {
        0x00, 0x00, 0x07, 0xCF,   /* last LBA = 1999 */
        0x00, 0x00, 0x02, 0x00,   /* block size = 512 */
    };
    mock_send_data_in(sv[1], itt, 0 /* GOOD */, cap_data, 8);

    /* Wait for nbd_serve thread to finish */
    pthread_join(tid, NULL);

    /* Wait for child */
    int child_status = 0;
    waitpid(pid, &child_status, 0);

    int failed = 0;
    if (arg.result != 0) { FAIL("nbd_serve returned non-zero"); failed = 1; }
    if (!failed && (!WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0)) {
        FAIL("NBD client child exited with error");
        failed = 1;
    }

    free(conn);
    session_destroy(sess);
    close(sv[0]);
    close(sv[1]);

    if (!failed) PASS();
}

/* -----------------------------------------------------------------------
 * Test 3: NBD_OPT_GO handshake
 * ----------------------------------------------------------------------- */

static void test_handshake_go(void)
{
    TEST("nbd_serve: OPT_GO handshake + DISC");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) { FAIL("socketpair"); return; }

    int port = 0;
    int listen_fd = nbd_bind(&port);
    if (listen_fd < 0) { close(sv[0]); close(sv[1]); FAIL("nbd_bind"); return; }

    iscsi_session_t *sess = make_sess();
    iscsi_conn_t    *conn = make_conn(sv[0]);
    if (!sess || !conn) {
        close(sv[0]); close(sv[1]); close(listen_fd);
        free(conn); if (sess) session_destroy(sess);
        FAIL("alloc"); return;
    }

    uint8_t lun_raw[8] = {0};
    nbd_serve_arg_t arg = {
        .sess = sess, .conn = conn, .listen_fd = listen_fd, .result = -1,
    };
    memcpy(arg.lun_raw, lun_raw, 8);

    pthread_t tid;
    if (pthread_create(&tid, NULL, nbd_serve_thread, &arg) != 0) {
        close(sv[0]); close(sv[1]); close(listen_fd);
        free(conn); session_destroy(sess); FAIL("pthread_create"); return;
    }

    pid_t pid = fork();
    if (pid < 0) {
        pthread_cancel(tid); pthread_join(tid, NULL);
        close(sv[0]); close(sv[1]);
        free(conn); session_destroy(sess); FAIL("fork"); return;
    }

    if (pid == 0) {
        close(sv[0]); close(sv[1]);

        int cfd = socket(AF_INET, SOCK_STREAM, 0);
        if (cfd < 0) _exit(1);
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port   = htons((uint16_t)port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (connect(cfd, (struct sockaddr *)&addr, sizeof(addr)) != 0) _exit(1);

        /* Read greeting */
        uint8_t greeting[18];
        if (tp_read_all(cfd, greeting, 18) != 0) _exit(1);
        if (tp_get64be(greeting) != NBD_MAGIC) _exit(1);

        /* Send client flags */
        uint8_t cflags[4];
        tp_put32be(cflags, NBD_FLAG_C_FIXED_NEWSTYLE | NBD_FLAG_C_NO_ZEROES);
        if (tp_write_all(cfd, cflags, 4) != 0) _exit(1);

        /* Send NBD_OPT_GO with empty name */
        uint8_t opt[20];
        tp_put64be(opt,      NBD_IHAVEOPT);
        tp_put32be(opt +  8, NBD_OPT_GO);
        tp_put32be(opt + 12, 4);   /* 4 bytes of option data */
        tp_put32be(opt + 16, 0);   /* name length = 0 (default export) */
        if (tp_write_all(cfd, opt, 20) != 0) _exit(1);

        /*
         * Read NBD_REP_INFO (20-byte reply header + 12-byte INFO_EXPORT body)
         * then NBD_REP_ACK (20-byte reply header, no body).
         */
        uint8_t rep[20 + 12];
        if (tp_read_all(cfd, rep, 32) != 0) _exit(1);

        /* Verify it's a reply to OPT_GO and read the export size */
        uint32_t rep_opt  = tp_get32be(rep + 8);
        uint32_t rep_type = tp_get32be(rep + 12);
        if (rep_opt != NBD_OPT_GO) _exit(1);
        if (rep_type != 3u /* NBD_REP_INFO */) _exit(1);
        uint64_t export_size = tp_get64be(rep + 22); /* 20 hdr + 2 info_type */
        if (export_size != (uint64_t)2000 * 512) _exit(1);

        /* Read NBD_REP_ACK (20 bytes) */
        uint8_t ack[20];
        if (tp_read_all(cfd, ack, 20) != 0) _exit(1);
        if (tp_get32be(ack + 12) != 1u /* NBD_REP_ACK */) _exit(1);

        /* Send DISC */
        uint8_t disc[28];
        memset(disc, 0, 28);
        tp_put32be(disc,     NBD_REQUEST_MAGIC);
        tp_put16be(disc + 6, (uint16_t)NBD_CMD_DISC);
        if (tp_write_all(cfd, disc, 28) != 0) _exit(1);

        close(cfd);
        _exit(0);
    }

    /* Parent: iSCSI mock target on sv[1] */
    uint32_t itt = mock_drain_cmd_get_itt(sv[1]);
    uint8_t cap_data[8] = {
        0x00, 0x00, 0x07, 0xCF, 0x00, 0x00, 0x02, 0x00,
    };
    mock_send_data_in(sv[1], itt, 0, cap_data, 8);

    pthread_join(tid, NULL);
    int child_status = 0;
    waitpid(pid, &child_status, 0);

    int failed = 0;
    if (arg.result != 0) { FAIL("nbd_serve returned non-zero"); failed = 1; }
    if (!failed && (!WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0)) {
        FAIL("NBD client child exited with error"); failed = 1;
    }

    free(conn); session_destroy(sess);
    close(sv[0]); close(sv[1]);
    if (!failed) PASS();
}

/* -----------------------------------------------------------------------
 * main
 * ----------------------------------------------------------------------- */

int main(void)
{
    printf("test_nbd\n");

    test_nbd_bind();
    test_handshake_disc();
    test_handshake_go();

    printf("\n%s: %d failure(s)\n", failures ? "FAIL" : "PASS", failures);
    return failures ? 1 : 0;
}
