/*
 * nbd.c - NBD (Network Block Device) server over iSCSI
 *
 * Protocol: NBD newstyle fixed handshake.
 *
 * Handshake phase:
 *   Server → Client: NBDMAGIC (8) + IHAVEOPT (8) + server_flags (2)
 *   Client → Server: client_flags (4)
 *   Option loop until export selected:
 *     Client → Server: IHAVEOPT (8) + opt_type (4) + opt_len (4) + opt_data
 *     Server → Client: reply(ies)
 *   Supported options: NBD_OPT_EXPORT_NAME, NBD_OPT_GO, NBD_OPT_INFO,
 *                      NBD_OPT_ABORT (others return NBD_REP_ERR_UNSUP)
 *
 * Transmission phase (simple requests):
 *   Client → Server: magic (4) + flags (2) + type (2) + handle (8) +
 *                    offset (8) + length (4) [+ data for WRITE]
 *   Server → Client: magic (4) + error (4) + handle (8) [+ data for READ]
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "nbd.h"
#include "scsi.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <syslog.h>
#include <unistd.h>

/* -----------------------------------------------------------------------
 * NBD protocol constants
 * ----------------------------------------------------------------------- */

#define NBD_MAGIC            UINT64_C(0x4e42444d41474943)  /* "NBDMAGIC" */
#define NBD_IHAVEOPT         UINT64_C(0x49484156454f5054)  /* "IHAVEOPT" */
#define NBD_REPLY_MAGIC      UINT64_C(0x0003e889045565a9)
#define NBD_REQUEST_MAGIC    UINT32_C(0x25609513)
#define NBD_RESPONSE_MAGIC   UINT32_C(0x67446698)

/* Server handshake flags */
#define NBD_FLAG_FIXED_NEWSTYLE   0x0001u
#define NBD_FLAG_NO_ZEROES        0x0002u

/* Client handshake flags */
#define NBD_FLAG_C_FIXED_NEWSTYLE 0x00000001u
#define NBD_FLAG_C_NO_ZEROES      0x00000002u

/* Option types */
#define NBD_OPT_EXPORT_NAME  1u
#define NBD_OPT_ABORT        2u
#define NBD_OPT_LIST         3u
#define NBD_OPT_INFO         6u
#define NBD_OPT_GO           7u

/* Reply types */
#define NBD_REP_ACK           UINT32_C(1)
#define NBD_REP_INFO          UINT32_C(3)
#define NBD_REP_ERR_UNSUP     UINT32_C(0x80000001)

/* Transmission flags (returned to client in export info) */
#define NBD_TX_FLAG_HAS_FLAGS   0x0001u
#define NBD_TX_FLAG_SEND_FLUSH  0x0004u

/* Command types */
#define NBD_CMD_READ    0u
#define NBD_CMD_WRITE   1u
#define NBD_CMD_DISC    2u
#define NBD_CMD_FLUSH   3u

/* NBD_INFO_EXPORT info type (used in NBD_REP_INFO for OPT_INFO/OPT_GO) */
#define NBD_INFO_EXPORT  0u

/* Maximum SCSI transfer size: READ(10)/WRITE(10) transfer length is 16-bit */
#define NBD_MAX_SCSI_BLOCKS  65535u

/* -----------------------------------------------------------------------
 * I/O helpers
 * ----------------------------------------------------------------------- */

static int write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n <= 0) return -1;
        p   += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

static int read_all(int fd, void *buf, size_t len)
{
    uint8_t *p = buf;
    while (len > 0) {
        ssize_t n = read(fd, p, len);
        if (n <= 0) return -1;
        p   += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

/* Big-endian serializers */
static void put64be(uint8_t *b, uint64_t v)
{
    b[0] = (uint8_t)(v >> 56); b[1] = (uint8_t)(v >> 48);
    b[2] = (uint8_t)(v >> 40); b[3] = (uint8_t)(v >> 32);
    b[4] = (uint8_t)(v >> 24); b[5] = (uint8_t)(v >> 16);
    b[6] = (uint8_t)(v >>  8); b[7] = (uint8_t)(v);
}

static void put32be(uint8_t *b, uint32_t v)
{
    b[0] = (uint8_t)(v >> 24); b[1] = (uint8_t)(v >> 16);
    b[2] = (uint8_t)(v >>  8); b[3] = (uint8_t)(v);
}

static void put16be(uint8_t *b, uint16_t v)
{
    b[0] = (uint8_t)(v >> 8); b[1] = (uint8_t)(v);
}

static uint64_t get64be(const uint8_t *b)
{
    return ((uint64_t)b[0] << 56) | ((uint64_t)b[1] << 48) |
           ((uint64_t)b[2] << 40) | ((uint64_t)b[3] << 32) |
           ((uint64_t)b[4] << 24) | ((uint64_t)b[5] << 16) |
           ((uint64_t)b[6] <<  8) |  (uint64_t)b[7];
}

static uint32_t get32be(const uint8_t *b)
{
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] <<  8) |  (uint32_t)b[3];
}

static uint16_t get16be(const uint8_t *b)
{
    return (uint16_t)(((uint16_t)b[0] << 8) | b[1]);
}

/* -----------------------------------------------------------------------
 * nbd_bind
 * ----------------------------------------------------------------------- */

int nbd_bind(int *port_out)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        syslog(LOG_ERR, "nbd: socket: %s", strerror(errno));
        return -1;
    }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = 0;                      /* OS picks port */
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK); /* 127.0.0.1 only */

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        syslog(LOG_ERR, "nbd: bind: %s", strerror(errno));
        close(fd);
        return -1;
    }
    if (listen(fd, 1) != 0) {
        syslog(LOG_ERR, "nbd: listen: %s", strerror(errno));
        close(fd);
        return -1;
    }

    socklen_t addrlen = sizeof(addr);
    getsockname(fd, (struct sockaddr *)&addr, &addrlen);
    *port_out = (int)ntohs(addr.sin_port);
    return fd;
}

/* -----------------------------------------------------------------------
 * Handshake helpers
 * ----------------------------------------------------------------------- */

/*
 * Send an option reply frame.
 * data/data_len: optional payload (may be NULL / 0).
 */
static int send_opt_reply(int fd, uint32_t opt, uint32_t reply_type,
                           const void *data, uint32_t data_len)
{
    uint8_t hdr[20];
    put64be(hdr,      NBD_REPLY_MAGIC);
    put32be(hdr +  8, opt);
    put32be(hdr + 12, reply_type);
    put32be(hdr + 16, data_len);
    if (write_all(fd, hdr, 20) != 0) return -1;
    if (data_len > 0 && data != NULL)
        if (write_all(fd, data, data_len) != 0) return -1;
    return 0;
}

/*
 * Send export information to the client.
 * Used by both NBD_OPT_EXPORT_NAME (inline, no reply framing) and
 * NBD_OPT_GO (via NBD_REP_INFO + NBD_REP_ACK).
 */
static int send_export_info_go(int fd, uint32_t opt, uint64_t export_size)
{
    /* NBD_REP_INFO with NBD_INFO_EXPORT payload (12 bytes) */
    uint8_t info[12];
    put16be(info,    NBD_INFO_EXPORT);
    put64be(info + 2, export_size);
    put16be(info + 10, (uint16_t)(NBD_TX_FLAG_HAS_FLAGS | NBD_TX_FLAG_SEND_FLUSH));
    if (send_opt_reply(fd, opt, NBD_REP_INFO, info, 12) != 0) return -1;
    return send_opt_reply(fd, opt, NBD_REP_ACK, NULL, 0);
}

/*
 * Drain len bytes from fd (discard data).
 * Returns 0 on success, -1 on I/O error.
 */
static int drain(int fd, uint32_t len)
{
    uint8_t buf[256];
    while (len > 0) {
        uint32_t chunk = (len < sizeof(buf)) ? len : (uint32_t)sizeof(buf);
        if (read_all(fd, buf, chunk) != 0) return -1;
        len -= chunk;
    }
    return 0;
}

/*
 * Perform the NBD newstyle fixed handshake.
 *
 * On success (entering transmission) returns 0.
 * On client abort or error returns -1.
 *
 * *no_zeroes_out is set to 1 if the client negotiated NBD_FLAG_C_NO_ZEROES
 * (used only for NBD_OPT_EXPORT_NAME padding, but tracked for completeness).
 */
static int do_handshake(int fd, uint64_t export_size, int *no_zeroes_out)
{
    /* ---- Send server greeting ---- */
    uint8_t greeting[18];
    put64be(greeting,      NBD_MAGIC);
    put64be(greeting +  8, NBD_IHAVEOPT);
    put16be(greeting + 16, (uint16_t)(NBD_FLAG_FIXED_NEWSTYLE | NBD_FLAG_NO_ZEROES));
    if (write_all(fd, greeting, 18) != 0) return -1;

    /* ---- Read client flags (4 bytes) ---- */
    uint8_t cflags[4];
    if (read_all(fd, cflags, 4) != 0) return -1;
    uint32_t client_flags = get32be(cflags);
    if (!(client_flags & NBD_FLAG_C_FIXED_NEWSTYLE)) {
        syslog(LOG_WARNING, "nbd: client did not negotiate FIXED_NEWSTYLE");
        return -1;
    }
    *no_zeroes_out = (client_flags & NBD_FLAG_C_NO_ZEROES) ? 1 : 0;

    /* ---- Option negotiation loop ---- */
    for (;;) {
        uint8_t oph[16];
        if (read_all(fd, oph, 16) != 0) return -1;

        uint64_t magic  = get64be(oph);
        uint32_t opt    = get32be(oph + 8);
        uint32_t optlen = get32be(oph + 12);

        if (magic != NBD_IHAVEOPT) {
            syslog(LOG_ERR, "nbd: bad option magic 0x%016llx",
                   (unsigned long long)magic);
            return -1;
        }
        /* Sanity-limit option data to prevent large allocations */
        if (optlen > 64u * 1024u) {
            syslog(LOG_WARNING, "nbd: option %u data too large (%u bytes), aborting",
                   opt, optlen);
            return -1;
        }

        /* Read option data (up to 256 bytes; drain any excess) */
        uint8_t optdata[256];
        uint32_t to_read = (optlen < sizeof(optdata)) ? optlen
                                                       : (uint32_t)sizeof(optdata);
        if (to_read > 0 && read_all(fd, optdata, to_read) != 0) return -1;
        if (drain(fd, optlen - to_read) != 0) return -1;

        switch (opt) {
        case NBD_OPT_EXPORT_NAME: {
            /*
             * Old-style option: no reply frame.  Server sends export size
             * (8 bytes) + transmission flags (2 bytes) + optional 124 zero
             * bytes (omitted when both sides negotiate NBD_FLAG_NO_ZEROES).
             */
            uint8_t resp[134];
            put64be(resp,    export_size);
            put16be(resp + 8, (uint16_t)(NBD_TX_FLAG_HAS_FLAGS |
                                          NBD_TX_FLAG_SEND_FLUSH));
            size_t resp_len = 10;
            if (!(*no_zeroes_out)) {
                memset(resp + 10, 0, 124);
                resp_len = 134;
            }
            return write_all(fd, resp, resp_len);  /* 0 on success */
        }

        case NBD_OPT_GO:
            /* New-style: NBD_REP_INFO(s) + NBD_REP_ACK, then transmission. */
            if (send_export_info_go(fd, opt, export_size) != 0) return -1;
            return 0;

        case NBD_OPT_INFO:
            /* Like GO but does NOT start transmission; loop continues. */
            if (send_export_info_go(fd, opt, export_size) != 0) return -1;
            break;

        case NBD_OPT_ABORT:
            (void)send_opt_reply(fd, opt, NBD_REP_ACK, NULL, 0);
            return -1;

        default:
            /* Unsupported option: reply with NBD_REP_ERR_UNSUP and continue. */
            if (send_opt_reply(fd, opt, NBD_REP_ERR_UNSUP, NULL, 0) != 0)
                return -1;
            break;
        }
    }
}

/* -----------------------------------------------------------------------
 * Transmission reply helper
 * ----------------------------------------------------------------------- */

static int send_reply(int fd, uint32_t error, const uint8_t handle[8],
                       const void *data, uint32_t data_len)
{
    uint8_t hdr[16];
    put32be(hdr,     NBD_RESPONSE_MAGIC);
    put32be(hdr + 4, error);
    memcpy(hdr + 8, handle, 8);
    if (write_all(fd, hdr, 16) != 0) return -1;
    if (data_len > 0 && data != NULL)
        if (write_all(fd, data, data_len) != 0) return -1;
    return 0;
}

/* -----------------------------------------------------------------------
 * Transmission loop
 * ----------------------------------------------------------------------- */

/*
 * do_transmission — serve NBD requests until DISC or error.
 *
 * Large requests (more blocks than NBD_MAX_SCSI_BLOCKS) are split into
 * multiple SCSI READ(10)/WRITE(10) commands automatically.
 *
 * Returns 0 on clean DISC, -1 on I/O or protocol error.
 */
static int do_transmission(int fd,
                             iscsi_session_t *sess, iscsi_conn_t *conn,
                             const uint8_t lun_raw[8],
                             uint32_t num_blocks, uint32_t block_size)
{
    /* Maximum read/write size: 128 MB per NBD request (sanity limit) */
    const uint32_t max_nbd_bytes = 128u * 1024u * 1024u;

    for (;;) {
        /* Read 28-byte NBD simple request header */
        uint8_t req[28];
        if (read_all(fd, req, 28) != 0) return 0;  /* peer closed */

        uint32_t magic = get32be(req);
        if (magic != NBD_REQUEST_MAGIC) {
            syslog(LOG_ERR, "nbd: bad request magic 0x%08x", magic);
            return -1;
        }

        /* req[4..5] = flags (NBD_CMD_FLAG_FUA etc.) — unused for now */
        uint16_t type   = get16be(req + 6);
        uint8_t  handle[8];
        memcpy(handle, req + 8, 8);
        uint64_t offset = get64be(req + 16);
        uint32_t length = get32be(req + 24);

        switch ((unsigned)type) {

        /* ---- NBD_CMD_READ ---- */
        case NBD_CMD_READ: {
            /* Validate alignment and bounds */
            if (length == 0 || block_size == 0 ||
                (offset % block_size) != 0 || (length % block_size) != 0 ||
                length > max_nbd_bytes) {
                if (send_reply(fd, EINVAL, handle, NULL, 0) != 0) return -1;
                break;
            }
            uint32_t lba_start = (uint32_t)(offset / block_size);
            uint32_t nblocks   = length / block_size;
            if ((uint64_t)lba_start + nblocks > num_blocks) {
                if (send_reply(fd, EINVAL, handle, NULL, 0) != 0) return -1;
                break;
            }

            uint8_t *buf = malloc(length);
            if (!buf) {
                if (send_reply(fd, ENOMEM, handle, NULL, 0) != 0) return -1;
                break;
            }

            /* Issue SCSI READ(10) in chunks of at most NBD_MAX_SCSI_BLOCKS */
            int err = 0;
            uint32_t done = 0;
            while (done < nblocks) {
                uint32_t chunk = nblocks - done;
                if (chunk > NBD_MAX_SCSI_BLOCKS) chunk = NBD_MAX_SCSI_BLOCKS;
                if (scsi_read10(sess, conn, lun_raw,
                                lba_start + done, (uint16_t)chunk, block_size,
                                buf + (size_t)done * block_size) != 0) {
                    err = EIO;
                    break;
                }
                done += chunk;
            }

            if (err) {
                free(buf);
                if (send_reply(fd, (uint32_t)err, handle, NULL, 0) != 0)
                    return -1;
            } else {
                int rc = send_reply(fd, 0, handle, buf, length);
                free(buf);
                if (rc != 0) return -1;
            }
            break;
        }

        /* ---- NBD_CMD_WRITE ---- */
        case NBD_CMD_WRITE: {
            if (length == 0 || block_size == 0 ||
                (offset % block_size) != 0 || (length % block_size) != 0 ||
                length > max_nbd_bytes) {
                /* Drain the write data before replying with error */
                if (drain(fd, length) != 0) return -1;
                if (send_reply(fd, EINVAL, handle, NULL, 0) != 0) return -1;
                break;
            }
            uint32_t lba_start = (uint32_t)(offset / block_size);
            uint32_t nblocks   = length / block_size;
            if ((uint64_t)lba_start + nblocks > num_blocks) {
                if (drain(fd, length) != 0) return -1;
                if (send_reply(fd, EINVAL, handle, NULL, 0) != 0) return -1;
                break;
            }

            uint8_t *buf = malloc(length);
            if (!buf) {
                if (drain(fd, length) != 0) return -1;
                if (send_reply(fd, ENOMEM, handle, NULL, 0) != 0) return -1;
                break;
            }
            if (read_all(fd, buf, length) != 0) {
                free(buf);
                return -1;
            }

            int err = 0;
            uint32_t done = 0;
            while (done < nblocks) {
                uint32_t chunk = nblocks - done;
                if (chunk > NBD_MAX_SCSI_BLOCKS) chunk = NBD_MAX_SCSI_BLOCKS;
                if (scsi_write10(sess, conn, lun_raw,
                                 lba_start + done, (uint16_t)chunk, block_size,
                                 buf + (size_t)done * block_size) != 0) {
                    err = EIO;
                    break;
                }
                done += chunk;
            }
            free(buf);
            if (send_reply(fd, err ? (uint32_t)err : 0u, handle, NULL, 0) != 0)
                return -1;
            break;
        }

        /* ---- NBD_CMD_FLUSH ---- */
        case NBD_CMD_FLUSH: {
            /*
             * Issue SYNCHRONIZE CACHE(10) to flush the target's write cache
             * to stable storage (SBC-4 §5.24).  IMMED=0 means the target
             * waits until the cache is fully flushed before sending the SCSI
             * Response, giving us a reliable durability guarantee.
             */
            uint32_t err = 0;
            if (scsi_sync_cache10(sess, conn, lun_raw) != 0) {
                syslog(LOG_WARNING, "nbd: SYNCHRONIZE CACHE(10) failed");
                err = (uint32_t)EIO;
            }
            if (send_reply(fd, err, handle, NULL, 0) != 0) return -1;
            break;
        }

        /* ---- NBD_CMD_DISC ---- */
        case NBD_CMD_DISC:
            return 0;  /* clean disconnect */

        default:
            if (send_reply(fd, EINVAL, handle, NULL, 0) != 0) return -1;
            break;
        }
    }
}

/* -----------------------------------------------------------------------
 * nbd_serve — public entry point
 * ----------------------------------------------------------------------- */

int nbd_serve(iscsi_session_t *sess, iscsi_conn_t *conn,
              const uint8_t lun_raw[8], int listen_fd)
{
    /*
     * Fetch LUN geometry before accepting the NBD client.  This validates
     * that the LUN is accessible and gives us the export size for the
     * NBD handshake.
     */
    uint32_t num_blocks = 0, block_size = 0;
    if (scsi_read_capacity10(sess, conn, lun_raw, &num_blocks, &block_size) != 0) {
        syslog(LOG_ERR, "nbd: READ CAPACITY(10) failed; cannot serve LUN");
        close(listen_fd);
        return -1;
    }
    if (block_size == 0) {
        syslog(LOG_ERR, "nbd: target reported zero block size");
        close(listen_fd);
        return -1;
    }

    uint64_t export_size = (uint64_t)num_blocks * block_size;
    syslog(LOG_INFO, "nbd: serving LUN — %u blocks x %u bytes = %llu bytes",
           num_blocks, block_size, (unsigned long long)export_size);

    /* Set a 60-second timeout so the server doesn't hang indefinitely
     * if the NBD client never connects. */
    struct timeval tv = {.tv_sec = 60, .tv_usec = 0};
    setsockopt(listen_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Accept exactly one NBD client. */
    struct sockaddr_in client_addr;
    memset(&client_addr, 0, sizeof(client_addr));
    socklen_t addrlen = sizeof(client_addr);
    int client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &addrlen);
    close(listen_fd);   /* no longer needed regardless of outcome */
    if (client_fd < 0) {
        syslog(LOG_ERR, "nbd: accept failed: %s", strerror(errno));
        return -1;
    }

    syslog(LOG_INFO, "nbd: client connected from %s",
           inet_ntoa(client_addr.sin_addr));

    int no_zeroes = 0;
    if (do_handshake(client_fd, export_size, &no_zeroes) != 0) {
        syslog(LOG_ERR, "nbd: handshake failed");
        close(client_fd);
        return -1;
    }

    int rc = do_transmission(client_fd, sess, conn, lun_raw,
                              num_blocks, block_size);
    close(client_fd);
    syslog(LOG_INFO, "nbd: client disconnected (rc=%d)", rc);
    return rc;
}
