/* CTC_SLIRP_TEST.C  Unit tests for CTCIS libslirp integration.
   Standalone: links only libslirp, no Hercules objects.             */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#if defined( __has_include )
#if __has_include(<slirp/libslirp.h>)
#include <slirp/libslirp.h>
#else
#include <libslirp.h>
#endif
#else
#include <libslirp.h>
#endif

/*-------------------------------------------------------------------*/
/* Test framework macros                                             */
/*-------------------------------------------------------------------*/

static int g_pass = 0;
static int g_fail = 0;

#define TEST_ASSERT( cond, msg ) \
    do { \
        if (!(cond)) { \
            fprintf( stderr, "  FAIL: %s (line %d): %s\n", \
                     __func__, __LINE__, (msg) ); \
            g_fail++; \
            return; \
        } \
    } while (0)

#define TEST_RUN( fn ) \
    do { \
        printf( "  %-40s", #fn ); \
        fflush( stdout ); \
        fn(); \
        printf( "ok\n" ); \
        g_pass++; \
    } while (0)

/*-------------------------------------------------------------------*/
/* Constants matching ctc_slirp.c                                    */
/*-------------------------------------------------------------------*/

#define ETH_HDR_SIZE  14
#define ETH_TYPE_IP   0x0800
#define ETH_TYPE_ARP  0x0806

static const uint8_t GUEST_MAC[6]   = { 0x52, 0x54, 0x00, 0x12, 0x34, 0x56 };
static const uint8_t GATEWAY_MAC[6] = { 0x52, 0x54, 0x00, 0x12, 0x34, 0x57 };

/*-------------------------------------------------------------------*/
/* Test 1: Poll event translation                                    */
/*                                                                   */
/* Verify SLIRP_POLL_* <-> POLL* mapping handles the value swap:     */
/*   SLIRP_POLL_OUT(2) -> POLLOUT(4), SLIRP_POLL_PRI(4) -> POLLPRI(2) */
/*-------------------------------------------------------------------*/

/* Replicate the mapping logic from ctc_slirp.c ctcis_add_poll */
static short slirp_to_poll( int events )
{
    short p = 0;
    if (events & SLIRP_POLL_IN)  p |= POLLIN;
    if (events & SLIRP_POLL_OUT) p |= POLLOUT;
    if (events & SLIRP_POLL_PRI) p |= POLLPRI;
    return p;
}

/* Replicate the mapping logic from ctc_slirp.c ctcis_get_revents */
static int poll_to_slirp( short revents )
{
    int s = 0;
    if (revents & POLLIN)  s |= SLIRP_POLL_IN;
    if (revents & POLLOUT) s |= SLIRP_POLL_OUT;
    if (revents & POLLPRI) s |= SLIRP_POLL_PRI;
    if (revents & POLLERR) s |= SLIRP_POLL_ERR;
    if (revents & POLLHUP) s |= SLIRP_POLL_HUP;
    return s;
}

static void test_poll_events( void )
{
    /* Verify the critical swaps */
    TEST_ASSERT( SLIRP_POLL_IN == 1,  "SLIRP_POLL_IN must be 1" );
    TEST_ASSERT( SLIRP_POLL_OUT == 2, "SLIRP_POLL_OUT must be 2" );
    TEST_ASSERT( SLIRP_POLL_PRI == 4, "SLIRP_POLL_PRI must be 4" );

    /* Forward: SLIRP_POLL_OUT(2) must map to POLLOUT(4), not POLLPRI(2) */
    TEST_ASSERT( slirp_to_poll( SLIRP_POLL_OUT ) == POLLOUT,
                 "SLIRP_POLL_OUT -> POLLOUT" );
    TEST_ASSERT( slirp_to_poll( SLIRP_POLL_PRI ) == POLLPRI,
                 "SLIRP_POLL_PRI -> POLLPRI" );
    TEST_ASSERT( slirp_to_poll( SLIRP_POLL_IN ) == POLLIN,
                 "SLIRP_POLL_IN -> POLLIN" );

    /* Combined flags */
    TEST_ASSERT( slirp_to_poll( SLIRP_POLL_IN | SLIRP_POLL_OUT ) ==
                 (POLLIN | POLLOUT), "IN|OUT combined forward" );

    /* Reverse: POLLOUT(4) must map to SLIRP_POLL_OUT(2) */
    TEST_ASSERT( poll_to_slirp( POLLOUT ) == SLIRP_POLL_OUT,
                 "POLLOUT -> SLIRP_POLL_OUT" );
    TEST_ASSERT( poll_to_slirp( POLLPRI ) == SLIRP_POLL_PRI,
                 "POLLPRI -> SLIRP_POLL_PRI" );
    TEST_ASSERT( poll_to_slirp( POLLIN ) == SLIRP_POLL_IN,
                 "POLLIN -> SLIRP_POLL_IN" );

    /* Round-trip: slirp -> poll -> slirp */
    int orig = SLIRP_POLL_IN | SLIRP_POLL_OUT | SLIRP_POLL_PRI;
    TEST_ASSERT( poll_to_slirp( slirp_to_poll( orig ) ) == orig,
                 "round-trip IN|OUT|PRI" );
}

/*-------------------------------------------------------------------*/
/* Test 2: Ethernet framing helpers                                  */
/*-------------------------------------------------------------------*/

/* Replicate ctcis_make_eth_from_ipv4 */
static int make_eth_from_ipv4( const uint8_t* ip, size_t iplen,
                               uint8_t* eth, size_t* ethlen )
{
    if (iplen < 20 || (ip[0] >> 4) != 4)
        return -1;

    int ihl = (ip[0] & 0x0f) * 4;
    if (ihl < 20 || (size_t)ihl > iplen)
        return -1;

    uint16_t total = ((uint16_t)ip[2] << 8) | ip[3];
    if (total < (uint16_t)ihl || total > iplen)
        return -1;

    if (*ethlen < iplen + ETH_HDR_SIZE)
        return -1;

    memcpy( eth, GATEWAY_MAC, 6 );
    memcpy( eth + 6, GUEST_MAC, 6 );
    eth[12] = 0x08;
    eth[13] = 0x00;
    memcpy( eth + ETH_HDR_SIZE, ip, iplen );
    *ethlen = iplen + ETH_HDR_SIZE;
    return 0;
}

/* Replicate ctcis_extract_ipv4_from_eth */
static int extract_ipv4_from_eth( const uint8_t* eth, size_t ethlen,
                                  const uint8_t** ip, size_t* iplen )
{
    if (ethlen < ETH_HDR_SIZE)
        return -1;

    uint16_t type = ((uint16_t)eth[12] << 8) | eth[13];
    if (type != ETH_TYPE_IP)
        return -1;

    *ip = eth + ETH_HDR_SIZE;
    *iplen = ethlen - ETH_HDR_SIZE;

    if (*iplen < 20 || ((*ip)[0] >> 4) != 4)
        return -1;

    return 0;
}

/* Build a minimal valid IPv4 header */
static void build_ip_packet( uint8_t* buf, size_t payload_len,
                             uint8_t proto,
                             const char* src, const char* dst )
{
    size_t total = 20 + payload_len;
    memset( buf, 0, total );
    buf[0] = 0x45;                              /* version=4, ihl=5 */
    buf[2] = (uint8_t)(total >> 8);
    buf[3] = (uint8_t)(total & 0xff);
    buf[8] = 64;                                /* TTL */
    buf[9] = proto;
    inet_pton( AF_INET, src, buf + 12 );
    inet_pton( AF_INET, dst, buf + 16 );
}

static void test_eth_framing( void )
{
    uint8_t ip[64];
    uint8_t eth[128];
    size_t ethlen;
    const uint8_t* extracted_ip;
    size_t extracted_len;

    /* Build a 40-byte IP packet (20 hdr + 20 payload) */
    build_ip_packet( ip, 20, 6, "10.0.2.15", "10.0.2.2" );

    /* Wrap IP -> Ethernet */
    ethlen = sizeof( eth );
    TEST_ASSERT( make_eth_from_ipv4( ip, 40, eth, &ethlen ) == 0,
                 "wrap IP to Ethernet" );
    TEST_ASSERT( ethlen == 40 + ETH_HDR_SIZE, "eth frame size correct" );
    TEST_ASSERT( eth[12] == 0x08 && eth[13] == 0x00, "EtherType is IPv4" );

    /* Unwrap Ethernet -> IP */
    TEST_ASSERT( extract_ipv4_from_eth( eth, ethlen, &extracted_ip,
                 &extracted_len ) == 0, "unwrap Ethernet to IP" );
    TEST_ASSERT( extracted_len == 40, "extracted IP length matches" );
    TEST_ASSERT( memcmp( extracted_ip, ip, 40 ) == 0,
                 "round-trip preserves IP packet" );

    /* Edge: runt packet (too short) */
    uint8_t runt[10] = {0};
    ethlen = sizeof( eth );
    TEST_ASSERT( make_eth_from_ipv4( runt, sizeof( runt ), eth, &ethlen ) == -1,
                 "reject runt packet" );

    /* Edge: non-IPv4 ethertype */
    uint8_t arp_frame[64];
    memset( arp_frame, 0, sizeof( arp_frame ) );
    arp_frame[12] = 0x08; arp_frame[13] = 0x06;  /* ARP */
    TEST_ASSERT( extract_ipv4_from_eth( arp_frame, sizeof( arp_frame ),
                 &extracted_ip, &extracted_len ) == -1,
                 "reject ARP ethertype" );

    /* Edge: buffer too small */
    ethlen = 10;
    TEST_ASSERT( make_eth_from_ipv4( ip, 40, eth, &ethlen ) == -1,
                 "reject when buffer too small" );
}

/*-------------------------------------------------------------------*/
/* Test 3: ARP proxy (libslirp integration)                          */
/*                                                                   */
/* Create a libslirp instance, add a hostfwd, run poll cycles.       */
/* Verify that when libslirp sends an ARP request for the guest,     */
/* our ARP proxy reply causes packets to flow.                       */
/*-------------------------------------------------------------------*/

typedef struct
{
    Slirp*          slirp;
    int             wakefd[2];
    uint8_t         pkt_buf[4096];  /* last packet from send_packet */
    size_t          pkt_len;
    int             pkt_count;      /* total packets received */
    int             arp_seen;       /* ARP requests seen */
    int             ipv4_seen;      /* IPv4 packets seen */
    struct in_addr  guest_addr;
} test_ctx_t;

static ssize_t test_send_packet( const void* pkt, size_t len, void* opaque )
{
    test_ctx_t* ctx = (test_ctx_t*)opaque;
    uint16_t etype;

    if (len > sizeof( ctx->pkt_buf ))
        len = sizeof( ctx->pkt_buf );
    memcpy( ctx->pkt_buf, pkt, len );
    ctx->pkt_len = len;
    ctx->pkt_count++;

    if (len >= ETH_HDR_SIZE)
    {
        etype = ((uint16_t)((const uint8_t*)pkt)[12] << 8) |
                ((const uint8_t*)pkt)[13];
        if (etype == ETH_TYPE_ARP)
            ctx->arp_seen++;
        else if (etype == ETH_TYPE_IP)
            ctx->ipv4_seen++;
    }
    return (ssize_t)len;
}

static void test_guest_error( const char* msg, void* opaque )
{
    (void)opaque;
    (void)msg;
}

static int64_t test_clock_get_ns( void* opaque )
{
    struct timeval tv;
    (void)opaque;
    gettimeofday( &tv, NULL );
    return ((int64_t)tv.tv_sec * 1000000000LL) + ((int64_t)tv.tv_usec * 1000);
}

typedef struct {
    SlirpTimerId id;
    void* opaque;
    int64_t expire_ms;
} test_timer_t;

static test_timer_t g_timers[8];
static int g_ntimers = 0;

static void* test_timer_new( SlirpTimerId id, void* cb_opaque, void* opaque )
{
    (void)opaque;
    if (g_ntimers >= 8) return NULL;
    test_timer_t* t = &g_timers[g_ntimers++];
    t->id = id;
    t->opaque = cb_opaque;
    t->expire_ms = -1;
    return t;
}

static void test_timer_free( void* timer, void* opaque )
{
    (void)timer;
    (void)opaque;
}

static void test_timer_mod( void* timer, int64_t expire_time, void* opaque )
{
    (void)opaque;
    test_timer_t* t = (test_timer_t*)timer;
    t->expire_ms = expire_time;
}

static void test_register_poll_fd( int fd, void* opaque )
{
    (void)fd; (void)opaque;
}

static void test_unregister_poll_fd( int fd, void* opaque )
{
    (void)fd; (void)opaque;
}

static void test_notify( void* opaque )
{
    (void)opaque;
}

/* Build an ARP reply for the guest IP (same as ctcis_handle_arp) */
static int build_arp_reply( const uint8_t* req, size_t reqlen,
                            uint8_t* reply, struct in_addr guest_addr )
{
    const uint8_t* arp;
    uint16_t op;

    if (reqlen < 42)
        return -1;

    arp = req + ETH_HDR_SIZE;
    if (arp[0] != 0 || arp[1] != 1 ||
        arp[2] != 0x08 || arp[3] != 0 ||
        arp[4] != 6 || arp[5] != 4)
        return -1;

    op = ((uint16_t)arp[6] << 8) | arp[7];
    if (op != 1) return -1;

    if (memcmp( arp + 24, &guest_addr.s_addr, 4 ) != 0)
        return -1;

    /* Ethernet header */
    memcpy( reply, req + 6, 6 );
    memcpy( reply + 6, GUEST_MAC, 6 );
    reply[12] = 0x08; reply[13] = 0x06;

    /* ARP payload */
    reply[14] = 0; reply[15] = 1;       /* HTYPE */
    reply[16] = 0x08; reply[17] = 0;    /* PTYPE */
    reply[18] = 6; reply[19] = 4;       /* HLEN, PLEN */
    reply[20] = 0; reply[21] = 2;       /* OPER = REPLY */
    memcpy( reply + 22, GUEST_MAC, 6 );
    memcpy( reply + 28, &guest_addr.s_addr, 4 );
    memcpy( reply + 32, arp + 8, 6 );
    memcpy( reply + 38, arp + 14, 4 );
    return 0;
}

#define MAX_POLLFD 128

typedef struct {
    struct pollfd fds[MAX_POLLFD];
    int nfds;
} poll_ctx_t;

static int test_add_poll( int fd, int events, void* opaque )
{
    poll_ctx_t* ctx = (poll_ctx_t*)opaque;
    if (ctx->nfds >= MAX_POLLFD) return -1;

    short pev = 0;
    if (events & SLIRP_POLL_IN)  pev |= POLLIN;
    if (events & SLIRP_POLL_OUT) pev |= POLLOUT;
    if (events & SLIRP_POLL_PRI) pev |= POLLPRI;

    ctx->fds[ctx->nfds].fd = fd;
    ctx->fds[ctx->nfds].events = pev;
    ctx->fds[ctx->nfds].revents = 0;
    return ctx->nfds++;
}

static int test_get_revents( int idx, void* opaque )
{
    poll_ctx_t* ctx = (poll_ctx_t*)opaque;
    if (idx < 0 || idx >= ctx->nfds) return 0;

    short r = ctx->fds[idx].revents;
    int s = 0;
    if (r & POLLIN)  s |= SLIRP_POLL_IN;
    if (r & POLLOUT) s |= SLIRP_POLL_OUT;
    if (r & POLLPRI) s |= SLIRP_POLL_PRI;
    if (r & POLLERR) s |= SLIRP_POLL_ERR;
    if (r & POLLHUP) s |= SLIRP_POLL_HUP;
    return s;
}

static SlirpCb test_cb = {
    .send_packet        = test_send_packet,
    .guest_error        = test_guest_error,
    .clock_get_ns       = test_clock_get_ns,
    .timer_new_opaque   = test_timer_new,
    .timer_free         = test_timer_free,
    .timer_mod          = test_timer_mod,
    .register_poll_fd   = test_register_poll_fd,
    .unregister_poll_fd = test_unregister_poll_fd,
    .notify             = test_notify
};

static Slirp* create_test_slirp( test_ctx_t* ctx )
{
    SlirpConfig cfg;
    memset( &cfg, 0, sizeof( cfg ) );
    cfg.version = 4;
    cfg.restricted = false;
    cfg.in_enabled = true;
    inet_pton( AF_INET, "10.0.2.0", &cfg.vnetwork );
    inet_pton( AF_INET, "255.255.255.0", &cfg.vnetmask );
    inet_pton( AF_INET, "10.0.2.2", &cfg.vhost );
    inet_pton( AF_INET, "10.0.2.3", &cfg.vnameserver );
    cfg.if_mtu = 1500;
    cfg.if_mru = 1500;

    inet_pton( AF_INET, "10.0.2.15", &ctx->guest_addr );
    ctx->pkt_count = 0;
    ctx->arp_seen = 0;
    ctx->ipv4_seen = 0;
    ctx->pkt_len = 0;
    g_ntimers = 0;

    return slirp_new( &cfg, &test_cb, ctx );
}

/* Run one poll cycle on libslirp */
static void run_poll_cycle( Slirp* slirp, int timeout_ms )
{
    poll_ctx_t pctx;
    uint32_t timeout = (uint32_t)timeout_ms;
    int rc;

    memset( &pctx, 0, sizeof( pctx ) );
    slirp_pollfds_fill( slirp, &timeout, test_add_poll, &pctx );

    if (timeout > (uint32_t)timeout_ms)
        timeout = (uint32_t)timeout_ms;

    rc = poll( pctx.fds, pctx.nfds, (int)timeout );

    slirp_pollfds_poll( slirp, rc < 0, test_get_revents, &pctx );

    /* Fire due timers */
    struct timeval tv;
    gettimeofday( &tv, NULL );
    int64_t now_ms = ((int64_t)tv.tv_sec * 1000) + (tv.tv_usec / 1000);
    for (int i = 0; i < g_ntimers; i++)
    {
        if (g_timers[i].expire_ms >= 0 && g_timers[i].expire_ms <= now_ms)
        {
            g_timers[i].expire_ms = -1;
            slirp_handle_timer( slirp, g_timers[i].id, g_timers[i].opaque );
        }
    }
}

static void test_arp_proxy( void )
{
    test_ctx_t ctx;
    uint8_t reply[42];
    int i;

    Slirp* slirp = create_test_slirp( &ctx );
    TEST_ASSERT( slirp != NULL, "slirp_new succeeded" );

    /* Add a port forward so libslirp has a reason to send to guest */
    struct in_addr host_bind, guest_fwd;
    inet_pton( AF_INET, "127.0.0.1", &host_bind );
    guest_fwd = ctx.guest_addr;
    int rc = slirp_add_hostfwd( slirp, 0, host_bind, 0, guest_fwd, 7777 );
    TEST_ASSERT( rc == 0, "slirp_add_hostfwd succeeded" );

    /* Run a few poll cycles -- libslirp should try to send ARP */
    for (i = 0; i < 5; i++)
        run_poll_cycle( slirp, 10 );

    /* Now try connecting to the forwarded port to trigger ARP */
    int sock = socket( AF_INET, SOCK_STREAM, 0 );
    TEST_ASSERT( sock >= 0, "socket() succeeded" );

    /* We need to connect to trigger libslirp to ARP for guest.
       Use a fresh hostfwd with a known ephemeral port. */
    slirp_cleanup( slirp );

    /* Recreate with ephemeral port we can discover */
    slirp = create_test_slirp( &ctx );
    TEST_ASSERT( slirp != NULL, "slirp_new #2 succeeded" );

    /* Use port 0 -- libslirp will pick an ephemeral port, but
       slirp_add_hostfwd doesn't tell us which. Use a fixed port. */
    int fwd_port = 19876;
    rc = slirp_add_hostfwd( slirp, 0, host_bind, fwd_port, guest_fwd, 7777 );
    if (rc != 0)
    {
        /* Port busy, try another */
        fwd_port = 19877;
        rc = slirp_add_hostfwd( slirp, 0, host_bind, fwd_port, guest_fwd, 7777 );
    }
    TEST_ASSERT( rc == 0, "hostfwd on fixed port" );

    /* Connect from host side -- this triggers libslirp to NAT and ARP */
    struct sockaddr_in sa;
    memset( &sa, 0, sizeof( sa ) );
    sa.sin_family = AF_INET;
    sa.sin_port = htons( fwd_port );
    inet_pton( AF_INET, "127.0.0.1", &sa.sin_addr );

    int csock = socket( AF_INET, SOCK_STREAM, 0 );
    TEST_ASSERT( csock >= 0, "connect socket" );
    fcntl( csock, F_SETFL, fcntl( csock, F_GETFL, 0 ) | O_NONBLOCK );
    connect( csock, (struct sockaddr*)&sa, sizeof( sa ) );
    /* Non-blocking connect may return -1/EINPROGRESS, that's fine */

    /* Run poll cycles -- libslirp should send ARP for 10.0.2.15 */
    ctx.arp_seen = 0;
    for (i = 0; i < 20; i++)
    {
        run_poll_cycle( slirp, 50 );
        if (ctx.arp_seen > 0)
            break;
    }

    TEST_ASSERT( ctx.arp_seen > 0, "libslirp sent ARP request" );

    /* Verify it's an ARP request for our guest IP */
    TEST_ASSERT( ctx.pkt_len >= 42, "ARP packet large enough" );
    uint16_t etype = ((uint16_t)ctx.pkt_buf[12] << 8) | ctx.pkt_buf[13];
    TEST_ASSERT( etype == ETH_TYPE_ARP, "packet is ARP" );

    /* Build ARP reply (as ctcis_handle_arp would) */
    rc = build_arp_reply( ctx.pkt_buf, ctx.pkt_len, reply, ctx.guest_addr );
    TEST_ASSERT( rc == 0, "built ARP reply" );

    /* Inject ARP reply into libslirp */
    slirp_input( slirp, reply, 42 );

    /* Run more cycles -- now libslirp should send an IPv4 packet (SYN) */
    ctx.ipv4_seen = 0;
    for (i = 0; i < 20; i++)
    {
        run_poll_cycle( slirp, 50 );
        if (ctx.ipv4_seen > 0)
            break;
    }

    TEST_ASSERT( ctx.ipv4_seen > 0,
                 "libslirp delivered IPv4 after ARP resolved" );

    close( csock );
    close( sock );
    slirp_cleanup( slirp );
}

/*-------------------------------------------------------------------*/
/* Test 4: Full TCP echo via libslirp                                */
/*                                                                   */
/* Simulates a z/OS guest by implementing a mini TCP stack on the    */
/* guest side of libslirp.  Host connects, sends "HELLO", guest      */
/* echoes it back.                                                   */
/*-------------------------------------------------------------------*/

/* IP/TCP checksum helper */
static uint16_t ip_checksum( const void* data, size_t len )
{
    const uint8_t* p = (const uint8_t*)data;
    uint32_t sum = 0;
    size_t i;
    for (i = 0; i + 1 < len; i += 2)
        sum += ((uint16_t)p[i] << 8) | p[i + 1];
    if (i < len)
        sum += (uint16_t)p[i] << 8;
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum & 0xffff);
}

static uint16_t tcp_checksum( const uint8_t* ip, const uint8_t* tcp,
                              size_t tcplen )
{
    uint32_t sum = 0;
    size_t i;

    /* Pseudo-header */
    sum += ((uint16_t)ip[12] << 8) | ip[13];  /* src ip hi */
    sum += ((uint16_t)ip[14] << 8) | ip[15];  /* src ip lo */
    sum += ((uint16_t)ip[16] << 8) | ip[17];  /* dst ip hi */
    sum += ((uint16_t)ip[18] << 8) | ip[19];  /* dst ip lo */
    sum += 6;                                   /* protocol TCP */
    sum += (uint16_t)tcplen;

    /* TCP segment */
    for (i = 0; i + 1 < tcplen; i += 2)
        sum += ((uint16_t)tcp[i] << 8) | tcp[i + 1];
    if (i < tcplen)
        sum += (uint16_t)tcp[i] << 8;

    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)(~sum & 0xffff);
}

/* Mini TCP responder state */
typedef enum {
    TCP_LISTEN,
    TCP_SYN_RCVD,
    TCP_ESTABLISHED,
    TCP_CLOSE_WAIT,
    TCP_CLOSED
} tcp_state_t;

typedef struct {
    tcp_state_t state;
    uint32_t    local_seq;
    uint32_t    remote_seq;
    uint16_t    local_port;
    uint16_t    remote_port;
    uint32_t    local_ip;
    uint32_t    remote_ip;
    uint8_t     echo_data[256];
    int         echo_len;
} mini_tcp_t;

/* Build and send a TCP response via libslirp */
static void tcp_send( Slirp* slirp, mini_tcp_t* tcp,
                      uint8_t flags, const uint8_t* data, size_t datalen )
{
    uint8_t pkt[1500];
    size_t iplen = 20 + 20 + datalen;  /* ip hdr + tcp hdr + data */
    size_t framelen = ETH_HDR_SIZE + iplen;
    uint8_t* ip;
    uint8_t* th;
    uint16_t cksum;

    if (framelen > sizeof( pkt ))
        return;

    /* Ethernet header */
    memcpy( pkt, GATEWAY_MAC, 6 );
    memcpy( pkt + 6, GUEST_MAC, 6 );
    pkt[12] = 0x08; pkt[13] = 0x00;

    /* IP header */
    ip = pkt + ETH_HDR_SIZE;
    memset( ip, 0, 20 );
    ip[0] = 0x45;
    ip[2] = (uint8_t)(iplen >> 8);
    ip[3] = (uint8_t)(iplen & 0xff);
    ip[8] = 64;    /* TTL */
    ip[9] = 6;     /* TCP */
    memcpy( ip + 12, &tcp->local_ip, 4 );
    memcpy( ip + 16, &tcp->remote_ip, 4 );
    /* IP checksum */
    cksum = ip_checksum( ip, 20 );
    ip[10] = (uint8_t)(cksum >> 8);
    ip[11] = (uint8_t)(cksum & 0xff);

    /* TCP header */
    th = ip + 20;
    memset( th, 0, 20 );
    th[0] = (uint8_t)(tcp->local_port >> 8);
    th[1] = (uint8_t)(tcp->local_port & 0xff);
    th[2] = (uint8_t)(tcp->remote_port >> 8);
    th[3] = (uint8_t)(tcp->remote_port & 0xff);
    /* seq */
    th[4] = (uint8_t)(tcp->local_seq >> 24);
    th[5] = (uint8_t)(tcp->local_seq >> 16);
    th[6] = (uint8_t)(tcp->local_seq >> 8);
    th[7] = (uint8_t)(tcp->local_seq);
    /* ack */
    th[8] = (uint8_t)(tcp->remote_seq >> 24);
    th[9] = (uint8_t)(tcp->remote_seq >> 16);
    th[10] = (uint8_t)(tcp->remote_seq >> 8);
    th[11] = (uint8_t)(tcp->remote_seq);
    th[12] = 0x50;   /* data offset = 5 words (20 bytes) */
    th[13] = flags;
    th[14] = 0x40; th[15] = 0x00;  /* window = 16384 */
    /* data */
    if (datalen > 0)
        memcpy( th + 20, data, datalen );
    /* TCP checksum */
    cksum = tcp_checksum( ip, th, 20 + datalen );
    th[16] = (uint8_t)(cksum >> 8);
    th[17] = (uint8_t)(cksum & 0xff);

    slirp_input( slirp, pkt, (int)framelen );
    tcp->local_seq += (uint32_t)datalen;
    if (flags & 0x02) tcp->local_seq++;  /* SYN consumes seq */
    if (flags & 0x01) tcp->local_seq++;  /* FIN consumes seq */
}

/* Process an incoming TCP packet from libslirp */
static void tcp_process( Slirp* slirp, mini_tcp_t* tcp,
                         const uint8_t* eth, size_t ethlen )
{
    const uint8_t* ip;
    const uint8_t* th;
    uint8_t flags;
    uint32_t seq;
    int ihl, thlen, datalen;
    uint16_t total;

    if (ethlen < ETH_HDR_SIZE + 40)
        return;

    ip = eth + ETH_HDR_SIZE;
    if ((ip[0] >> 4) != 4 || ip[9] != 6)
        return;

    ihl = (ip[0] & 0x0f) * 4;
    total = ((uint16_t)ip[2] << 8) | ip[3];
    th = ip + ihl;
    thlen = (th[12] >> 4) * 4;
    datalen = total - ihl - thlen;
    if (datalen < 0) datalen = 0;

    flags = th[13];
    seq = ((uint32_t)th[4] << 24) | ((uint32_t)th[5] << 16) |
          ((uint32_t)th[6] << 8) | th[7];

    /* Extract remote addressing from first packet */
    if (tcp->state == TCP_LISTEN)
    {
        memcpy( &tcp->remote_ip, ip + 12, 4 );
        memcpy( &tcp->local_ip, ip + 16, 4 );
        tcp->remote_port = ((uint16_t)th[0] << 8) | th[1];
        tcp->local_port = ((uint16_t)th[2] << 8) | th[3];
    }

    switch (tcp->state)
    {
    case TCP_LISTEN:
        if (flags & 0x02)  /* SYN */
        {
            tcp->remote_seq = seq + 1;
            /* SYN-ACK */
            tcp_send( slirp, tcp, 0x12, NULL, 0 );  /* SYN|ACK */
            tcp->state = TCP_SYN_RCVD;
        }
        break;

    case TCP_SYN_RCVD:
        if (flags & 0x10)  /* ACK */
        {
            tcp->state = TCP_ESTABLISHED;
            tcp->remote_seq = seq;
        }
        break;

    case TCP_ESTABLISHED:
        tcp->remote_seq = seq + (uint32_t)datalen;

        if (datalen > 0)
        {
            /* Echo data back */
            const uint8_t* payload = th + thlen;
            int echolen = datalen;
            if (echolen > (int)sizeof( tcp->echo_data ))
                echolen = (int)sizeof( tcp->echo_data );
            memcpy( tcp->echo_data, payload, echolen );
            tcp->echo_len = echolen;

            /* ACK + data echo */
            tcp_send( slirp, tcp, 0x18, tcp->echo_data, echolen );  /* PSH|ACK */
        }
        else if (flags & 0x10)
        {
            /* Pure ACK, acknowledge it */
        }

        if (flags & 0x01)  /* FIN */
        {
            tcp->remote_seq++;
            tcp_send( slirp, tcp, 0x11, NULL, 0 );  /* FIN|ACK */
            tcp->state = TCP_CLOSE_WAIT;
        }
        break;

    case TCP_CLOSE_WAIT:
        tcp->state = TCP_CLOSED;
        break;

    case TCP_CLOSED:
        break;
    }
}

/* Context for the TCP echo test */
typedef struct {
    Slirp*          slirp;
    mini_tcp_t      tcp;
    volatile int    running;
    uint8_t         queued_pkts[16][1600];
    size_t          queued_lens[16];
    volatile int    queue_head;
    volatile int    queue_tail;
    struct in_addr  guest_addr;
} echo_ctx_t;

static ssize_t echo_send_packet( const void* pkt, size_t len, void* opaque )
{
    echo_ctx_t* ctx = (echo_ctx_t*)opaque;
    uint16_t etype;
    int next;

    if (len < ETH_HDR_SIZE)
        return (ssize_t)len;

    etype = ((uint16_t)((const uint8_t*)pkt)[12] << 8) |
            ((const uint8_t*)pkt)[13];

    /* Handle ARP inline */
    if (etype == ETH_TYPE_ARP)
    {
        uint8_t reply[42];
        if (build_arp_reply( pkt, len, reply, ctx->guest_addr ) == 0)
        {
            /* Queue the ARP reply for injection in poll loop
               (can't call slirp_input from callback safely
                without recursive mutex) */
            next = (ctx->queue_tail + 1) % 16;
            if (next != ctx->queue_head)
            {
                memcpy( ctx->queued_pkts[ctx->queue_tail], reply, 42 );
                ctx->queued_lens[ctx->queue_tail] = 42;
                ctx->queue_tail = next;
            }
        }
        return (ssize_t)len;
    }

    /* Queue IPv4 packets for TCP processing */
    if (etype == ETH_TYPE_IP)
    {
        next = (ctx->queue_tail + 1) % 16;
        if (next != ctx->queue_head && len <= 1600)
        {
            memcpy( ctx->queued_pkts[ctx->queue_tail], pkt, len );
            ctx->queued_lens[ctx->queue_tail] = len;
            ctx->queue_tail = next;
        }
    }

    return (ssize_t)len;
}

static void echo_guest_error( const char* msg, void* opaque )
{
    (void)opaque; (void)msg;
}

static void echo_notify( void* opaque )
{
    (void)opaque;
}

static SlirpCb echo_cb = {
    .send_packet        = echo_send_packet,
    .guest_error        = echo_guest_error,
    .clock_get_ns       = test_clock_get_ns,
    .timer_new_opaque   = test_timer_new,
    .timer_free         = test_timer_free,
    .timer_mod          = test_timer_mod,
    .register_poll_fd   = test_register_poll_fd,
    .unregister_poll_fd = test_unregister_poll_fd,
    .notify             = echo_notify
};

static void* echo_guest_thread( void* arg )
{
    echo_ctx_t* ctx = (echo_ctx_t*)arg;
    poll_ctx_t pctx;
    uint32_t timeout;
    int rc;

    while (ctx->running)
    {
        memset( &pctx, 0, sizeof( pctx ) );
        timeout = 50;
        slirp_pollfds_fill( ctx->slirp, &timeout, test_add_poll, &pctx );
        if (timeout > 50) timeout = 50;

        rc = poll( pctx.fds, pctx.nfds, (int)timeout );
        slirp_pollfds_poll( ctx->slirp, rc < 0, test_get_revents, &pctx );

        /* Fire timers */
        struct timeval tv;
        gettimeofday( &tv, NULL );
        int64_t now_ms = ((int64_t)tv.tv_sec * 1000) + (tv.tv_usec / 1000);
        for (int i = 0; i < g_ntimers; i++)
        {
            if (g_timers[i].expire_ms >= 0 && g_timers[i].expire_ms <= now_ms)
            {
                g_timers[i].expire_ms = -1;
                slirp_handle_timer( ctx->slirp, g_timers[i].id,
                                    g_timers[i].opaque );
            }
        }

        /* Process queued packets */
        while (ctx->queue_head != ctx->queue_tail)
        {
            int idx = ctx->queue_head;
            uint8_t* pkt = ctx->queued_pkts[idx];
            size_t len = ctx->queued_lens[idx];
            ctx->queue_head = (idx + 1) % 16;

            uint16_t etype = ((uint16_t)pkt[12] << 8) | pkt[13];
            if (etype == ETH_TYPE_ARP)
            {
                /* Inject ARP reply */
                slirp_input( ctx->slirp, pkt, (int)len );
            }
            else if (etype == ETH_TYPE_IP)
            {
                tcp_process( ctx->slirp, &ctx->tcp, pkt, len );
            }
        }
    }
    return NULL;
}

static void test_tcp_echo( void )
{
    echo_ctx_t ctx;
    SlirpConfig cfg;
    struct in_addr host_bind;
    int fwd_port = 19878;
    int rc, i;
    pthread_t tid;

    memset( &ctx, 0, sizeof( ctx ) );
    inet_pton( AF_INET, "10.0.2.15", &ctx.guest_addr );

    g_ntimers = 0;

    memset( &cfg, 0, sizeof( cfg ) );
    cfg.version = 4;
    cfg.restricted = false;
    cfg.in_enabled = true;
    inet_pton( AF_INET, "10.0.2.0", &cfg.vnetwork );
    inet_pton( AF_INET, "255.255.255.0", &cfg.vnetmask );
    inet_pton( AF_INET, "10.0.2.2", &cfg.vhost );
    inet_pton( AF_INET, "10.0.2.3", &cfg.vnameserver );
    cfg.if_mtu = 1500;
    cfg.if_mru = 1500;

    ctx.slirp = slirp_new( &cfg, &echo_cb, &ctx );
    TEST_ASSERT( ctx.slirp != NULL, "slirp_new for echo test" );

    inet_pton( AF_INET, "127.0.0.1", &host_bind );

    /* Try a few ports in case one is busy */
    for (i = 0; i < 5; i++)
    {
        rc = slirp_add_hostfwd( ctx.slirp, 0, host_bind, fwd_port + i,
                                ctx.guest_addr, 8888 );
        if (rc == 0)
        {
            fwd_port = fwd_port + i;
            break;
        }
    }
    TEST_ASSERT( rc == 0, "hostfwd for echo test" );

    /* Init mini TCP responder */
    memset( &ctx.tcp, 0, sizeof( ctx.tcp ) );
    ctx.tcp.state = TCP_LISTEN;
    ctx.tcp.local_seq = 1000;
    inet_pton( AF_INET, "10.0.2.15", &ctx.tcp.local_ip );

    /* Start guest simulation thread */
    ctx.running = 1;
    rc = pthread_create( &tid, NULL, echo_guest_thread, &ctx );
    TEST_ASSERT( rc == 0, "guest thread created" );

    /* Give the guest thread a moment to start */
    usleep( 100000 );

    /* Connect from host side */
    int sock = socket( AF_INET, SOCK_STREAM, 0 );
    TEST_ASSERT( sock >= 0, "host socket" );

    struct sockaddr_in sa;
    memset( &sa, 0, sizeof( sa ) );
    sa.sin_family = AF_INET;
    sa.sin_port = htons( fwd_port );
    inet_pton( AF_INET, "127.0.0.1", &sa.sin_addr );

    /* Connect with timeout */
    struct timeval tv_timeout;
    tv_timeout.tv_sec = 5;
    tv_timeout.tv_usec = 0;

    rc = connect( sock, (struct sockaddr*)&sa, sizeof( sa ) );
    if (rc != 0 && errno != EINPROGRESS)
    {
        /* Retry with small delay -- guest thread needs to start ARP */
        usleep( 200000 );
        close( sock );
        sock = socket( AF_INET, SOCK_STREAM, 0 );
        rc = connect( sock, (struct sockaddr*)&sa, sizeof( sa ) );
    }
    TEST_ASSERT( rc == 0, "connect to forwarded port" );

    /* Set receive timeout */
    setsockopt( sock, SOL_SOCKET, SO_RCVTIMEO, &tv_timeout, sizeof( tv_timeout ) );

    /* Send test data */
    const char* msg = "HELLO";
    ssize_t sent = send( sock, msg, 5, 0 );
    TEST_ASSERT( sent == 5, "sent HELLO" );

    /* Read echoed data back */
    char rbuf[64];
    memset( rbuf, 0, sizeof( rbuf ) );
    ssize_t got = 0;
    for (i = 0; i < 50 && got < 5; i++)
    {
        ssize_t n = recv( sock, rbuf + got, sizeof( rbuf ) - got, 0 );
        if (n > 0)
            got += n;
        else if (n == 0)
            break;
        else if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            usleep( 100000 );
            continue;
        }
        else
            break;
    }

    TEST_ASSERT( got == 5, "received 5 bytes" );
    TEST_ASSERT( memcmp( rbuf, "HELLO", 5 ) == 0, "echoed data matches" );

    /* Clean shutdown */
    close( sock );
    ctx.running = 0;
    pthread_join( tid, NULL );
    slirp_cleanup( ctx.slirp );
}

/*-------------------------------------------------------------------*/
/* Main                                                              */
/*-------------------------------------------------------------------*/

int main( int argc, char* argv[] )
{
    (void)argc; (void)argv;

    printf( "ctc_slirp_test: running tests...\n" );

    TEST_RUN( test_poll_events );
    TEST_RUN( test_eth_framing );
    TEST_RUN( test_arp_proxy );
    TEST_RUN( test_tcp_echo );

    printf( "\n  %d passed, %d failed\n", g_pass, g_fail );
    return g_fail > 0 ? 1 : 0;
}
