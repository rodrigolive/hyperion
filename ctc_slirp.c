/* CTC_SLIRP.C  Userspace NAT CTCI support via libslirp              */

#include "hstdinc.h"

#if defined( OPTION_SLIRP )

#include "hercules.h"
#include "ctcadpt.h"
#include "tuntap.h"
#include "opcode.h"
#include "herc_getopt.h"

#if defined( HAVE_SLIRP_LIBSLIRP_H )
#include <slirp/libslirp.h>
#else
#include <libslirp.h>
#endif

#define CTCIS_DEVICES_IN_GROUP  2
#define CTCIS_MAX_FWD           32
#define CTCIS_MAX_POLLFD        128
#define CTCIS_ETH_HDR_SIZE      14
#define CTCIS_TIMER_CANCELLED   ((int64_t)-1)

typedef struct _CTCISFWD CTCISFWD;
typedef struct _CTCISTIMER CTCISTIMER;
typedef struct _CTCISBLK CTCISBLK, *PCTCISBLK;

struct _CTCISFWD
{
    int             is_udp;
    struct in_addr  host_addr;
    struct in_addr  guest_addr;
    int             host_port;
    int             guest_port;
};

struct _CTCISTIMER
{
    PCTCISBLK       blk;
    SlirpTimerId    id;
    void*           opaque;
    int64_t         expire_ms;
    CTCISTIMER*     next;
};

struct _CTCISBLK
{
    DEVBLK*         pDEVBLK[2];
    TID             tid;
    pid_t           pid;
    int             wakefd[2];

    U16             iMaxFrameBufferSize;
    BYTE            bFrameBuffer[CTC_DEF_FRAME_BUFFER_SIZE];
    U16             iFrameOffset;
    U16             sMTU;

    LOCK            Lock;
    LOCK            EventLock;
    COND            Event;
    LOCK            SlirpLock;

    u_int           fDebug:1;
    u_int           fDataPending:1;
    u_int           fCloseInProgress:1;
    u_int           fReadWaiting:1;
    u_int           fHaltOrClear:1;

    Slirp*          slirp;
    CTCISTIMER*     timers;

    struct in_addr  net_addr;
    struct in_addr  netmask;
    struct in_addr  guest_addr;
    struct in_addr  gateway_addr;
    struct in_addr  dns_addr;
    struct in_addr  bind_addr;

    MAC             guest_mac;
    MAC             gateway_mac;

    CTCISFWD        fwd[CTCIS_MAX_FWD];
    int             fwd_count;
};

typedef struct _CTCISPOLLCTX
{
    struct pollfd   fds[CTCIS_MAX_POLLFD];
    int             nfds;
} CTCISPOLLCTX;

static BYTE CTCIS_Immed_Commands[256]=
{ 0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,
  0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

static void* CTCIS_ReadThread( void* arg );
static void  CTCIS_Read( DEVBLK* dev, U32 count, BYTE* buf, BYTE* unitstat,
                         U32* residual, BYTE* more );
static void  CTCIS_Write( DEVBLK* dev, U32 count, BYTE* buf, BYTE* unitstat,
                          U32* residual );
static void  ctcis_halt_or_clear( DEVBLK* dev );
static int   ctcis_parse_args( DEVBLK* dev, PCTCISBLK blk, int argc, char** argv );
static int   ctcis_enqueue_ip_packet( PCTCISBLK blk, const BYTE* data, size_t size );
static int   ctcis_make_eth_from_ipv4( PCTCISBLK blk, const BYTE* ip, size_t iplen,
                                       BYTE* eth, size_t* ethlen );
static int   ctcis_extract_ipv4_from_eth( PCTCISBLK blk, const BYTE* eth, size_t ethlen,
                                         const BYTE** ip, size_t* iplen );

DEVHND ctcis_device_hndinfo =
{
        &CTCIS_Init,
        &CTCIS_ExecuteCCW,
        &CTCIS_Close,
        &CTCIS_Query,
        NULL, NULL, NULL, NULL, NULL,
        &ctcis_halt_or_clear,
        NULL, NULL, NULL, NULL, NULL, NULL,
        CTCIS_Immed_Commands,
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

static int64_t ctcis_now_ms( void )
{
    struct timeval tv;
    gettimeofday( &tv, NULL );
    return ((int64_t)tv.tv_sec * 1000) + (tv.tv_usec / 1000);
}

static int64_t ctcis_clock_get_ns( void* opaque )
{
    UNREFERENCED( opaque );
    return ctcis_now_ms() * 1000000;
}

static void* ctcis_timer_new( SlirpTimerId id, void* cb_opaque, void* opaque )
{
    PCTCISBLK blk = (PCTCISBLK) opaque;
    CTCISTIMER* timer = malloc( sizeof( CTCISTIMER ) );

    if (!timer)
        return NULL;

    memset( timer, 0, sizeof( CTCISTIMER ) );
    timer->blk = blk;
    timer->id = id;
    timer->opaque = cb_opaque;
    timer->expire_ms = CTCIS_TIMER_CANCELLED;

    obtain_lock( &blk->SlirpLock );
    timer->next = blk->timers;
    blk->timers = timer;
    release_lock( &blk->SlirpLock );

    return timer;
}

static void ctcis_timer_free( void* timer, void* opaque )
{
    PCTCISBLK blk = (PCTCISBLK) opaque;
    CTCISTIMER* cur;
    CTCISTIMER* prev = NULL;

    obtain_lock( &blk->SlirpLock );
    for (cur = blk->timers; cur; prev = cur, cur = cur->next)
    {
        if (cur == (CTCISTIMER*)timer)
        {
            if (prev)
                prev->next = cur->next;
            else
                blk->timers = cur->next;
            free( cur );
            break;
        }
    }
    release_lock( &blk->SlirpLock );
}

static void ctcis_timer_mod( void* timer, int64_t expire_time, void* opaque )
{
    PCTCISBLK blk = (PCTCISBLK) opaque;
    CTCISTIMER* t = (CTCISTIMER*) timer;
    UNREFERENCED( blk );
    t->expire_ms = expire_time;
}

static void ctcis_timer_fire_due( PCTCISBLK blk )
{
    CTCISTIMER* t;
    int64_t now = ctcis_now_ms();

    for (t = blk->timers; t; t = t->next)
    {
        if (t->expire_ms != CTCIS_TIMER_CANCELLED && t->expire_ms <= now)
        {
            t->expire_ms = CTCIS_TIMER_CANCELLED;
            slirp_handle_timer( blk->slirp, t->id, t->opaque );
        }
    }
}

static int ctcis_timer_timeout( PCTCISBLK blk )
{
    CTCISTIMER* t;
    int64_t now = ctcis_now_ms();
    int64_t nearest = -1;

    for (t = blk->timers; t; t = t->next)
        if (t->expire_ms != CTCIS_TIMER_CANCELLED &&
            (nearest < 0 || t->expire_ms < nearest))
            nearest = t->expire_ms;

    if (nearest < 0)
        return 1000;

    if (nearest <= now)
        return 0;

    return (int)(nearest - now);
}

static int ctcis_add_poll( int fd, int events, void* opaque )
{
    CTCISPOLLCTX* ctx = (CTCISPOLLCTX*) opaque;

    if (ctx->nfds >= CTCIS_MAX_POLLFD)
        return -1;

    ctx->fds[ctx->nfds].fd = fd;
    ctx->fds[ctx->nfds].events = events;
    ctx->fds[ctx->nfds].revents = 0;
    return ctx->nfds++;
}

static int ctcis_get_revents( int idx, void* opaque )
{
    CTCISPOLLCTX* ctx = (CTCISPOLLCTX*) opaque;

    if (idx < 0 || idx >= ctx->nfds)
        return 0;

    return ctx->fds[idx].revents;
}

static void ctcis_notify( void* opaque )
{
    PCTCISBLK blk = (PCTCISBLK) opaque;
    BYTE b = 0;

    if (blk->wakefd[1] >= 0)
        write_pipe( blk->wakefd[1], &b, 1 );
}

static void ctcis_guest_error( const char* msg, void* opaque )
{
    PCTCISBLK blk = (PCTCISBLK) opaque;
    DEVBLK* dev = blk->pDEVBLK[CTC_READ_SUBCHANN];

    WRMSG( HHC00991, "W", SSID_TO_LCSS( dev->ssid ), dev->devnum,
           dev->typname, msg ? msg : "unknown" );
}

static ssize_t ctcis_send_packet( const void* pkt, size_t pkt_len, void* opaque )
{
    PCTCISBLK blk = (PCTCISBLK) opaque;
    DEVBLK* dev = blk->pDEVBLK[CTC_READ_SUBCHANN];
    const BYTE* ip = NULL;
    size_t iplen = 0;

    if (blk->fCloseInProgress)
        return -1;

    if (ctcis_extract_ipv4_from_eth( blk, pkt, pkt_len, &ip, &iplen ) != 0)
        return (ssize_t)pkt_len;

    if (blk->fDebug)
    {
        WRMSG( HHC00913, "D", SSID_TO_LCSS( dev->ssid ), dev->devnum,
               dev->typname, "", (int)iplen, "libslirp" );
        net_data_trace( dev, (BYTE*)ip, (int)iplen, '>', 'D', "packet", 0 );
    }

    if (ctcis_enqueue_ip_packet( blk, ip, iplen ) != 0)
    {
        if (errno == EMSGSIZE)
            WRMSG( HHC00914, "W", SSID_TO_LCSS( dev->ssid ), dev->devnum );
        return -1;
    }

    return (ssize_t)pkt_len;
}

/* No-op stubs for libslirp register/unregister callbacks.
   Required by libslirp >= 4.8 which unconditionally calls these
   when setting up host-forwarded listening sockets.  CTCIS uses its
   own poll loop so the stubs are intentionally empty.               */
static void ctcis_register_poll_fd( int fd, void* opaque )
{
    UNREFERENCED( fd );
    UNREFERENCED( opaque );
}

static void ctcis_unregister_poll_fd( int fd, void* opaque )
{
    UNREFERENCED( fd );
    UNREFERENCED( opaque );
}

static SlirpCb ctcis_slirp_cb =
{
    .send_packet = ctcis_send_packet,
    .guest_error = ctcis_guest_error,
    .clock_get_ns = ctcis_clock_get_ns,
    .timer_new_opaque = ctcis_timer_new,
    .timer_free = ctcis_timer_free,
    .timer_mod = ctcis_timer_mod,
    .register_poll_fd = ctcis_register_poll_fd,
    .unregister_poll_fd = ctcis_unregister_poll_fd,
    .notify = ctcis_notify
};

static int ctcis_ipv4_ok( const BYTE* ip, size_t len )
{
    U16 total;
    int ihl;

    if (len < 20 || (ip[0] >> 4) != 4)
        return 0;

    ihl = (ip[0] & 0x0f) * 4;
    if (ihl < 20 || (size_t)ihl > len)
        return 0;

    total = ((U16)ip[2] << 8) | ip[3];
    return total >= ihl && total <= len;
}

static int ctcis_make_eth_from_ipv4( PCTCISBLK blk, const BYTE* ip, size_t iplen,
                                     BYTE* eth, size_t* ethlen )
{
    if (!ctcis_ipv4_ok( ip, iplen ) || *ethlen < iplen + CTCIS_ETH_HDR_SIZE)
        return -1;

    memcpy( eth, blk->gateway_mac, IFHWADDRLEN );
    memcpy( eth + IFHWADDRLEN, blk->guest_mac, IFHWADDRLEN );
    eth[12] = 0x08;
    eth[13] = 0x00;
    memcpy( eth + CTCIS_ETH_HDR_SIZE, ip, iplen );
    *ethlen = iplen + CTCIS_ETH_HDR_SIZE;
    return 0;
}

static int ctcis_extract_ipv4_from_eth( PCTCISBLK blk, const BYTE* eth, size_t ethlen,
                                        const BYTE** ip, size_t* iplen )
{
    DEVBLK* dev = blk->pDEVBLK[CTC_READ_SUBCHANN];
    U16 type;

    if (ethlen < CTCIS_ETH_HDR_SIZE)
    {
        if (blk->fDebug)
            WRMSG( HHC00990, "D", SSID_TO_LCSS( dev->ssid ), dev->devnum,
                   dev->typname, "short ethernet", (unsigned)ethlen );
        return -1;
    }

    type = ((U16)eth[12] << 8) | eth[13];
    if (type != ETH_TYPE_IP)
    {
        if (blk->fDebug)
            WRMSG( HHC00990, "D", SSID_TO_LCSS( dev->ssid ), dev->devnum,
                   dev->typname, type == ETH_TYPE_IPV6 ? "IPv6" :
                   type == ETH_TYPE_ARP ? "ARP" : "non-IPv4", (unsigned)ethlen );
        return -1;
    }

    *ip = eth + CTCIS_ETH_HDR_SIZE;
    *iplen = ethlen - CTCIS_ETH_HDR_SIZE;

    if (!ctcis_ipv4_ok( *ip, *iplen ) || *iplen > 9000)
    {
        if (blk->fDebug)
            WRMSG( HHC00990, "D", SSID_TO_LCSS( dev->ssid ), dev->devnum,
                   dev->typname, "malformed IPv4", (unsigned)*iplen );
        return -1;
    }

    return 0;
}

static int ctcis_enqueue_ip_packet( PCTCISBLK blk, const BYTE* data, size_t size )
{
    PCTCIHDR frame;
    PCTCISEG segment;

    if (size > (blk->iMaxFrameBufferSize - sizeof( CTCIHDR ) - sizeof( CTCISEG ) -
                sizeof_member( CTCIHDR, hwOffset )) || size > 9000)
    {
        errno = EMSGSIZE;
        return -1;
    }

    obtain_lock( &blk->Lock );

    if ((blk->iFrameOffset + sizeof( CTCIHDR ) + sizeof( CTCISEG ) + size +
         sizeof( frame->hwOffset )) > blk->iMaxFrameBufferSize)
    {
        release_lock( &blk->Lock );
        errno = ENOBUFS;
        return -1;
    }

    frame = (PCTCIHDR)blk->bFrameBuffer;
    segment = (PCTCISEG)(blk->bFrameBuffer + sizeof( CTCIHDR ) + blk->iFrameOffset);
    memset( segment, 0, sizeof( CTCISEG ) + size );

    blk->iFrameOffset += (U16)(sizeof( CTCISEG ) + size);
    STORE_HW( frame->hwOffset, blk->iFrameOffset + sizeof( CTCIHDR ) );
    STORE_HW( segment->hwLength, (U16)(sizeof( CTCISEG ) + size) );
    STORE_HW( segment->hwType, ETH_TYPE_IP );
    memcpy( segment->bData, data, size );
    blk->fDataPending = 1;

    release_lock( &blk->Lock );

    obtain_lock( &blk->EventLock );
    signal_condition( &blk->Event );
    release_lock( &blk->EventLock );

    return 0;
}

int CTCIS_Init( DEVBLK* dev, int argc, char *argv[] )
{
    CTCISBLK work;
    PCTCISBLK blk;
    SlirpConfig cfg;
    int i, rc;
    char thread_name[32];

    dev->devtype = 0x3088;
    dev->excps = 0;

    if (!group_device( dev, CTCIS_DEVICES_IN_GROUP ))
        return 0;

    memset( &work, 0, sizeof( work ) );
    work.wakefd[0] = work.wakefd[1] = -1;
    work.sMTU = 1500;
    work.iMaxFrameBufferSize = sizeof( work.bFrameBuffer );
    work.guest_mac[0] = 0x52; work.guest_mac[1] = 0x54; work.guest_mac[2] = 0x00;
    work.guest_mac[3] = 0x12; work.guest_mac[4] = 0x34; work.guest_mac[5] = 0x56;
    work.gateway_mac[0] = 0x52; work.gateway_mac[1] = 0x54; work.gateway_mac[2] = 0x00;
    work.gateway_mac[3] = 0x12; work.gateway_mac[4] = 0x34; work.gateway_mac[5] = 0x57;

    VERIFY( inet_aton( "10.0.2.0", &work.net_addr ) );
    VERIFY( inet_aton( "255.255.255.0", &work.netmask ) );
    VERIFY( inet_aton( "10.0.2.15", &work.guest_addr ) );
    VERIFY( inet_aton( "10.0.2.2", &work.gateway_addr ) );
    VERIFY( inet_aton( "10.0.2.3", &work.dns_addr ) );
    VERIFY( inet_aton( "127.0.0.1", &work.bind_addr ) );

    if (ctcis_parse_args( dev, &work, argc, argv ) != 0)
        return -1;

    blk = malloc( sizeof( CTCISBLK ) );
    if (!blk)
    {
        WRMSG( HHC00900, "E", SSID_TO_LCSS( dev->ssid ), dev->devnum,
               "CTCIS", "malloc()", strerror( errno ) );
        return -1;
    }

    memcpy( blk, &work, sizeof( CTCISBLK ) );
    blk->pDEVBLK[CTC_READ_SUBCHANN] = dev->group->memdev[0];
    blk->pDEVBLK[CTC_WRITE_SUBCHANN] = dev->group->memdev[1];
    blk->pDEVBLK[CTC_READ_SUBCHANN]->dev_data = blk;
    blk->pDEVBLK[CTC_WRITE_SUBCHANN]->dev_data = blk;

    SetSIDInfo( blk->pDEVBLK[CTC_READ_SUBCHANN], 0x3088, 0x08, 0x3088, 0x01 );
    SetSIDInfo( blk->pDEVBLK[CTC_WRITE_SUBCHANN], 0x3088, 0x08, 0x3088, 0x01 );
    blk->pDEVBLK[CTC_READ_SUBCHANN]->ctctype = CTC_CTCIS;
    blk->pDEVBLK[CTC_WRITE_SUBCHANN]->ctctype = CTC_CTCIS;
    blk->pDEVBLK[CTC_READ_SUBCHANN]->ctcxmode = 1;
    blk->pDEVBLK[CTC_WRITE_SUBCHANN]->ctcxmode = 1;
    STRLCPY( blk->pDEVBLK[CTC_READ_SUBCHANN]->filename, "libslirp" );
    STRLCPY( blk->pDEVBLK[CTC_WRITE_SUBCHANN]->filename, "libslirp" );

    initialize_lock( &blk->Lock );
    initialize_lock( &blk->EventLock );
    initialize_lock( &blk->SlirpLock );
    initialize_condition( &blk->Event );

    if (create_pipe( blk->wakefd ) < 0)
    {
        WRMSG( HHC00900, "E", SSID_TO_LCSS( dev->ssid ), dev->devnum,
               "CTCIS", "create_pipe()", strerror( errno ) );
        free( blk );
        return -1;
    }

#if !defined( WIN32 )
    fcntl( blk->wakefd[0], F_SETFL, fcntl( blk->wakefd[0], F_GETFL, 0 ) | O_NONBLOCK );
    fcntl( blk->wakefd[1], F_SETFL, fcntl( blk->wakefd[1], F_GETFL, 0 ) | O_NONBLOCK );
#endif

    memset( &cfg, 0, sizeof( cfg ) );
    cfg.version = 4;
    cfg.restricted = false;
    cfg.in_enabled = true;
    cfg.vnetwork.s_addr = blk->net_addr.s_addr;
    cfg.vnetmask.s_addr = blk->netmask.s_addr;
    cfg.vhost.s_addr = blk->gateway_addr.s_addr;
    cfg.vnameserver.s_addr = blk->dns_addr.s_addr;
    cfg.if_mtu = blk->sMTU;
    cfg.if_mru = blk->sMTU;

    blk->slirp = slirp_new( &cfg, &ctcis_slirp_cb, blk );
    if (!blk->slirp)
    {
        WRMSG( HHC00900, "E", SSID_TO_LCSS( dev->ssid ), dev->devnum,
               "CTCIS", "slirp_new()", strerror( errno ) );
        close_pipe( blk->wakefd[0] );
        close_pipe( blk->wakefd[1] );
        free( blk );
        return -1;
    }

    for (i = 0; i < blk->fwd_count; i++)
    {
        CTCISFWD* f = &blk->fwd[i];
        char hbuf[32], gbuf[32];
        STRLCPY( hbuf, inet_ntoa( f->host_addr ) );
        STRLCPY( gbuf, inet_ntoa( f->guest_addr ) );
        rc = slirp_add_hostfwd( blk->slirp, f->is_udp,
                                f->host_addr, f->host_port,
                                f->guest_addr, f->guest_port );
        if (rc != 0)
        {
            WRMSG( HHC00989, "E", SSID_TO_LCSS( dev->ssid ), dev->devnum,
                   "CTCIS", f->is_udp ? "udp" : "tcp", hbuf,
                   (unsigned)f->host_port, strerror( errno ) );
            CTCIS_Close( blk->pDEVBLK[CTC_READ_SUBCHANN] );
            return -1;
        }
        WRMSG( HHC00988, "I", SSID_TO_LCSS( dev->ssid ), dev->devnum,
               "CTCIS", f->is_udp ? "udp" : "tcp", hbuf, (unsigned)f->host_port,
               gbuf, (unsigned)f->guest_port );
    }

    blk->pDEVBLK[CTC_READ_SUBCHANN]->fd = blk->wakefd[0];
    blk->pDEVBLK[CTC_WRITE_SUBCHANN]->fd = blk->wakefd[0];

    WRMSG( HHC00901, "I", SSID_TO_LCSS( dev->ssid ), dev->devnum,
           "CTCIS", "libslirp", "userspace NAT" );

    MSGBUF( thread_name, "CTCIS %4.4X ReadThread", dev->devnum );
    rc = create_thread( &blk->tid, JOINABLE, CTCIS_ReadThread, blk, thread_name );
    if (rc)
    {
        WRMSG( HHC00102, "E", strerror( rc ) );
        CTCIS_Close( blk->pDEVBLK[CTC_READ_SUBCHANN] );
        return -1;
    }

    blk->pDEVBLK[CTC_READ_SUBCHANN]->tid = blk->tid;
    blk->pDEVBLK[CTC_WRITE_SUBCHANN]->tid = blk->tid;
    return 0;
}

int CTCIS_Close( DEVBLK* dev )
{
    PCTCISBLK blk = (PCTCISBLK)dev->dev_data;
    TID tid;

    if (!blk)
        return 0;

    if (!blk->fCloseInProgress)
    {
        blk->fCloseInProgress = 1;
        ctcis_notify( blk );
        tid = blk->tid;
        if (tid)
        {
            join_thread( tid, NULL );
#if defined( OPTION_FTHREADS )
            detach_thread( tid );
#endif
        }
    }

    if (blk->slirp)
    {
        slirp_cleanup( blk->slirp );
        blk->slirp = NULL;
    }

    while (blk->timers)
    {
        CTCISTIMER* next = blk->timers->next;
        free( blk->timers );
        blk->timers = next;
    }

    if (blk->wakefd[0] >= 0)
        close_pipe( blk->wakefd[0] );
    if (blk->wakefd[1] >= 0)
        close_pipe( blk->wakefd[1] );

    blk->pDEVBLK[CTC_READ_SUBCHANN]->fd = -1;
    blk->pDEVBLK[CTC_WRITE_SUBCHANN]->fd = -1;
    blk->pDEVBLK[CTC_READ_SUBCHANN]->dev_data = NULL;
    blk->pDEVBLK[CTC_WRITE_SUBCHANN]->dev_data = NULL;
    free( blk );
    return 0;
}

void CTCIS_Query( DEVBLK* dev, char** class, int buflen, char* buffer )
{
    PCTCISBLK blk;
    char guest[32], gateway[32];
    char filename[PATH_MAX + 1];

    BEGIN_DEVICE_CLASS_QUERY( "CTCA", dev, class, buflen, buffer );
    blk = (PCTCISBLK)dev->dev_data;
    if (!blk)
    {
        strlcpy( buffer, "*Uninitialized", buflen );
        return;
    }

    STRLCPY( guest, inet_ntoa( blk->guest_addr ) );
    STRLCPY( gateway, inet_ntoa( blk->gateway_addr ) );
    snprintf( buffer, buflen, "CTCIS %s/%s libslirp%s IO[%"PRIu64"]",
              guest, gateway, blk->fDebug ? " -d" : "", dev->excps );
    buffer[buflen - 1] = '\0';
}

void CTCIS_ExecuteCCW( DEVBLK* dev, BYTE code, BYTE flags, BYTE chained,
                       U32 count, BYTE prevcode, int ccwseq, BYTE* buf,
                       BYTE* more, BYTE* unitstat, U32* residual )
{
    BYTE op;
    int n;

    UNREFERENCED( flags );
    UNREFERENCED( chained );
    UNREFERENCED( prevcode );
    UNREFERENCED( ccwseq );

    if (dev->fd < 0 && !IS_CCW_SENSE( code ) && !IS_CCW_CONTROL( code ))
    {
        dev->sense[0] = SENSE_IR;
        *unitstat = CSW_CE | CSW_DE | CSW_UC;
        return;
    }

    if ((code & 0x07) == 0x07)
        op = 0x07;
    else if ((code & 0x03) == 0x02)
        op = 0x02;
    else if ((code & 0x0F) == 0x0C)
        op = 0x0C;
    else if ((code & 0x03) == 0x01)
        op = dev->ctcxmode ? (code & 0x83) : 0x01;
    else if ((code & 0x1F) == 0x14)
        op = 0x14;
    else if ((code & 0x47) == 0x03)
        op = 0x03;
    else if ((code & 0xC7) == 0x43)
        op = 0x43;
    else
        op = code;

    switch (op)
    {
    case 0x01:
        if (!count)
            *unitstat = CSW_CE | CSW_DE;
        else
            CTCIS_Write( dev, count, buf, unitstat, residual );
        break;
    case 0x81:
    case 0x07:
    case 0x03:
    case 0xE3:
    case 0x14:
        *unitstat = CSW_CE | CSW_DE;
        break;
    case 0x02:
    case 0x0C:
        CTCIS_Read( dev, count, buf, unitstat, residual, more );
        break;
    case 0x43:
        if (dev->ctcxmode == 0)
        {
            dev->sense[0] = SENSE_CR;
            *unitstat = CSW_CE | CSW_DE | CSW_UC;
        }
        else
        {
            dev->ctcxmode = 0;
            *residual = 0;
            *unitstat = CSW_CE | CSW_DE;
        }
        break;
    case 0xC3:
        dev->ctcxmode = 1;
        *residual = 0;
        *unitstat = CSW_CE | CSW_DE;
        break;
    case 0x04:
        if (dev->ctcxmode == 0)
        {
            dev->sense[0] = SENSE_CR;
            *unitstat = CSW_CE | CSW_DE | CSW_UC;
            break;
        }
        n = count < dev->numsense ? count : dev->numsense;
        *residual = count - n;
        if (count < dev->numsense)
            *more = 1;
        memcpy( buf, dev->sense, n );
        memset( dev->sense, 0, sizeof( dev->sense ) );
        *unitstat = CSW_CE | CSW_DE;
        break;
    case 0xE4:
        n = count < dev->numdevid ? count : dev->numdevid;
        *residual = count - n;
        if (count < dev->numdevid)
            *more = 1;
        memcpy( buf, dev->devid, n );
        *unitstat = CSW_CE | CSW_DE;
        break;
    default:
        dev->sense[0] = SENSE_CR;
        *unitstat = CSW_CE | CSW_DE | CSW_UC;
        break;
    }
}

static void ctcis_halt_or_clear( DEVBLK* dev )
{
    PCTCISBLK blk = (PCTCISBLK)dev->dev_data;

    if (!blk)
        return;

    obtain_lock( &blk->EventLock );
    if (blk->fReadWaiting)
    {
        blk->fHaltOrClear = 1;
        signal_condition( &blk->Event );
    }
    release_lock( &blk->EventLock );
}

static void CTCIS_Read( DEVBLK* dev, U32 count, BYTE* buf, BYTE* unitstat,
                        U32* residual, BYTE* more )
{
    PCTCISBLK blk = (PCTCISBLK)dev->dev_data;
    PCTCIHDR frame;
    size_t length;
    int rc;

    for (;;)
    {
        obtain_lock( &blk->Lock );
        if (!blk->fDataPending)
        {
            struct timeval now;
            struct timespec waittime;
            release_lock( &blk->Lock );
            gettimeofday( &now, NULL );
            waittime.tv_sec = now.tv_sec + DEF_NET_READ_TIMEOUT_SECS;
            waittime.tv_nsec = now.tv_usec * 1000;
            obtain_lock( &blk->EventLock );
            blk->fReadWaiting = 1;
            rc = timed_wait_condition( &blk->Event, &blk->EventLock, &waittime );
            blk->fReadWaiting = 0;
            if (blk->fHaltOrClear)
            {
                blk->fHaltOrClear = 0;
                release_lock( &blk->EventLock );
                if (dev->ccwtrace)
                    WRMSG( HHC00904, "I", SSID_TO_LCSS( dev->ssid ), dev->devnum, "CTCIS" );
                *unitstat = CSW_CE | CSW_DE;
                *residual = count;
                return;
            }
            release_lock( &blk->EventLock );
            if (rc == ETIMEDOUT || rc == EINTR)
                continue;
            obtain_lock( &blk->Lock );
        }

        if (blk->iFrameOffset == 0)
        {
            release_lock( &blk->Lock );
            continue;
        }

        frame = (PCTCIHDR)(blk->bFrameBuffer + sizeof( CTCIHDR ) + blk->iFrameOffset);
        STORE_HW( frame->hwOffset, 0 );
        length = blk->iFrameOffset + sizeof( CTCIHDR );

        if (count < length)
        {
            *more = 1;
            *residual = 0;
            length = count;
        }
        else
        {
            *more = 0;
            *residual -= (U16)length;
        }

        memcpy( buf, blk->bFrameBuffer, length );
        *unitstat = CSW_CE | CSW_DE;

        if (blk->fDebug)
        {
            WRMSG( HHC00982, "D", SSID_TO_LCSS( dev->ssid ), dev->devnum,
                   "CTCIS", (int)length );
            net_data_trace( dev, blk->bFrameBuffer, (int)length, '>', 'D', "data", 0 );
        }

        blk->iFrameOffset = 0;
        blk->fDataPending = 0;
        release_lock( &blk->Lock );
        return;
    }
}

static void CTCIS_Write( DEVBLK* dev, U32 count, BYTE* buf, BYTE* unitstat,
                         U32* residual )
{
    PCTCISBLK blk = (PCTCISBLK)dev->dev_data;
    PCTCIHDR frame;
    PCTCISEG seg;
    U16 offset, seglen, datalen, type;
    U32 pos;

    if (count < sizeof( CTCIHDR ))
    {
        WRMSG( HHC00906, "E", SSID_TO_LCSS( dev->ssid ), dev->devnum, count );
        dev->sense[0] = SENSE_DC;
        *unitstat = CSW_CE | CSW_DE | CSW_UC;
        return;
    }

    if (blk->fDebug)
    {
        WRMSG( HHC00981, "D", SSID_TO_LCSS( dev->ssid ), dev->devnum, dev->typname, (int)count );
        net_data_trace( dev, buf, (int)count, '<', 'D', "data", 0 );
    }

    frame = (PCTCIHDR)buf;
    FETCH_HW( offset, frame->hwOffset );

    if (offset == 0)
    {
        *unitstat = CSW_CE | CSW_DE;
        *residual = 0;
        return;
    }

    *residual -= sizeof( CTCIHDR );

    for (pos = sizeof( CTCIHDR ); pos < offset; pos += seglen)
    {
        BYTE ethbuf[CTCIS_ETH_HDR_SIZE + 9000];
        size_t ethlen = sizeof( ethbuf );

        if (pos + sizeof( CTCISEG ) > offset)
        {
            WRMSG( HHC00908, "E", SSID_TO_LCSS( dev->ssid ), dev->devnum, pos );
            dev->sense[0] = SENSE_DC;
            *unitstat = CSW_CE | CSW_DE | CSW_UC;
            return;
        }

        seg = (PCTCISEG)(buf + pos);
        FETCH_HW( seglen, seg->hwLength );
        FETCH_HW( type, seg->hwType );

        if (seglen < sizeof( CTCISEG ) || pos + seglen > offset || pos + seglen > count)
        {
            WRMSG( HHC00909, "E", SSID_TO_LCSS( dev->ssid ), dev->devnum, seglen, pos );
            dev->sense[0] = SENSE_DC;
            *unitstat = CSW_CE | CSW_DE | CSW_UC;
            return;
        }

        datalen = seglen - sizeof( CTCISEG );

        if (type != ETH_TYPE_IP || ctcis_make_eth_from_ipv4( blk, seg->bData, datalen, ethbuf, &ethlen ) != 0)
        {
            if (blk->fDebug)
                WRMSG( HHC00990, "D", SSID_TO_LCSS( dev->ssid ), dev->devnum,
                       dev->typname, "malformed CTCI", (unsigned)datalen );
            continue;
        }

        if (blk->fDebug)
        {
            WRMSG( HHC00910, "D", SSID_TO_LCSS( dev->ssid ), dev->devnum,
                   "CTCIS", "", datalen, "libslirp" );
            net_data_trace( dev, seg->bData, datalen, '<', 'D', "packet", 0 );
        }

        obtain_lock( &blk->SlirpLock );
        slirp_input( blk->slirp, ethbuf, ethlen );
        release_lock( &blk->SlirpLock );

        *residual -= seglen;
    }

    *unitstat = CSW_CE | CSW_DE;
    *residual = 0;
}

static void* CTCIS_ReadThread( void* arg )
{
    PCTCISBLK blk = (PCTCISBLK)arg;
    CTCISPOLLCTX ctx;
    BYTE drain[64];

    blk->pid = getpid();

    while (!blk->fCloseInProgress)
    {
        int timeout;
        int rc;

        memset( &ctx, 0, sizeof( ctx ) );
        obtain_lock( &blk->SlirpLock );
        slirp_pollfds_fill( blk->slirp, &timeout, ctcis_add_poll, &ctx );
        timeout = MIN( timeout, ctcis_timer_timeout( blk ) );
        release_lock( &blk->SlirpLock );

        if (ctx.nfds < CTCIS_MAX_POLLFD)
        {
            ctx.fds[ctx.nfds].fd = blk->wakefd[0];
            ctx.fds[ctx.nfds].events = POLLIN;
            ctx.fds[ctx.nfds].revents = 0;
            ctx.nfds++;
        }

        rc = poll( ctx.fds, ctx.nfds, timeout );
        if (rc < 0 && errno == EINTR)
            continue;
        if (rc < 0)
            break;

        if (ctx.nfds > 0 && ctx.fds[ctx.nfds - 1].revents & POLLIN)
            while (read_pipe( blk->wakefd[0], drain, sizeof( drain ) ) > 0)
                ;

        obtain_lock( &blk->SlirpLock );
        slirp_pollfds_poll( blk->slirp, rc < 0, ctcis_get_revents, &ctx );
        ctcis_timer_fire_due( blk );
        release_lock( &blk->SlirpLock );
    }

    return NULL;
}

static int ctcis_parse_ipv4( const char* s, struct in_addr* addr, int allow_multicast )
{
    U32 host;

    if (!s || !inet_aton( s, addr ))
        return -1;

    host = ntohl( addr->s_addr );
    if (!allow_multicast && host >= 0xE0000000U && host <= 0xEFFFFFFFU)
        return -1;

    return 0;
}

static int ctcis_parse_port( const char* s )
{
    char* end = NULL;
    long port = strtol( s, &end, 10 );

    if (!s || !*s || *end || port <= 0 || port > 65535)
        return -1;
    return (int)port;
}

static int ctcis_add_forward( DEVBLK* dev, PCTCISBLK blk, const char* value )
{
    char work[128];
    char* tok[5];
    char* p;
    int ntok = 0;
    CTCISFWD f;
    int i;

    if (strlen( value ) >= sizeof( work ))
        return -1;

    STRLCPY( work, value );
    for (p = strtok( work, ":" ); p && ntok < 5; p = strtok( NULL, ":" ))
        tok[ntok++] = p;
    if (strtok( NULL, ":" ))
        return -1;

    memset( &f, 0, sizeof( f ) );
    if (!strcasecmp( tok[0], "tcp" ))
        f.is_udp = 0;
    else if (!strcasecmp( tok[0], "udp" ))
        f.is_udp = 1;
    else
        return -1;

    if (ntok == 3)
    {
        f.host_addr = blk->bind_addr;
        f.guest_addr = blk->guest_addr;
        f.host_port = ctcis_parse_port( tok[1] );
        f.guest_port = ctcis_parse_port( tok[2] );
    }
    else if (ntok == 5)
    {
        if (ctcis_parse_ipv4( tok[1], &f.host_addr, 0 ) != 0 ||
            ctcis_parse_ipv4( tok[3], &f.guest_addr, 0 ) != 0)
            return -1;
        f.host_port = ctcis_parse_port( tok[2] );
        f.guest_port = ctcis_parse_port( tok[4] );
    }
    else
        return -1;

    if (f.host_port < 0 || f.guest_port < 0 || blk->fwd_count >= CTCIS_MAX_FWD)
        return -1;

    for (i = 0; i < blk->fwd_count; i++)
        if (blk->fwd[i].is_udp == f.is_udp &&
            blk->fwd[i].host_addr.s_addr == f.host_addr.s_addr &&
            blk->fwd[i].host_port == f.host_port)
        {
            WRMSG( HHC00916, "E", SSID_TO_LCSS( dev->ssid ), dev->devnum,
                   "CTCIS", "host forward", value );
            return -1;
        }

    blk->fwd[blk->fwd_count++] = f;
    return 0;
}

static int ctcis_parse_args( DEVBLK* dev, PCTCISBLK blk, int argc, char** argx )
{
    char* argn[MAX_ARGS];
    char** argv = argn;
    int i, c;

    for (i = 0; i < argc && i < MAX_ARGS; i++)
        argn[i] = argx[i];

    if (argc > MAX_ARGS - 1)
        argc = MAX_ARGS - 1;
    for (i = argc; i > 0; i--)
        argv[i] = argv[i - 1];
    argv[0] = dev->typname;
    argc++;

    OPTRESET();
    optind = 0;

    for (;;)
    {
#if defined( HAVE_GETOPT_LONG )
        int optidx;
        static struct option options[] =
        {
            { "addr",    required_argument, NULL, 'a' },
            { "gateway", required_argument, NULL, 'g' },
            { "netmask", required_argument, NULL, 's' },
            { "net",     required_argument, NULL, 'n' },
            { "dns",     required_argument, NULL, 'r' },
            { "bind",    required_argument, NULL, 'b' },
            { "mtu",     required_argument, NULL, 't' },
            { "debug",   no_argument,       NULL, 'd' },
            { NULL,      0,                 NULL,  0  }
        };
        c = getopt_long( argc, argv, "p:a:g:s:n:r:b:t:d", options, &optidx );
#else
        c = getopt( argc, argv, "p:a:g:s:n:r:b:t:d" );
#endif
        if (c == -1)
            break;

        switch (c)
        {
        case 'p':
            if (ctcis_add_forward( dev, blk, optarg ) != 0)
            {
                WRMSG( HHC00916, "E", SSID_TO_LCSS( dev->ssid ), dev->devnum,
                       "CTCIS", "port forward", optarg );
                return -1;
            }
            break;
        case 'a':
            if (ctcis_parse_ipv4( optarg, &blk->guest_addr, 0 ) != 0)
                goto bad_opt;
            break;
        case 'g':
            if (ctcis_parse_ipv4( optarg, &blk->gateway_addr, 0 ) != 0)
                goto bad_opt;
            break;
        case 's':
            if (ctcis_parse_ipv4( optarg, &blk->netmask, 1 ) != 0)
                goto bad_opt;
            break;
        case 'n':
            if (ctcis_parse_ipv4( optarg, &blk->net_addr, 0 ) != 0)
                goto bad_opt;
            break;
        case 'r':
            if (ctcis_parse_ipv4( optarg, &blk->dns_addr, 0 ) != 0)
                goto bad_opt;
            break;
        case 'b':
            if (ctcis_parse_ipv4( optarg, &blk->bind_addr, 0 ) != 0)
                goto bad_opt;
            break;
        case 't':
            i = atoi( optarg );
            if (i < 46 || i > 65535)
                goto bad_opt;
            blk->sMTU = i;
            break;
        case 'd':
            blk->fDebug = 1;
            break;
        default:
            WRMSG( HHC00918, "E", SSID_TO_LCSS( dev->ssid ), dev->devnum,
                   "CTCIS", argv[optind - 1] );
            return -1;
        }
        continue;

bad_opt:
        WRMSG( HHC00916, "E", SSID_TO_LCSS( dev->ssid ), dev->devnum,
               "CTCIS", argv[optind - 1], optarg );
        return -1;
    }

    argc -= optind;
    if (argc != 0)
    {
        WRMSG( HHC00915, "E", SSID_TO_LCSS( dev->ssid ), dev->devnum, "CTCIS" );
        return -1;
    }

    for (i = 0; i < blk->fwd_count; i++)
        if (blk->fwd[i].guest_addr.s_addr == 0)
            blk->fwd[i].guest_addr = blk->guest_addr;

    return 0;
}

#endif /* defined( OPTION_SLIRP ) */
