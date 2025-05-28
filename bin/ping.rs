#![feature(never_type)]

use std::{
    collections::VecDeque,
    fmt::Display,
    net::Ipv4Addr,
    os::fd::{AsFd, AsRawFd, BorrowedFd},
    str::FromStr,
    sync::{Mutex, RwLock},
    thread::{self, sleep},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Error, Ok, anyhow};
use clap::Parser;
use derive_more::derive::{Deref, DerefMut};
use linuxc::{
    epoll::{Epoll, EpollData, EpollEvent, EpollFlag},
    netdb::{AIFamilies, getaddrinfo},
    signal::{Signal, SignalSet, pthread_sigmask},
    socket::{
        AddressFamilies, ExtraBehavior, SockAddr, SockAddrIn, SocketProtocol,
        SocketType, recv_all, sendto_all, socket,
    },
};
use m6ptr::{OnceStatic, OwnedPtr, Ptr};
use m6tobytes::{as_raw_slice, from_raw_slice};
use osimodel::network::{
    icmp::{ICMP, ICMPCode, ICMPTypeSpec},
    inet_cksum,
    ip::{IPv4, ProtocolSpec},
};

////////////////////////////////////////////////////////////////////////////////
//// Constants

////////////////////////////////////////////////////////////////////////////////
//// Static Variables

static INTERVAL_MILIS: OnceStatic<u64> = OnceStatic::new();
static TIMEOUT_MILIS: OnceStatic<u64> = OnceStatic::new();
static WND: OnceStatic<u16> = OnceStatic::new();


////////////////////////////////////////////////////////////////////////////////
//// Structures

#[derive(Debug, Clone)]
enum Host {
    IPv4(Ipv4Addr),
    RegName(String),
}

type Result<T> = std::result::Result<T, Error>;

struct ControlSignals {
    value: OwnedPtr<RwLock<SignalSet>>,
}

#[derive(Debug, Clone, Copy)]
struct ControlSignalsRef {
    value: Ptr<RwLock<SignalSet>>,
}

#[derive(Debug)]
struct RequestRecord {
    seq: u16,
    /// as nanos
    sent: u128,
}

#[derive(Debug)]
struct StatsGroupRaw {
    dst_ip: Ipv4Addr,
    sent_cnt: u64,
    recv_cnt: u64,
    lost_cnt: u64,
    /// nanos
    sent_time: u128,
    tbl: VecDeque<RequestRecord>,
}

#[derive(Debug, Deref, DerefMut)]
struct StatsGroup {
    value: OwnedPtr<Mutex<StatsGroupRaw>>,
}

#[derive(Debug, Deref, DerefMut, Clone, Copy)]
struct StatsGroupRef {
    value: Ptr<Mutex<StatsGroupRaw>>,
}

struct Stats {
    dst_ip: Ipv4Addr,
    sent_cnt: u64,
    recv_cnt: u64,
    lost_cnt: u64,
    diff_time: u128,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct ICMPPacket {
    hdr: ICMP,
    _padding: [u8; 8],
    data: EchoData,
}

#[derive(Clone, Copy)]
#[repr(C)]
struct EchoData {
    timestamp: u128,
}

struct DisplayMiliSecondDuration {
    nanos: u128,
}

struct DisplaySecondDuration {
    nanos: u128,
}

////////////////////////////////////////
//// Cli

#[derive(Parser)]
struct Cli {
    dst: String,
    /// recv timeout (ms)
    #[arg(short, default_value = "5000")]
    timeout: u64,
    /// send interval (ms)
    #[arg(short, default_value = "500")]
    interval: u64,
    /// send window size
    #[arg(short, default_value = "5")]
    window: u16,
}

////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl DisplaySecondDuration {
    fn new(nanos: u128) -> Self {
        Self { nanos }
    }
}

impl Display for DisplaySecondDuration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let us_int = self.nanos / 1000;
        let ms_int = us_int / 1000;
        let ms_rem = us_int % 1000;
        let s_int = ms_int / 1000;
        let m_int = s_int / 60;
        let h_int = m_int / 60;

        if h_int > 0 {
            write!(f, "{h_int}h{}m", m_int % 60)
        }
        else if m_int > 0 {
            write!(f, "{m_int}m{}s", s_int % 60)
        }
        else if s_int > 0 {
            write!(f, "{s_int}.{}s", ms_rem / 100)
        }
        else {
            write!(f, "{ms_int}ms")
        }
    }
}

impl DisplayMiliSecondDuration {
    fn new(nanos: u128) -> Self {
        Self { nanos }
    }
}

impl Display for DisplayMiliSecondDuration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let us_int = self.nanos / 1000;
        let us_rem = self.nanos % 1000;
        let ms_int = us_int / 1000;
        let ms_rem = us_int % 1000;
        let s_int = ms_int / 1000;

        if s_int > 0 {
            write!(f, "{s_int}.{}s", ms_rem / 100)
        }
        else if ms_int > 0 {
            write!(f, "{ms_int}.{}ms", us_rem / 100)
        }
        else {
            write!(f, "0.{us_rem}ms")
        }
    }
}

impl FromStr for Host {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        let c = s.as_bytes()[0] as char;

        Ok(if c.is_digit(10) {
            Self::IPv4(Ipv4Addr::from_str(s)?)
        }
        else {
            Self::RegName(s.to_owned())
        })
    }
}

impl Host {
    fn get_ip(&self) -> Result<Ipv4Addr> {
        let hostname = match self {
            Self::IPv4(ipv4_addr) => return Ok(*ipv4_addr),
            Self::RegName(name) => name,
        };

        let tbl = getaddrinfo(Some(&hostname), None, None)
            .map_err(|err| anyhow!("dns lookup failed: {err}"))?;

        tbl.into_iter()
            .find_map(|addrinfo| {
                if matches!(addrinfo.family, AIFamilies::INET) {
                    addrinfo
                        .sockaddr
                        .map(|sockaddr| {
                            if let SockAddr::Inet(sockaddr_in) = sockaddr {
                                Some(sockaddr_in.addr.into())
                            }
                            else {
                                None
                            }
                        })
                        .flatten()
                }
                else {
                    None
                }
            })
            .ok_or(anyhow!("unknown host {hostname}"))
    }
}

impl ControlSignals {
    fn new() -> Self {
        Self {
            value: OwnedPtr::new(RwLock::new(SignalSet::empty())),
        }
    }

    fn as_ref(&self) -> ControlSignalsRef {
        ControlSignalsRef {
            value: self.value.ptr(),
        }
    }
}

impl ControlSignalsRef {
    fn insert(&mut self, sig: Signal) {
        self.value.write().unwrap().insert(sig);
    }

    fn has_sig(&self, sig: Signal) -> bool {
        self.value.read().unwrap().is_member(sig)
    }

    fn is_empty(&self) -> bool {
        self.value.read().unwrap().is_empty()
    }
}

impl RequestRecord {
    /// now: nanos
    fn is_expired(&self, now: u128) -> bool {
        assert!(now > self.sent);

        (now - self.sent) >= (*TIMEOUT_MILIS as u128 * 1000_000)
    }

    fn do_print_expired(&self) {
        println!("icmp_seq={} Timeout", self.seq)
    }
}

impl StatsGroup {
    fn new(dst_ip: Ipv4Addr) -> Result<Self> {
        assert!(*TIMEOUT_MILIS > *INTERVAL_MILIS);

        Ok(Self {
            value: OwnedPtr::new(Mutex::new(StatsGroupRaw {
                dst_ip,
                sent_cnt: 0,
                recv_cnt: 0,
                lost_cnt: 0,
                sent_time: timestamp_now()?,
                tbl: VecDeque::<RequestRecord>::with_capacity(
                    (TIMEOUT_MILIS.div_ceil(*INTERVAL_MILIS)) as usize,
                ),
            })),
        })
    }

    fn as_ref(&self) -> StatsGroupRef {
        StatsGroupRef {
            value: self.value.ptr(),
        }
    }
}

impl StatsGroupRef {
    fn push(&mut self, rec: RequestRecord) {
        let mut t = self.lock().unwrap();

        t.tbl.push_back(rec);
        t.sent_cnt += 1;
    }

    fn cwnd(&self) -> u16 {
        let t = self.lock().unwrap();

        (t.sent_cnt - (t.recv_cnt + t.lost_cnt)) as _
    }

    fn remove_expired(&mut self) -> Result<Vec<RequestRecord>> {
        let now = timestamp_now()?;

        let mut t = self.value.lock().unwrap();

        let Some(back) = t.tbl.back()
        else {
            return Ok(Default::default());
        };

        if back.is_expired(now) {
            t.lost_cnt += t.tbl.len() as u64;
            return Ok(t.tbl.drain(..).collect());
        }

        /* back isn't expired */

        if let Some(pos) = t.tbl.iter().position(|rec| !rec.is_expired(now)) {
            t.lost_cnt += pos as u64;
            return Ok(t.tbl.drain(..pos).collect());
        }

        Ok(Default::default())
    }

    fn remove(&mut self, seq: u16) -> Option<RequestRecord> {
        let mut t = self.value.lock().unwrap();

        if let Some(pos) = t.tbl.iter().position(|rec| rec.seq == seq) {
            t.recv_cnt += 1;
            t.tbl.remove(pos)
        }
        else {
            None
        }
    }

    fn elapsed(&self) -> Result<Stats> {
        let now = timestamp_now()?;
        let t = self.value.lock().unwrap();

        Ok(Stats {
            dst_ip: t.dst_ip,
            sent_cnt: t.sent_cnt,
            recv_cnt: t.recv_cnt,
            lost_cnt: t.lost_cnt,
            diff_time: now - t.sent_time,
        })
    }
}

impl Stats {
    fn do_print(&self) {
        println!("--- {} ping statistics ---", self.dst_ip);

        let tot = self.recv_cnt + self.lost_cnt;
        let loss_rate = if tot == 0 {
            format!("-")
        }
        else {
            format!("{}%", self.lost_cnt * 100 / tot)
        };

        println!(
            "{} packets transmitted, {} received, {} lost, {} packet loss, time: {}",
            self.sent_cnt,
            self.recv_cnt,
            self.lost_cnt,
            loss_rate,
            DisplaySecondDuration::new(self.diff_time)
        )
    }
}

////////////////////////////////////////////////////////////////////////////////
//// Functions

fn timestamp_now() -> Result<u128> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())
}

fn icmp_pack<'a>(
    buf: &'a mut [u8],
    seq: u16,
    data: EchoData,
) -> Result<&'a [u8]> {
    let ty = ICMPTypeSpec::EchoRequest.into();
    let code = ICMPCode::default();
    let cksum = Default::default();
    let gid = 0;
    let un = pack_un(gid, seq);

    let hdr = ICMP {
        ty,
        code,
        cksum,
        un,
    };

    let mut icmp = ICMPPacket {
        hdr,
        _padding: Default::default(),
        data,
    };

    // ICMP checksum including the ICMP header and data.
    icmp.hdr.cksum = inet_cksum(as_raw_slice(&icmp)).into();

    buf[..size_of::<ICMPPacket>()].copy_from_slice(as_raw_slice(&icmp));

    Ok(&buf[..size_of::<ICMPPacket>()])
}

fn pack_un(id: u16, seq: u16) -> u32 {
    (seq.to_be() as u32) << 16 | id.to_be() as u32
}

/// -> (id, seq)
fn unpack_un(un: u32) -> (u16, u16) {
    (
        u16::from_be((un & 0xFFFF) as u16),
        u16::from_be((un >> 16) as u16),
    )
}

fn ping_send_loop(
    sock: BorrowedFd,
    dst: Ipv4Addr,
    mut stats: StatsGroupRef,
    ctlsigs: ControlSignalsRef,
) -> Result<()> {
    let mut buf = [0u8; 1500];
    let mut seq = 0u16;

    println!(
        "PING ({:?}) {}({}) bytes of data.",
        dst,
        size_of::<ICMPPacket>(),
        size_of::<ICMPPacket>() + size_of::<IPv4>()
    );

    'end: loop {
        seq = seq.wrapping_add(1);

        let rec = ping_once(&mut buf, sock, seq, dst)?;

        stats.push(rec);

        loop {
            if !ctlsigs.is_empty() {
                if ctlsigs.has_sig(Signal::SIGINT)
                    || ctlsigs.has_sig(Signal::SIGTERM)
                {
                    break 'end;
                }
            }

            sleep(Duration::from_millis(*INTERVAL_MILIS));

            if stats.cwnd() <= *WND {
                break;
            }
        }
    }

    Ok(())
}

fn ping_once(
    buf: &mut [u8],
    sock: BorrowedFd,
    seq: u16,
    dst: Ipv4Addr,
) -> Result<RequestRecord> {
    let sent = timestamp_now()?;

    let packed = icmp_pack(buf, seq, EchoData { timestamp: sent })?;

    sendto_all(
        sock,
        packed,
        Default::default(),
        SockAddrIn::from(dst).into(),
    )
    .map_err(|err| anyhow!("sendto failed {err}"))?;

    Ok(RequestRecord { seq, sent })
}

fn ping_recv(
    buf: &mut [u8],
    dst: Ipv4Addr,
    sock: BorrowedFd,
    mut stats: StatsGroupRef,
) -> Result<()> {
    let readn = recv_all(sock, buf, Default::default())?;

    /* filter malformed package */

    if readn < size_of::<IPv4>() + size_of::<ICMPPacket>() {
        return Ok(());
    }

    let buf = &buf[..readn];

    let iphdr = from_raw_slice::<IPv4>(buf);

    /* filter src */

    if iphdr.src != dst.into() {
        return Ok(());
    }

    // checksum offload
    if !iphdr.cksum.is_zero() {
        /* verify checksum */

        if !iphdr.verify_cksum() {
            // "IP header verify cksum failed {iphdr:#?}"
            return Ok(());
        }
    }

    let icmp = from_raw_slice::<ICMPPacket>(&buf[size_of::<IPv4>()..]);
    let icmphdr = icmp.hdr;
    let icmptype: ICMPTypeSpec = icmphdr.ty.into();

    /* filter icmp type  */

    // filter loopback echo request

    if iphdr.src.is_loopback() && icmptype == ICMPTypeSpec::EchoRequest {
        return Ok(());
    }

    print!(
        "{}({}) bytes from {:#?}: ",
        iphdr.totlen.data_len(),
        iphdr.totlen.tot_len(),
        iphdr.src,
    );

    if icmptype != ICMPTypeSpec::EchoReply {
        use ICMPTypeSpec::*;

        match icmptype {
            DestinationUnreachable
            | RouterAdvertisement
            | RouterSolicitation
            | TimeExceeded
            | BadParam => {
                println!("{:?}/{:?}", icmphdr.ty, icmphdr.debug_icmp_code())
            }
            _ => println!("{:?}", icmphdr.ty),
        }

        return Ok(());
    }

    /* verify icmp checksum */

    if inet_cksum(as_raw_slice(&icmp)) != 0 {
        println!("Bad Checksum");
        return Ok(());
    }

    let (_id, seq) = unpack_un(icmphdr.un);

    let data = icmp.data;
    let delay = timestamp_now()? - data.timestamp;

    stats.remove(seq);

    println!(
        "icmp_seq={} ttl={} rrt={}",
        seq,
        iphdr.ttl.to_bits(),
        DisplayMiliSecondDuration::new(delay),
    );

    Ok(())
}

fn ping_recv_loop(
    sock: BorrowedFd,
    dst: Ipv4Addr,
    mut stats: StatsGroupRef,
    ctlsigs: ControlSignalsRef,
) -> Result<()> {
    let mut buf = [0u8; 2500];
    let mut epoll = Epoll::create()?;

    epoll.insert(
        sock,
        EpollEvent {
            events: EpollFlag::In | EpollFlag::ET,
            data: EpollData {
                fd: sock.as_raw_fd(),
            },
        },
    )?;

    let mut events = [EpollEvent::default(); 1];

    loop {
        let recvd = epoll.pwait(&mut events, *TIMEOUT_MILIS as _, None)?;

        if !ctlsigs.is_empty() {
            if ctlsigs.has_sig(Signal::SIGINT)
                || ctlsigs.has_sig(Signal::SIGTERM)
            {
                break;
            }
        }

        for rec in stats.remove_expired()? {
            rec.do_print_expired();
        }

        if recvd.is_empty() {
            for rec in stats.remove_expired()? {
                rec.do_print_expired();
            }

            continue;
        }

        ping_recv(&mut buf, dst, sock, stats)?;
    }

    Ok(())
}

fn thread_ctl(sigset: SignalSet, mut ctlsig: ControlSignalsRef) {
    let sig = sigset.wait();

    ctlsig.insert(sig);
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let dst = cli.dst.parse::<Host>()?;
    let dst_ip = dst.get_ip()?;

    TIMEOUT_MILIS.init(cli.timeout).unwrap();
    INTERVAL_MILIS.init(cli.interval).unwrap();
    WND.init(cli.window).unwrap();

    let sock = socket(
        AddressFamilies::INET,
        SocketType::RAW,
        ExtraBehavior::default().non_block(),
        SocketProtocol::IP(ProtocolSpec::ICMP),
    )
    .map_err(|err| anyhow!("create raw sock failed for {err}"))?;

    let stats = StatsGroup::new(dst_ip)?;
    let mut stats_ref = stats.as_ref();
    let ctlsigs = ControlSignals::new();
    let blocked_sigset = Signal::SIGINT | Signal::SIGTERM;

    pthread_sigmask(Default::default(), blocked_sigset)?;

    /* TODO: Rust 线程隔绝了 POSIX 线程实现，通过线程间互相通信来实现信号的互相通知, 取代 sigwait */

    thread::scope(|s| {
        let ctlsigs_ref = ctlsigs.as_ref();
        let fd = sock.as_fd();

        thread::Builder::new()
            .name("child-send".to_owned())
            .spawn_scoped(s, move || {
                if let Err(err) =
                    ping_send_loop(fd, dst_ip, stats_ref, ctlsigs_ref)
                {
                    eprintln!("child-send: {err}");
                }
            })?;

        thread::Builder::new()
            .name("child-recv".to_owned())
            .spawn_scoped(s, move || {
                if let Err(err) =
                    ping_recv_loop(fd, dst_ip, stats_ref, ctlsigs_ref)
                {
                    eprintln!("child-recv: {err}");
                }
            })?;

        thread::Builder::new()
            .name("child-ctlsigs".to_owned())
            .spawn_scoped(s, move || {
                thread_ctl(blocked_sigset, ctlsigs_ref)
            })?;

        Ok(())
    })?;

    /* pthread_sigmask affects globaly on rust */

    for rec in stats_ref.remove_expired()? {
        rec.do_print_expired();
    }

    stats_ref.elapsed()?.do_print();

    Ok(())
}
