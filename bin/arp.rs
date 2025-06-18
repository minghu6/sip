#![feature(never_type)]

use std::{
    error::Error,
    net::Ipv4Addr,
    os::fd::{AsFd, AsRawFd, BorrowedFd},
    ptr::{read, write},
};

use clap::Parser;
use linuxc::{
    epoll::{Epoll, EpollData, EpollEvent, EpollFlag},
    errno::{self},
    iface::{IfAddr, get_ifaddrtbl, get_ifindex, get_ifip},
    socket::{
        AddressFamily, ExtraBehavior, Flags, InAddr, PktType, SaFamily,
        SockAddr, SockAddrLL, SocketProtocol, SocketType, recv_all,
        sendto_all, socket,
    },
    ether::{ EthTypeKind }
};
use m6ptr::OnceStatic;
use osimodel::{
    datalink::{
        Eth, Mac,
        arp::{ARP, ARPOpKind, HTypeKind},
    },
    network::IPv4Addr,
};

////////////////////////////////////////////////////////////////////////////////
//// Constants

const BUF_SIZE: usize = 60;

////////////////////////////////////////////////////////////////////////////////
//// Static Variables

static SRC_IP: OnceStatic<IPv4Addr> = OnceStatic::new();
static IFINDEX: OnceStatic<i32> = OnceStatic::new();

////////////////////////////////////////////////////////////////////////////////
//// Structures


#[derive(Parser)]
struct Cli {
    /// IP
    #[arg(required = true)]
    dst: Vec<Ipv4Addr>,

    /// Set interface by name or else use first nonloop interface
    #[arg(short = 'i')]
    ifname: Option<String>,
}


////////////////////////////////////////////////////////////////////////////////
//// Implementations



////////////////////////////////////////////////////////////////////////////////
//// Functions

fn send_arp(sock: BorrowedFd, dst_ip: IPv4Addr) -> errno::Result<usize> {
    let src_mac = Mac::BROADCAST;

    let sockaddr = SockAddrLL {
        family: SaFamily::Packet.into(),
        protocol: EthTypeKind::ARP.into(),
        ifindex: *IFINDEX,
        hatype: HTypeKind::Ethernet10Mb.into(),
        pkttype: PktType::Broadcast,
        halen: size_of::<Mac>() as u8,
        addr: src_mac.into(),
    };

    let mut buf = [0u8; BUF_SIZE];

    /* Init package */

    let eth = Eth {
        dst: Mac::BROADCAST,
        src: src_mac,
        proto: EthTypeKind::ARP.into_proto(),
    };

    let arp = ARP {
        htype: HTypeKind::Ethernet10Mb.into(),
        ptype: EthTypeKind::IPv4.into(),
        hlen: size_of::<Mac>() as u8,
        plen: size_of::<InAddr> as u8,
        op: ARPOpKind::Request.into(),
        sha: src_mac,
        spa: *SRC_IP,
        tha: Mac::ZERO,
        tpa: dst_ip,
    };

    let mut cnt = 0;

    unsafe {
        let p = buf.as_mut_ptr();

        write(p.byte_add(cnt) as *mut Eth, eth);
        cnt += size_of::<Eth>();

        write(p.byte_add(cnt) as *mut ARP, arp);
        cnt += size_of::<ARP>();
    }

    sendto_all(
        sock,
        &buf[..cnt],
        Flags::default(),
        Some(SockAddr::Packet(sockaddr)),
    )
}

fn recv_arp(sock: BorrowedFd, i: &mut usize) -> Result<(), Box<dyn Error>> {
    let mut buf = [0u8; BUF_SIZE];

    let readn = recv_all(sock, &mut buf, Flags::default())?;

    let hdrsz = size_of::<Eth>() + size_of::<ARP>();

    if readn < hdrsz {
        Err(format!("expect {hdrsz} bytes, found {readn} bytes"))?
    }

    let mut cnt = 0;

    unsafe {
        let p = buf.as_ptr();

        // let ethhdr = read(p.byte_add(cnt) as *mut Eth);
        cnt += size_of::<Eth>();

        let arphdr = read(p.byte_add(cnt) as *mut ARP);
        // cnt += size_of::<ARP>();

        if arphdr.tpa != *SRC_IP {
            // not target deveice, discard it
            return Ok(());
        }

        *i += 1;

        println!("  {i:04} {}/{}", arphdr.spa, arphdr.sha);
    }

    Ok(())
}

fn main() -> Result<!, Box<dyn Error>> {
    let cli = Cli::parse();

    let (ifname, ip) = if let Some(ifname) = cli.ifname {
        let ip = get_ifip(&ifname)?;

        (ifname, ip.into())
    }
    else {
        let ifaddrtbl = get_ifaddrtbl()?;

        let Some((ifname, ip)) = ifaddrtbl.iter().find_map(|if_addr| {
            if let IfAddr::Inet { name, addr, .. } = if_addr {
                if !addr.is_loopback() {
                    Some((name.clone(), *addr))
                }
                else {
                    None
                }
            }
            else {
                None
            }
        })
        else {
            Err(format!("No matched net interface"))?
        };

        (ifname, ip.into())
    };

    SRC_IP.init(ip).unwrap();
    IFINDEX.init(get_ifindex(&ifname)?).unwrap();

    let dst_list = cli.dst;
    let mut sock_list = Vec::with_capacity(dst_list.len());

    let mut epoll = Epoll::create()?;

    for dst in dst_list {
        let dst_ip = IPv4Addr::from(dst);

        let sock = socket(
            AddressFamily::PACKET,
            SocketType::RAW,
            ExtraBehavior::default().non_block(),
            SocketProtocol::Eth(EthTypeKind::ARP),
        )
        .map_err(|code| format!("socket error: {code}"))?;

        epoll.insert(
            sock.as_fd(),
            EpollEvent {
                events: EpollFlag::ET | EpollFlag::In,
                data: EpollData {
                    fd: sock.as_raw_fd(),
                },
            },
        )?;

        println!("Send ARP request to {dst_ip:?}");
        send_arp(sock.as_fd(), dst_ip)?;

        sock_list.push(sock);
    }

    println!("sock_list: {sock_list:?}");

    let mut events = [EpollEvent::default(); 10];
    let mut i = 0;

    loop {
        let recvd = epoll.pwait(&mut events, 10_000, None)?;

        // println!("{i} RECV {recvd:?} Reply");

        for event in recvd {
            // if event & EpollFlag::Out {
            //     continue;
            // }

            if event == EpollFlag::In {
                // println!("{i:04} {:?}/fd {:?}", event.events, unsafe { event.data.fd });

                recv_arp(
                    unsafe { BorrowedFd::borrow_raw(event.data.fd) },
                    &mut i,
                )?;
            }
        }
    }
}
