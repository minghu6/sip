use std::{
    net::Ipv4Addr,
    os::fd::{AsFd, OwnedFd},
};

use anyhow::anyhow;
use linuxc::{
    ether::EthTypeKind,
    iface::{HwType, IfAddr, get_ifaddrtbl, get_ifhwaddr, get_ifmtu},
    netlink::get_gateway_ipv4_by_ifname,
    socket::{
        AddressFamily, PktType, SaFamily, SockAddrLL, SocketType, bind, socket,
    },
    unistd::read,
};
use log::{trace, warn};
use m6io::rawbuf::RawBuf;
use osimodel::{
    datalink::{
        Eth, EthProtoKind, EthTypeKind as OSIEtHTypeKind, Mac,
        arp::{HTypeKind},
    },
    network::ip::IPv4,
};

use crate::{
    arp::{ARP_TBL},
    skbuff::SkBuff,
};


#[derive(Debug)]
pub struct NetDevice {
    pub name: String,
    pub ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub gateway: Ipv4Addr,
    pub hwt: HwType,
    pub hwa: Mac,
    pub mtu: u16,
    /// Sock descriptor
    pub sd: OwnedFd,
    pub to: SockAddrLL,
}


impl NetDevice {
    pub fn init(ifname: &str) -> anyhow::Result<Self> {
        let sd = socket(
            AddressFamily::PACKET,
            SocketType::RAW,
            Default::default(),
            EthTypeKind::ALL.into(),
        )?;

        let ifaddrtbl = get_ifaddrtbl()?;

        let Some((ifindex, hwa)) = ifaddrtbl.iter().find_map(|ifaddr| {
            if let IfAddr::Packet {
                name,
                ifindex,
                addr,
                ..
            } = ifaddr
                && name == ifname
            {
                Some((*ifindex, *addr))
            }
            else {
                None
            }
        })
        else {
            Err(anyhow::anyhow!("no ifname `{ifname}` found"))?
        };

        let Some((ip, netmask)) = ifaddrtbl.iter().find_map(|ifaddr| {
            if let IfAddr::Inet { name, addr, mask, .. } = ifaddr
                && name == ifname
            {
                Some((*addr, *mask))
            }
            else {
                None
            }
        })
        else {
            Err(anyhow::anyhow!("no ifname `{ifname}` found"))?
        };

        let Some(gateway) = get_gateway_ipv4_by_ifname(ifname)?
        else {
            Err(anyhow::anyhow!("no gateway found for `{ifname}`"))?
        };

        let to = SockAddrLL {
            family: SaFamily::Packet,
            protocol: EthTypeKind::ARP.into(),
            ifindex,
            hatype: HTypeKind::Ethernet10Mb.into(),
            pkttype: PktType::Host,
            halen: size_of::<Mac>() as u8,
            addr: hwa.into(),
        };

        let hwt = get_ifhwaddr(ifname)?.ty;
        let mtu = get_ifmtu(ifname)? as u16;

        bind(sd.as_fd(), to.into())?;

        Ok(Self {
            name: ifname.to_owned(),
            ip,
            netmask,
            hwt,
            hwa,
            mtu,
            sd,
            to,
            gateway,
        })
    }

    pub fn input(&self) -> anyhow::Result<()> {
        // ethernet frame
        let mut ef: [u8; Eth::FRAME_LEN] = unsafe { core::mem::zeroed() };

        let readn = read(self.sd.as_fd(), &mut ef, Eth::FRAME_LEN)?;

        let data = RawBuf::new_from_slice(&ef[..readn]);

        let mut dataref = data.to_ref();

        let skb = SkBuff::default();

        skb.data.set(data).unwrap();
        skb.phy.set(dataref).unwrap();

        // Linux kernel strip off padding of Ethernet frame
        if dataref.rem_len() < size_of::<Eth>() {
            Err(anyhow!("Uncomplete Ethernet Frame {}",dataref.rem_len()))?
        }

        let ethh = dataref.consume::<Eth>().read_unaligned();
        skb.nh.set(dataref).unwrap();

        if ethh.dst != Mac::BROADCAST && ethh.dst != self.hwa {
            trace!("Filter Ethernet Frame from {:?}", ethh.dst);
            return Ok(());
        }

        let EthProtoKind::EthType(eth_type_spec) = ethh.proto.into_kind()
        else {
            match ethh.proto.into_kind() {
                EthProtoKind::Len(_) => {
                    warn!("Found Legacy 802.3 Ethernet Frame");
                }
                EthProtoKind::Undefined(x) => {
                    warn!("Undefined EthProto {x}");
                }
                _ => unreachable!(),
            }
            return Ok(());
        };

        match eth_type_spec {
            OSIEtHTypeKind::IPv4 => {
                if dataref.rem_len() < size_of::<IPv4>() {
                    Err(anyhow!("Uncomplete IPv4 header"))?
                }

                let iph = dataref.cast::<IPv4>().read_unaligned();

                ARP_TBL.write().unwrap().insert(iph.src.into(), ethh.src);

                trace!("Incomming Network IPv4 handled {:?}", iph.src);

                /* ip input */
            }
            OSIEtHTypeKind::ARP => {
                /* arp input */
                self.arp_input(skb)?;
            }
            _ => {
                trace!("Found {eth_type_spec:?} package, skip")
            }
        }

        Ok(())
    }
}
