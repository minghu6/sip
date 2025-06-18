use std::net::Ipv4Addr;

use anyhow::anyhow;
use derive_more::derive::{Deref, DerefMut};
use log::trace;
use m6ptr::{LazyStatic, OwnedPtr};
use osimodel::datalink::{
    Eth, EthTypeKind, Mac,
    arp::{ARP, ARPOpKind, HTypeKind},
};
use time::{Duration, UtcDateTime};

use crate::{dev::NetDevice, skbuff::SkBuff};

////////////////////////////////////////////////////////////////////////////////
//// Constant Variables

pub const ARP_TBL_SZ: usize = 10;
pub const ARPLIVE: Duration = Duration::minutes(10);

////////////////////////////////////////////////////////////////////////////////
//// Static Variables

pub static ARP_TBL: LazyStatic<ARPRecTbl> =
    LazyStatic::new(|| ARPRecTbl::new());

////////////////////////////////////////////////////////////////////////////////
//// Structures

#[derive(Debug, Clone, Copy)]
pub struct ARPRecord {
    pub is_valid: bool,
    pub age: u16,
    pub ip: Ipv4Addr,
    pub mac: Mac,
    pub ctime: UtcDateTime,
}

/// Using TRLU replace policy
#[derive(Debug, Deref, DerefMut, Clone, Copy)]
pub struct ARPRecTbl {
    value: [ARPRecord; ARP_TBL_SZ],
}

////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl Default for ARPRecord {
    fn default() -> Self {
        Self {
            is_valid: Default::default(),
            age: Default::default(),
            ip: Ipv4Addr::from_bits(0),
            mac: Default::default(),
            ctime: UtcDateTime::from_unix_timestamp(0).unwrap(),
        }
    }
}

impl ARPRecTbl {
    pub fn new() -> Self {
        Self {
            value: Default::default(),
        }
    }

    pub fn get_mut_and_update(
        &mut self,
        ip: Ipv4Addr,
    ) -> Option<&mut ARPRecord> {
        let now = UtcDateTime::now();

        for rec in self.iter_mut().filter(|rec| rec.is_valid) {
            if rec.ctime + ARPLIVE < now {
                rec.is_valid = false;
                continue;
            }

            if rec.ip == ip {
                rec.age = 0;
                return Some(rec);
            }

            if rec.age < u16::MAX {
                rec.age += 1;
            }
        }

        None
    }

    pub fn insert(&mut self, ip: Ipv4Addr, mac: Mac) {
        let now = UtcDateTime::now();

        if let Some(rec) = self.get_mut_and_update(ip) {
            rec.mac = mac;
            rec.ctime = now;
            return;
        }

        let rec = if let Some(rec) = self.iter_mut().find(|rec| !rec.is_valid)
        {
            rec
        }
        else {
            self.iter_mut().max_by_key(|rec| rec.age).unwrap()
        };

        rec.is_valid = true;
        rec.age = 0;
        rec.ip = ip;
        rec.ctime = now;
        rec.mac = mac;
    }
}


impl NetDevice {
    pub fn arp_input(&self, skb: SkBuff) -> anyhow::Result<()> {
        let mut arpbuf = *skb.nh.get().unwrap();

        if arpbuf.rem_len() < size_of::<ARP>() {
            Err(anyhow!("Uncomplete ARP packet"))?
        }

        let arp_ref = arpbuf.consume::<ARP>();
        let arph = arp_ref.read_unaligned();

        if arph.tpa == self.ip.into() {
            trace!("Incomming Network ARP handled {}\t\n{arph:#?}", arph.tpa);
        }
        else {
            trace!("Filter Network ARP Package from {}", arph.tpa)
        }

        match arph.op.to_kind() {
            ARPOpKind::Request => self.arp_request(arph.tpa.into())?,
            ARPOpKind::Reply => (),
            _ => (),
        }

        ARP_TBL.get_mut().unwrap().insert(arph.spa.into(), arph.sha);


        Ok(())
    }

    pub fn arp_output(
        &self,
        op: ARPOpKind,
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_mac: Mac,
        dst_mac: Mac,
        target_mac: Mac,
    ) -> anyhow::Result<()> {
        let skb = SkBuff::with_capacity(Eth::ZLEN);

        let mut rawbuf = *skb.phy.get().unwrap();

        let ethh = Eth {
            dst: dst_mac,
            src: src_mac,
            proto: EthTypeKind::ARP.into(),
        };

        rawbuf.consume::<Eth>().write_unaligned(ethh);
        skb.nh.set(rawbuf).unwrap();

        let arph = ARP {
            htype: HTypeKind::Ethernet10Mb.into(),
            // yes it's not ARP
            ptype: EthTypeKind::IPv4.into(),
            hlen: size_of::<Mac>().try_into().unwrap(),
            plen: size_of::<Ipv4Addr>().try_into().unwrap(),
            op: op.into(),
            sha: src_mac,
            spa: src_ip.into(),
            tha: target_mac,
            tpa: dst_ip.into(),
        };
        rawbuf.consume::<ARP>().write_unaligned(arph);

        trace!("Output: {arph:#?}");

        let owned = OwnedPtr::new(skb);

        self.linkoutput(owned.ptr())?;

        Ok(())
    }

    pub fn arp_request(&self, mut tip: Ipv4Addr) -> anyhow::Result<()> {
        /* query if it's in same subnet */

        if tip & self.netmask != self.ip & self.netmask {
            tip = self.netmask;
        }

        self.arp_output(
            ARPOpKind::Request,
            self.ip,
            tip,
            self.hwa,
            Mac::ZERO,
            Mac::ZERO,
        )?;

        Ok(())
    }
}
