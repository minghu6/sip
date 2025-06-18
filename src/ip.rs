use std::net::Ipv4Addr;

use m6ptr::Ptr;
use osimodel::network::{
    InetCkSum,
    ip::{FlagsAndOff, IHLAndVer, IPv4, Id, ProtocolKind, TTL, ToS, TotLen},
};

use crate::{dev::NetDevice, skbuff::SkBuff};



////////////////////////////////////////////////////////////////////////////////
//// Implementations


impl NetDevice {
    /// TDDO
    pub fn ip_output(
        &self,
        skb: Ptr<SkBuff>,
        src: Ipv4Addr,
        dst: Ipv4Addr,
    ) -> anyhow::Result<()> {
        let _rawbuf = *skb.nh.get().unwrap();

        let _iph = IPv4 {
            ihl_v: IHLAndVer::with_options_bytes(0),
            tos: ToS::default(),
            totlen: TotLen::new_with_tot_len(20),
            id: Id::new(0),
            flags_off: FlagsAndOff::default(),
            ttl: TTL::default(),
            proto: ProtocolKind::UDP.into(),
            cksum: InetCkSum::default(),
            src: src.into(),
            dst: dst.into(),
        }
        .checksummed();


        Ok(())
    }
}
