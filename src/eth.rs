use std::os::fd::AsFd;

use linuxc::socket::sendto;
use log::trace;
use m6ptr::Ptr;

use crate::{dev::NetDevice, skbuff::SkBuff};



impl NetDevice {
    pub fn linkoutput(&self, skb: Ptr<SkBuff>) -> anyhow::Result<()> {
        let mut skb = skb;

        loop {
            let n = sendto(
                self.sd.as_fd(),
                skb.phy.get().unwrap().cur_slice(),
                Default::default(),
                Default::default(),
            )?;

            trace!("linkoutput send {n} bytes");

            if let Some(next) = skb.next.as_ref() {
                skb = next.ptr();
            }
            else {
                break
            }
        }

        Ok(())
    }
}
