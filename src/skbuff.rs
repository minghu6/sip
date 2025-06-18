
use std::cell::OnceCell;

use m6ptr::{LazyStatic, OwnedPtr};
use m6io::rawbuf::{RawBuf, RawBufRef};

use crate::dev::NetDevice;

////////////////////////////////////////////////////////////////////////////////
//// Constant Variables


////////////////////////////////////////////////////////////////////////////////
//// Static Variables

pub static SKBUFF_TBL: LazyStatic<Option<SkBuff>> = LazyStatic::new(|| None);

////////////////////////////////////////////////////////////////////////////////
//// Structures

#[derive(Default)]
pub struct SkBuff {
    /// size_of::<Option<Box<T>>> = size_of::<usize>
    pub next: Option<OwnedPtr<Self>>,
    /// size_of::<Option<Box<T>>> = size_of::<usize>
    pub data: OnceCell<RawBuf>,
    pub th: OnceCell<RawBufRef>,
    pub nh: OnceCell<RawBufRef>,
    pub phy: OnceCell<RawBufRef>
}

pub struct SkBuffBuilder {

}

////////////////////////////////////////////////////////////////////////////////
//// Implementations

impl SkBuff {
    pub fn with_capacity(capacity: usize) -> Self {
        let data = RawBuf::with_capacity(capacity);
        let it = Self::default();

        it.phy.set(data.to_ref()).unwrap();
        it.data.set(data).unwrap();

        it
    }
}

impl NetDevice {

}


#[cfg(test)]
mod tests {

}

