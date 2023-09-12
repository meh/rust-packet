//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//                    Version 2, December 2004
//
// Copyleft (ↄ) meh. <meh@schizofreni.co> | http://meh.schizofreni.co
//
// Everyone is permitted to copy and distribute verbatim or modified
// copies of this license document, and changing it is allowed as long
// as the name is changed.
//
//            DO WHAT THE FUCK YOU WANT TO PUBLIC LICENSE
//   TERMS AND CONDITIONS FOR COPYING, DISTRIBUTION AND MODIFICATION
//
//  0. You just DO WHAT THE FUCK YOU WANT TO.

use crate::buffer::{self, Buffer};
use crate::builder::{Builder as Build, Finalization};
use crate::error::*;
use crate::ip::{v4, v6};

/// Generic IP packet builder.
#[derive(Debug)]
pub struct Builder<B: Buffer = buffer::Dynamic> {
    buffer: B,
    finalizer: Finalization,
}

impl<B: Buffer> Build<B> for Builder<B> {
    fn with(buffer: B) -> Result<Self> {
        Ok(Builder {
            buffer,
            finalizer: Default::default(),
        })
    }

    fn finalizer(&mut self) -> &mut Finalization {
        &mut self.finalizer
    }

    fn build(self) -> Result<B::Inner> {
        Err(Error::InvalidPacket)
    }
}

impl Default for Builder<buffer::Dynamic> {
    fn default() -> Self {
        Builder::with(buffer::Dynamic::default()).unwrap()
    }
}

impl<B: Buffer> Builder<B> {
    /// Create an IPv4 packet.
    pub fn v4(self) -> Result<v4::Builder<B>> {
        let mut v4 = v4::Builder::with(self.buffer)?;
        v4.finalizer().extend(self.finalizer);

        Ok(v4)
    }

    /// Create an IPv6 packet.
    pub fn v6(self) -> Result<v6::Builder<B>> {
        let mut v6 = v6::Builder::with(self.buffer)?;
        v6.finalizer().extend(self.finalizer);

        Ok(v6)
    }
}
