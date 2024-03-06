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
use crate::ip::v6::Packet;

use core::net::Ipv6Addr;
/// IPv6 packet builder.
#[derive(Debug)]
pub struct Builder<B: Buffer = buffer::Dynamic> {
    buffer: B,
    finalizer: Finalization,
}

impl<B: Buffer + AsMut<[u8]>> Builder<B> {
    pub fn source(mut self, ip: Ipv6Addr) -> Result<Self> {
        Packet::unchecked(self.buffer.data_mut()).set_source(ip)?;
        Ok(self)
    }
    pub fn destination(mut self, ip: Ipv6Addr) -> Result<Self> {
        Packet::unchecked(self.buffer.data_mut()).set_destination(ip)?;
        Ok(self)
    }
}

impl<B: Buffer> Build<B> for Builder<B> {
    fn with(mut buffer: B) -> Result<Self> {
        //use crate::size::header::Min;
        // 40 bytes is the length of the IPv6 header
        buffer.next(40)?;

        // Set version to 4 and header length to the minimum.
        //
        // XXX: This is needed for shit to work. The builder uses setters on the
        //      `ip::v6::Packet` which expect the header length to be set. While the TCP
        //      and UDP builders base their finalizer on extracting the parent IP
        //      packet.
        buffer.data_mut()[0] = (6 << 4);

        Ok(Builder {
            buffer: buffer,
            finalizer: Default::default(),
        })
    }

    fn finalizer(&mut self) -> &mut Finalization {
        &mut self.finalizer
    }

    fn build(self) -> Result<B::Inner> {
        //self.prepare();

		let mut buffer = self.buffer.into_inner();
		self.finalizer.finalize(buffer.as_mut())?;
		Ok(buffer)
    }
}

impl Default for Builder<buffer::Dynamic> {
    fn default() -> Self {
        Builder::with(buffer::Dynamic::default()).unwrap()
    }
}
