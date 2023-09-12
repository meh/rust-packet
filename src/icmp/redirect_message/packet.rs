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

use std::fmt;
use std::net::Ipv4Addr;

use crate::error::*;
use crate::icmp::Kind;
use crate::ip;
use crate::packet::{AsPacket, AsPacketMut, Packet as P, PacketMut as PM};
use crate::size;

/// Redirect Message packet parser.
pub struct Packet<B> {
    buffer: B,
}

sized!(Packet,
header {
    min:  8,
    max:  8,
    size: 8,
}

payload {
    min:  <ip::v4::Packet<()> as size::header::Min>::min(),
    max:  <ip::v4::Packet<()> as size::header::Max>::max(),
    size: p => {
        if let Ok(ip) = p.packet() {
            size::header::Size::size(&ip)
        }
        else {
            p.buffer.as_ref().len() - 8
        }
    },
});

impl<B: AsRef<[u8]>> fmt::Debug for Packet<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("icmp::redirect_message::Packet")
            .field("gateway", &self.gateway())
            .field("packet", &self.packet())
            .finish()
    }
}

impl<B: AsRef<[u8]>> Packet<B> {
    /// Create a Redirect Message packet without checking the buffer contents.
    pub fn unchecked(buffer: B) -> Packet<B> {
        Packet { buffer }
    }

    /// Parse a Redirect Message packet, checking the buffer contents are correct.
    pub fn new(buffer: B) -> Result<Packet<B>> {
        use crate::size::header::Min;

        let packet = Packet::unchecked(buffer);

        if packet.buffer.as_ref().len() < Self::min() {
            Err(Error::SmallBuffer)?
        }

        match Kind::from(packet.buffer.as_ref()[0]) {
            Kind::RedirectMessage => (),

            _ => Err(Error::InvalidPacket)?,
        }

        Ok(packet)
    }
}

impl<B: AsRef<[u8]>> Packet<B> {
    /// Convert the packet to its owned version.
    ///
    /// # Notes
    ///
    /// It would be nice if `ToOwned` could be implemented, but `Packet` already
    /// implements `Clone` and the impl would conflict.
    pub fn to_owned(&self) -> Packet<Vec<u8>> {
        Packet::unchecked(self.buffer.as_ref().to_vec())
    }
}

impl<B: AsRef<[u8]>> AsRef<[u8]> for Packet<B> {
    fn as_ref(&self) -> &[u8] {
        use crate::size::Size;

        &self.buffer.as_ref()[..self.size()]
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]> for Packet<B> {
    fn as_mut(&mut self) -> &mut [u8] {
        use crate::size::Size;

        let size = self.size();
        &mut self.buffer.as_mut()[..size]
    }
}

impl<'a, B: AsRef<[u8]>> AsPacket<'a, Packet<&'a [u8]>> for B {
    fn as_packet(&self) -> Result<Packet<&[u8]>> {
        Packet::new(self.as_ref())
    }
}

impl<'a, B: AsRef<[u8]> + AsMut<[u8]>> AsPacketMut<'a, Packet<&'a mut [u8]>> for B {
    fn as_packet_mut(&mut self) -> Result<Packet<&mut [u8]>> {
        Packet::new(self.as_mut())
    }
}

impl<B: AsRef<[u8]>> P for Packet<B> {
    fn split(&self) -> (&[u8], &[u8]) {
        self.buffer.as_ref().split_at(8)
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> PM for Packet<B> {
    fn split_mut(&mut self) -> (&mut [u8], &mut [u8]) {
        self.buffer.as_mut().split_at_mut(8)
    }
}

impl<B: AsRef<[u8]>> Packet<B> {
    /// Gateway to redirect the packet to.
    pub fn gateway(&self) -> Ipv4Addr {
        Ipv4Addr::new(
            self.buffer.as_ref()[4],
            self.buffer.as_ref()[5],
            self.buffer.as_ref()[6],
            self.buffer.as_ref()[7],
        )
    }

    /// Packet to redirect.
    pub fn packet(&self) -> Result<ip::v4::Packet<&[u8]>> {
        ip::v4::Packet::new(&self.buffer.as_ref()[8..])
    }
}
