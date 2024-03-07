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

use crate::error::*;
use crate::packet::{AsPacket, AsPacketMut, Packet as P, PacketMut as PM};
use std::convert::TryInto;
use std::fmt;
use std::net::Ipv6Addr;

/// IPv6 packet parser.
#[derive(Clone)]
pub struct Packet<B> {
    buffer: B,
}

sized!(Packet,
header {
    min:  0,
    max:  0,
    size: 0,
}

payload {
    min:  0,
    max:  0,
    size: 0,
});

impl<B: AsRef<[u8]>> fmt::Debug for Packet<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ip::v6::Packet").finish()
    }
}
impl<B: AsRef<[u8]> + AsMut<[u8]>> Packet<B> {
    pub fn set_destination(&mut self, value: Ipv6Addr) -> Result<&mut Self> {
        self.header_mut()[24..40].copy_from_slice(&value.octets());
        Ok(self)
    }

    pub fn set_source(&mut self, value: Ipv6Addr) -> Result<&mut Self> {
        self.header_mut()[8..24].copy_from_slice(&value.octets());
        Ok(self)
    }
}
impl<B: AsRef<[u8]>> Packet<B> {
    /// Create an IPv6 packet without checking the buffer.
    pub fn unchecked(buffer: B) -> Packet<B> {
        Packet { buffer }
    }

    pub fn source(&self) -> Ipv6Addr {
        let bytes: [u8; 16] = self.buffer.as_ref()[8..24].try_into().unwrap();
        bytes.into()
    }
    pub fn destination(&self) -> Ipv6Addr {
        let bytes: [u8; 16] = self.buffer.as_ref()[24..40].try_into().unwrap();
        bytes.into()
    }

    /// Parse an IPv6 packet without checking the payload.
    pub fn no_payload(buffer: B) -> Result<Packet<B>> {
        use crate::size::header::Min;

        let packet = Packet::unchecked(buffer);

        if packet.buffer.as_ref().len() < Self::min() {
            Err(Error::SmallBuffer)?
        }

        if packet.buffer.as_ref()[0] >> 4 != 6 {
            Err(Error::InvalidPacket)?
        }

        Ok(packet)
    }

    /// Parse an IPv6 packet, checking the buffer contents are correct.
    pub fn new(buffer: B) -> Result<Packet<B>> {
        Packet::no_payload(buffer)
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
        &[]
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]> for Packet<B> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut []
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
        (&[], &[])
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> PM for Packet<B> {
    fn split_mut(&mut self) -> (&mut [u8], &mut [u8]) {
        self.buffer.as_mut().split_at_mut(40)
    }
}

#[test]
fn iptest() {
    use crate::builder::Builder;
    use std::str::FromStr;
    let source = Ipv6Addr::from_str("::1").unwrap();
    let destination = Ipv6Addr::from_str("::1").unwrap();
    let packet = crate::ip::v6::Builder::default();
    println!("{:?}", packet);
    let pkt = Packet::new(
        packet
            .source(source)
            .unwrap()
            .destination(destination)
            .unwrap()
            .build()
            .unwrap(),
    )
    .unwrap();

    assert_eq!(pkt.source(), source);
    assert_eq!(pkt.destination(), destination);
}
