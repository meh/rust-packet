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

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::fmt;
use std::io::Cursor;

use crate::error::*;
use crate::ip;
use crate::packet::{AsPacket, AsPacketMut, Packet as P, PacketMut as PM};
use crate::udp::checksum;

/// UDP packet parser.
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
    min:  0,
    max:  u16::max_value() as usize - 8,
    size: p => (p.length() as usize).saturating_sub(8),
});

impl<B: AsRef<[u8]>> fmt::Debug for Packet<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("udp::Packet")
            .field("source", &self.source())
            .field("destination", &self.destination())
            .field("checksum", &self.length())
            .field("checksum", &self.checksum())
            .field("payload", &self.payload())
            .finish()
    }
}

impl<B: AsRef<[u8]>> Packet<B> {
    /// Create a UDP packet without checking.
    pub fn unchecked(buffer: B) -> Packet<B> {
        Packet { buffer }
    }

    /// Parse a UDP packet without checking the payload.
    pub fn no_payload(buffer: B) -> Result<Packet<B>> {
        use crate::size::header::Min;

        let packet = Packet::unchecked(buffer);

        if packet.buffer.as_ref().len() < Self::min() {
            Err(Error::SmallBuffer)?
        }

        Ok(packet)
    }

    /// Parse a UDP packet, checking the buffer contents are correct.
    pub fn new(buffer: B) -> Result<Packet<B>> {
        let packet = Packet::no_payload(buffer)?;

        if packet.buffer.as_ref().len() < packet.length() as usize {
            Err(Error::SmallBuffer)?
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
        Packet {
            buffer: self.buffer.as_ref().to_vec(),
        }
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
        use crate::size::payload::Size;

        let header = 8;
        let payload = self.size();

        let buffer = self.buffer.as_ref();
        let buffer = if buffer.len() < header + payload {
            buffer
        } else {
            &buffer[..header + payload]
        };

        buffer.split_at(header)
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> PM for Packet<B> {
    fn split_mut(&mut self) -> (&mut [u8], &mut [u8]) {
        use crate::size::payload::Size;

        let header = 8;
        let payload = self.size();

        let buffer = self.buffer.as_mut();
        let buffer = if buffer.len() < header + payload {
            buffer
        } else {
            &mut buffer[..header + payload]
        };

        buffer.split_at_mut(header)
    }
}

impl<B: AsRef<[u8]>> Packet<B> {
    /// Source port.
    pub fn source(&self) -> u16 {
        (&self.buffer.as_ref()[0..])
            .read_u16::<BigEndian>()
            .unwrap()
    }

    /// Destination port.
    pub fn destination(&self) -> u16 {
        (&self.buffer.as_ref()[2..])
            .read_u16::<BigEndian>()
            .unwrap()
    }

    /// Total length of the packet.
    pub fn length(&self) -> u16 {
        (&self.buffer.as_ref()[4..])
            .read_u16::<BigEndian>()
            .unwrap()
    }

    /// Checksum of the packet.
    pub fn checksum(&self) -> u16 {
        (&self.buffer.as_ref()[6..])
            .read_u16::<BigEndian>()
            .unwrap()
    }

    /// Verify the packet is valid by calculating the checksum.
    pub fn is_valid<I: AsRef<[u8]>>(&self, ip: &ip::Packet<I>) -> bool {
        checksum(ip, self.buffer.as_ref()) == self.checksum()
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> Packet<B> {
    /// Source port.
    pub fn set_source(&mut self, value: u16) -> Result<&mut Self> {
        Cursor::new(&mut self.header_mut()[0..]).write_u16::<BigEndian>(value)?;

        Ok(self)
    }

    /// Destination port.
    pub fn set_destination(&mut self, value: u16) -> Result<&mut Self> {
        Cursor::new(&mut self.header_mut()[2..]).write_u16::<BigEndian>(value)?;

        Ok(self)
    }

    /// Create a checksumed setter.
    pub fn checked<'a, 'b, BI: AsRef<[u8]> + 'b>(
        &'a mut self,
        ip: &'b ip::Packet<BI>,
    ) -> Checked<'a, 'b, B, BI> {
        Checked { packet: self, ip }
    }

    /// Set the checksum value.
    pub fn set_checksum(&mut self, value: u16) -> Result<&mut Self> {
        Cursor::new(&mut self.header_mut()[6..]).write_u16::<BigEndian>(value)?;

        Ok(self)
    }

    /// Recalculate and set the checksum value.
    pub fn update_checksum<BI: AsRef<[u8]>>(&mut self, ip: &ip::Packet<BI>) -> Result<&mut Self> {
        let checksum = checksum(ip, self.buffer.as_ref());
        self.set_checksum(checksum)
    }
}

/// Checked wrapper for UDP packets.
///
/// # Note
///
/// The checksum recalculation happens on `Drop`, so don't leak it.
pub struct Checked<'a, 'b, BP, BI>
where
    BP: AsRef<[u8]> + AsMut<[u8]> + 'a,
    BI: AsRef<[u8]> + 'b,
{
    packet: &'a mut Packet<BP>,
    ip: &'b ip::Packet<BI>,
}

impl<'a, 'b, BP, BI> Checked<'a, 'b, BP, BI>
where
    BP: AsRef<[u8]> + AsMut<[u8]> + 'a,
    BI: AsRef<[u8]> + 'b,
{
    /// Source port.
    pub fn set_source(&mut self, value: u16) -> Result<&mut Self> {
        self.packet.set_source(value)?;
        Ok(self)
    }

    /// Destination port.
    pub fn set_destination(&mut self, value: u16) -> Result<&mut Self> {
        self.packet.set_destination(value)?;
        Ok(self)
    }
}

impl<'a, 'b, BP, BI> Drop for Checked<'a, 'b, BP, BI>
where
    BP: AsRef<[u8]> + AsMut<[u8]> + 'a,
    BI: AsRef<[u8]> + 'b,
{
    fn drop(&mut self) {
        self.packet.update_checksum(self.ip).unwrap();
    }
}

#[cfg(test)]
mod test {
    use crate::ip;
    use crate::packet::{Packet, PacketMut};
    use crate::udp;

    #[test]
    fn values() {
        let raw = [
            0x45u8, 0x00, 0x00, 0x42, 0x47, 0x07, 0x40, 0x00, 0x40, 0x11, 0x6e, 0xcc, 0xc0, 0xa8,
            0x01, 0x89, 0xc0, 0xa8, 0x01, 0xfe, 0xba, 0x2f, 0x00, 0x35, 0x00, 0x2e, 0x1d, 0xf8,
            0xbc, 0x81, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x61,
            0x70, 0x69, 0x0c, 0x73, 0x74, 0x65, 0x61, 0x6d, 0x70, 0x6f, 0x77, 0x65, 0x72, 0x65,
            0x64, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x00, 0x01,
        ];

        let ip = ip::v4::Packet::new(&raw[..]).unwrap();
        let udp = udp::Packet::new(ip.payload()).unwrap();

        assert!(ip.is_valid());
        assert!(udp.is_valid(&ip::Packet::from(&ip)));

        assert_eq!(udp.destination(), 53);
    }

    #[test]
    fn mutable() {
        let mut raw = [
            0x45u8, 0x00, 0x00, 0x42, 0x47, 0x07, 0x40, 0x00, 0x40, 0x11, 0x6e, 0xcc, 0xc0, 0xa8,
            0x01, 0x89, 0xc0, 0xa8, 0x01, 0xfe, 0xba, 0x2f, 0x00, 0x35, 0x00, 0x2e, 0x1d, 0xf8,
            0xbc, 0x81, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x61,
            0x70, 0x69, 0x0c, 0x73, 0x74, 0x65, 0x61, 0x6d, 0x70, 0x6f, 0x77, 0x65, 0x72, 0x65,
            0x64, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x00, 0x01,
        ];

        let mut ip = ip::v4::Packet::new(&mut raw[..]).unwrap();
        let (ip, udp) = ip.split_mut();
        let ip = ip::Packet::from(ip::v4::Packet::unchecked(ip));
        let mut udp = udp::Packet::new(udp).unwrap();

        assert!(udp.is_valid(&ip));
        assert_eq!(udp.destination(), 53);

        udp.set_destination(9001).unwrap();
        assert_eq!(udp.destination(), 9001);
        assert!(!udp.is_valid(&ip));

        udp.update_checksum(&ip).unwrap();
        assert!(udp.is_valid(&ip));
    }

    #[test]
    fn mutable_checked() {
        let mut raw = [
            0x45u8, 0x00, 0x00, 0x42, 0x47, 0x07, 0x40, 0x00, 0x40, 0x11, 0x6e, 0xcc, 0xc0, 0xa8,
            0x01, 0x89, 0xc0, 0xa8, 0x01, 0xfe, 0xba, 0x2f, 0x00, 0x35, 0x00, 0x2e, 0x1d, 0xf8,
            0xbc, 0x81, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x61,
            0x70, 0x69, 0x0c, 0x73, 0x74, 0x65, 0x61, 0x6d, 0x70, 0x6f, 0x77, 0x65, 0x72, 0x65,
            0x64, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x00, 0x01,
        ];

        let mut ip = ip::v4::Packet::new(&mut raw[..]).unwrap();
        let (ip, udp) = ip.split_mut();
        let ip = ip::Packet::from(ip::v4::Packet::unchecked(ip));
        let mut udp = udp::Packet::new(udp).unwrap();

        assert!(udp.is_valid(&ip));
        assert_eq!(udp.destination(), 53);

        udp.checked(&ip).set_destination(9001).unwrap();
        assert_eq!(udp.destination(), 9001);
        assert!(udp.is_valid(&ip));
    }
}
