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
use std::io::Cursor;
use std::net::Ipv4Addr;
use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};

use error::*;
use packet::{Packet as P, PacketMut as PM, AsPacket, AsPacketMut};
use ip::Protocol;
use ip::v4::Flags;
use ip::v4::option;
use ip::v4::checksum;

/// IPv4 packet parser.
#[derive(Copy, Clone)]
pub struct Packet<B> {
	buffer: B,
}

sized!(Packet,
	header {
		min:  20,
		max:  60,
		size: p => p.header() as usize * 4,
	}

	payload {
		min:  0,
		max:  u16::max_value() as usize - 60,
		size: p => (p.length() as usize).saturating_sub(p.header() as usize * 4),
	});

impl<B: AsRef<[u8]>> fmt::Debug for Packet<B> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct(if self.is_valid() { "ip::v4::Packet" } else { "ip::v4::Packet!" })
			.field("version", &self.version())
			.field("header", &self.header())
			.field("dscp", &self.dscp())
			.field("ecn", &self.ecn())
			.field("length", &self.length())
			.field("id", &self.id())
			.field("flags", &self.flags())
			.field("offset", &self.offset())
			.field("ttl", &self.ttl())
			.field("protocol", &self.protocol())
			.field("checksum", &self.checksum())
			.field("source", &self.source())
			.field("destination", &self.destination())
			.field("payload", &self.payload())
			.finish()
	}
}

impl<B: AsRef<[u8]>> Packet<B> {
	/// Create an IPv4 packet without checking the buffer.
	pub fn unchecked(buffer: B) -> Packet<B> {
		Packet { buffer }
	}

	/// Parse an IPv4 packet without checking the payload.
	pub fn no_payload(buffer: B) -> Result<Packet<B>> {
		use size::header::Min;

		let packet = Packet::unchecked(buffer);

		if packet.buffer.as_ref().len() < Self::min() {
			return Err(ErrorKind::SmallBuffer.into());
		}

		if packet.buffer.as_ref()[0] >> 4 != 4 {
			return Err(ErrorKind::InvalidPacket.into());
		}

		if packet.buffer.as_ref().len() < packet.header() as usize * 4 {
			return Err(ErrorKind::SmallBuffer.into());
		}

		Ok(packet)
	}

	/// Parse an IPv4 packet, checking the buffer contents are correct.
	pub fn new(buffer: B) -> Result<Packet<B>> {
		let packet = Packet::no_payload(buffer)?;

		if packet.buffer.as_ref().len() < packet.length() as usize {
			return Err(ErrorKind::SmallBuffer.into());
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
		use size::Size;

		&self.buffer.as_ref()[.. self.size()]
	}
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]> for Packet<B> {
	fn as_mut(&mut self) -> &mut [u8] {
		use size::Size;

		let size = self.size();
		&mut self.buffer.as_mut()[.. size]
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
		use size::payload::Size;

		let header  = self.header() as usize * 4;
		let payload = self.size();

		let buffer = self.buffer.as_ref();
		let buffer = if buffer.len() < header + payload {
			buffer
		}
		else {
			&buffer[.. header + payload]
		};

		buffer.split_at(header)
	}
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> PM for Packet<B> {
	fn split_mut(&mut self) -> (&mut [u8], &mut [u8]) {
		use size::payload::Size;

		let header  = self.header() as usize * 4;
		let payload = self.size();

		let buffer = self.buffer.as_mut();
		let buffer = if buffer.len() < header + payload {
			buffer
		}
		else {
			&mut buffer[.. header + payload]
		};

		buffer.split_at_mut(header)
	}
}

impl<B: AsRef<[u8]>> Packet<B> {
	/// IP protocol version, will always be 4.
	pub fn version(&self) -> u8 {
		self.buffer.as_ref()[0] >> 4
	}

	/// Length of the IPv4 header in 32 bit words.
	pub fn header(&self) -> u8 {
		self.buffer.as_ref()[0] & 0b1111
	}

	/// DSCP value.
	pub fn dscp(&self) -> u8 {
		self.buffer.as_ref()[1] >> 2
	}

	/// ECN value.
	pub fn ecn(&self) -> u8 {
		self.buffer.as_ref()[1] & 0b11
	}

	/// Total length of the packet in octets.
	pub fn length(&self) -> u16 {
		(&self.buffer.as_ref()[2 ..]).read_u16::<BigEndian>().unwrap()
	}

	/// ID of the packet.
	pub fn id(&self) -> u16 {
		(&self.buffer.as_ref()[4 ..]).read_u16::<BigEndian>().unwrap()
	}

	/// Flags of the packet.
	pub fn flags(&self) -> Flags {
		Flags::from_bits((&self.buffer.as_ref()[6 ..])
			.read_u16::<BigEndian>().unwrap() >> 13).unwrap()
	}

	/// Offset of the packet.
	pub fn offset(&self) -> u16 {
		(&self.buffer.as_ref()[6 ..]).read_u16::<BigEndian>().unwrap() & 0x1fff
	}

	/// Time to Live for the packet.
	pub fn ttl(&self) -> u8 {
		self.buffer.as_ref()[8]
	}

	/// Protocol of the inner packet.
	pub fn protocol(&self) -> Protocol {
		self.buffer.as_ref()[9].into()
	}

	/// Checksum of the packet.
	pub fn checksum(&self) -> u16 {
		(&self.buffer.as_ref()[10 ..]).read_u16::<BigEndian>().unwrap()
	}

	/// Verify the packet is valid by calculating the checksum.
	pub fn is_valid(&self) -> bool {
		checksum(P::header(self)) == self.checksum()
	}

	/// Source IP address.
	pub fn source(&self) -> Ipv4Addr {
		Ipv4Addr::new(
			self.buffer.as_ref()[12],
			self.buffer.as_ref()[13],
			self.buffer.as_ref()[14],
			self.buffer.as_ref()[15])
	}

	/// Destination IP address.
	pub fn destination(&self) -> Ipv4Addr {
		Ipv4Addr::new(
			self.buffer.as_ref()[16],
			self.buffer.as_ref()[17],
			self.buffer.as_ref()[18],
			self.buffer.as_ref()[19])
	}

	/// IP options for the packet.
	pub fn options(&self) -> OptionIter {
		OptionIter {
			buffer: &self.buffer.as_ref()[20 .. (self.header() as usize * 4)],
		}
	}
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> Packet<B> {
	/// Differentiated Services Code Point.
	pub fn set_dscp(&mut self, value: u8) -> Result<&mut Self> {
		if value > 0b11_1111 {
			return Err(ErrorKind::InvalidValue.into());
		}

		let old = self.buffer.as_ref()[1];
		self.buffer.as_mut()[1] = (old & 0b11) | value << 2;

		Ok(self)
	}

	/// Explicit Congestion Notification.
	pub fn set_ecn(&mut self, value: u8) -> Result<&mut Self> {
		if value > 0b11 {
			return Err(ErrorKind::InvalidValue.into());
		}

		let old = self.buffer.as_ref()[1];
		self.buffer.as_mut()[1] = (old & 0b11_1111) | value;

		Ok(self)
	}

	/// Packet ID.
	pub fn set_id(&mut self, value: u16) -> Result<&mut Self> {
		Cursor::new(&mut self.buffer.as_mut()[4 ..])
			.write_u16::<BigEndian>(value)?;

		Ok(self)
	}

	/// Packet flags.
	pub fn set_flags(&mut self, value: Flags) -> Result<&mut Self> {
		Cursor::new(&mut self.header_mut()[6 ..])
			.write_u16::<BigEndian>(value.bits())?;

		Ok(self)
	}

	/// Packet fragment offset.
	pub fn set_offset(&mut self, value: u16) -> Result<&mut Self> {
		Cursor::new(&mut self.header_mut()[6 ..])
			.write_u16::<BigEndian>(value)?;

		Ok(self)
	}

	/// Time to Live.
	pub fn set_ttl(&mut self, value: u8) -> Result<&mut Self> {
		self.header_mut()[8] = value;

		Ok(self)
	}

	/// Source address.
	pub fn set_source(&mut self, value: Ipv4Addr) -> Result<&mut Self> {
		self.header_mut()[12 .. 16].copy_from_slice(&value.octets());

		Ok(self)
	}

	/// Destination address.
	pub fn set_destination(&mut self, value: Ipv4Addr) -> Result<&mut Self> {
		self.header_mut()[16 .. 20].copy_from_slice(&value.octets());

		Ok(self)
	}

	/// Inner protocol.
	pub fn set_protocol(&mut self, value: Protocol) -> Result<&mut Self> {
		self.header_mut()[9] = value.into();

		Ok(self)
	}

	/// Create a checksumed setter.
	pub fn checked(&mut self) -> Checked<B> {
		Checked {
			packet: self
		}
	}

	/// Set the checksum value.
	pub fn set_checksum(&mut self, value: u16) -> Result<&mut Self> {
		Cursor::new(&mut self.header_mut()[10 ..])
			.write_u16::<BigEndian>(value)?;

		Ok(self)
	}

	/// Recalculate and set the checksum value.
	pub fn update_checksum(&mut self) -> Result<&mut Self> {
		let checksum = checksum(P::header(self));
		self.set_checksum(checksum)
	}
}

/// Checked wrapper for IPv4 packets.
///
/// # Note
///
/// The checksum recalculation happens on `Drop`, so don't leak it.
pub struct Checked<'a, B: AsRef<[u8]> + AsMut<[u8]> + 'a> {
	packet: &'a mut Packet<B>
}

impl<'a, B: AsRef<[u8]> + AsMut<[u8]> + 'a> Checked<'a, B> {
	/// Differentiated Services Code Point.
	pub fn set_dscp(&mut self, value: u8) -> Result<&mut Self> {
		self.packet.set_dscp(value)?;
		Ok(self)
	}

	/// Explicit Congestion Notification.
	pub fn set_ecn(&mut self, value: u8) -> Result<&mut Self> {
		self.packet.set_ecn(value)?;
		Ok(self)
	}

	/// Packet ID.
	pub fn set_id(&mut self, value: u16) -> Result<&mut Self> {
		self.packet.set_id(value)?;
		Ok(self)
	}

	/// Packet flags.
	pub fn set_flags(&mut self, value: Flags) -> Result<&mut Self> {
		self.packet.set_flags(value)?;
		Ok(self)
	}

	/// Packet fragment offset.
	pub fn set_offset(&mut self, value: u16) -> Result<&mut Self> {
		self.packet.set_offset(value)?;
		Ok(self)
	}

	/// Time to Live.
	pub fn set_ttl(&mut self, value: u8) -> Result<&mut Self> {
		self.packet.set_ttl(value)?;
		Ok(self)
	}

	/// Source address.
	pub fn set_source(&mut self, value: Ipv4Addr) -> Result<&mut Self> {
		self.packet.set_source(value)?;
		Ok(self)
	}

	/// Destination address.
	pub fn set_destination(&mut self, value: Ipv4Addr) -> Result<&mut Self> {
		self.packet.set_destination(value)?;
		Ok(self)
	}

	/// Inner protocol.
	pub fn set_protocol(&mut self, value: Protocol) -> Result<&mut Self> {
		self.packet.set_protocol(value)?;
		Ok(self)
	}
}

impl<'a, B: AsRef<[u8]> + AsMut<[u8]>> Drop for Checked<'a, B> {
	fn drop(&mut self) {
		self.packet.update_checksum().unwrap();
	}
}

/// Iterator over IP packet options.
pub struct OptionIter<'a> {
	buffer: &'a [u8],
}

impl<'a> Iterator for OptionIter<'a> {
	type Item = Result<option::Option<&'a [u8]>>;

	fn next(&mut self) -> Option<Self::Item> {
		use size::Size;

		if self.buffer.is_empty() {
			return None;
		}

		match option::Option::new(self.buffer) {
			Ok(option) => {
				if option.number() == option::Number::End {
					return None;
				}

				self.buffer = &self.buffer[option.size() ..];
				Some(Ok(option))
			}

			Err(error) =>
				Some(Err(error))
		}
	}
}

#[cfg(test)]
mod test {
	use std::net::Ipv4Addr;
	use ip;

	#[test]
	fn short_packet() {
		assert!(ip::v4::Packet::no_payload(&[64; 10][..]).is_err());
		assert!(ip::v4::Packet::no_payload(&[64; 19][..]).is_err());
		assert!(ip::v4::Packet::no_payload(&[64; 20][..]).is_ok());
	}

	#[test]
	fn values() {
		let raw = [0x45u8, 0x00, 0x00, 0x34, 0x2d, 0x87, 0x00, 0x00, 0x2c, 0x06, 0x5c, 0x74, 0x42, 0x66, 0x01, 0x6c, 0xc0, 0xa8, 0x00, 0x4f];
		let ip  = ip::v4::Packet::no_payload(&raw[..]).unwrap();

		assert_eq!(ip.header(), 5);
		assert_eq!(ip.length(), 52);
		assert_eq!(ip.id(), 0x2d87);
		assert!(ip.flags().is_empty());
		assert_eq!(ip.protocol(), ip::Protocol::Tcp);
		assert_eq!(ip.checksum(), 0x5c74);
		assert!(ip.is_valid());
		assert_eq!(ip.source(), "66.102.1.108".parse::<Ipv4Addr>().unwrap());
		assert_eq!(ip.destination(), "192.168.0.79".parse::<Ipv4Addr>().unwrap());
	}

	#[test]
	fn owned() {
		let raw: Vec<u8> = vec![0x45, 0x00, 0x00, 0x34, 0x2d, 0x87, 0x00, 0x00, 0x2c, 0x06, 0x5c, 0x74, 0x42, 0x66, 0x01, 0x6c, 0xc0, 0xa8, 0x00, 0x4f];
		let ip           = ip::v4::Packet::no_payload(raw).unwrap();

		assert_eq!(ip.checksum(), 0x5c74);
		assert!(ip.is_valid());
	}

	#[test]
	fn mutable() {
		let mut raw = [0x45u8, 0x00, 0x00, 0x34, 0x2d, 0x87, 0x00, 0x00, 0x2c, 0x06, 0x5c, 0x74, 0x42, 0x66, 0x01, 0x6c, 0xc0, 0xa8, 0x00, 0x4f];
		let mut ip  = ip::v4::Packet::no_payload(&mut raw[..]).unwrap();

		assert_eq!(ip.id(), 0x2d87);
		assert!(ip.is_valid());

		ip.set_id(0x4242).unwrap();
		assert_eq!(ip.id(), 0x4242);
		assert!(!ip.is_valid());

		ip.update_checksum().unwrap();
		assert!(ip.is_valid());
	}

	#[test]
	fn mutable_checked() {
		let mut raw = [0x45u8, 0x00, 0x00, 0x34, 0x2d, 0x87, 0x00, 0x00, 0x2c, 0x06, 0x5c, 0x74, 0x42, 0x66, 0x01, 0x6c, 0xc0, 0xa8, 0x00, 0x4f];
		let mut ip  = ip::v4::Packet::no_payload(&mut raw[..]).unwrap();

		assert_eq!(ip.id(), 0x2d87);
		assert!(ip.is_valid());

		ip.checked().set_id(0x4242).unwrap();
		assert!(ip.is_valid());
	}
}
