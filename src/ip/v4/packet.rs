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
use std::borrow::ToOwned;
use std::net::Ipv4Addr;
use byteorder::{ReadBytesExt, BigEndian};

use error::*;
use packet::{Packet as P, AsPacket, AsPacketMut};
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
		size: p => p.length() as usize - (p.header() as usize * 4),
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
	/// Parse an IPv4 packet, checking the buffer contents are correct.
	pub fn new(buffer: B) -> Result<Packet<B>> {
		let packet = Packet::no_payload(buffer)?;

		if packet.buffer.as_ref().len() < packet.length() as usize {
			return Err(ErrorKind::SmallBuffer.into());
		}

		Ok(packet)
	}

	/// Parse an IPv4 packet without checking the payload.
	pub fn no_payload(buffer: B) -> Result<Packet<B>> {
		use size::header::Min;

		let packet = Packet {
			buffer: buffer,
		};

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
}

impl<B: ToOwned> Packet<B>
	where B::Owned: AsRef<[u8]>
{
	/// Convert the packet to its owned version.
	///
	/// # Notes
	///
	/// It would be nice if `ToOwned` could be implemented, but `Packet` already
	/// implements `Clone` and the impl would conflict.
	pub fn to_owned(&self) -> Packet<B::Owned> {
		Packet {
			buffer: self.buffer.to_owned()
		}
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
	fn header(&self) -> &[u8] {
		&self.buffer.as_ref()[.. self.header() as usize * 4]
	}

	fn payload(&self) -> &[u8] {
		use size::payload::Size;

		let header  = self.header() as usize * 4;
		let payload = self.size();

		&self.buffer.as_ref()[header .. header + payload]
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
	use packet::Packet;

	#[test]
	fn short_packet() {
		assert!(ip::v4::Packet::no_payload(&[64; 10][..]).is_err());
		assert!(ip::v4::Packet::no_payload(&[64; 19][..]).is_err());
		assert!(ip::v4::Packet::no_payload(&[64; 20][..]).is_ok());
	}

	#[test]
	fn values() {
		let packet = [0x45u8, 0x00, 0x00, 0x34, 0x2d, 0x87, 0x00, 0x00, 0x2c, 0x06, 0x5c, 0x74, 0x42, 0x66, 0x01, 0x6c, 0xc0, 0xa8, 0x00, 0x4f];
		let packet = ip::v4::Packet::no_payload(&packet[..]).unwrap();

		assert_eq!(packet.header(), 5);
		assert_eq!(packet.length(), 52);
		assert_eq!(packet.id(), 0x2d87);
		assert!(packet.flags().is_empty());
		assert_eq!(packet.protocol(), ip::Protocol::Tcp);
		assert_eq!(packet.checksum(), 0x5c74);
		assert!(packet.is_valid());
		assert_eq!(packet.source(), "66.102.1.108".parse::<Ipv4Addr>().unwrap());
		assert_eq!(packet.destination(), "192.168.0.79".parse::<Ipv4Addr>().unwrap());
	}

	#[test]
	fn owned() {
		let packet: Vec<u8> = vec![0x45, 0x00, 0x00, 0x34, 0x2d, 0x87, 0x00, 0x00, 0x2c, 0x06, 0x5c, 0x74, 0x42, 0x66, 0x01, 0x6c, 0xc0, 0xa8, 0x00, 0x4f];
		let packet = ip::v4::Packet::no_payload(packet).unwrap();

		assert_eq!(packet.checksum(), 0x5c74);
		assert!(packet.is_valid());
	}
}
