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

use std::ops::Deref;
use std::net::Ipv4Addr;
use byteorder::{ReadBytesExt, BigEndian};

use error::*;
use size::{Min, Max, Size};
use packet::Packet as P;
use ip::Protocol;
use ip::v4::Flags;
use ip::v4::option;
use ip::v4::checksum;

pub struct Packet<B> {
	buffer: B,
}

impl<B: Deref<Target = [u8]>> Packet<B> {
	pub fn new(buffer: B) -> Result<Packet<B>> {
		if buffer.len() < Self::min() {
			return Err(ErrorKind::InvalidPacket.into());
		}

		let packet = Packet {
			buffer: buffer,
		};

		if packet.buffer.len() < packet.header() as usize * 4 {
			return Err(ErrorKind::InvalidPacket.into());
		}

		Ok(packet)
	}
}

impl<B> Min for Packet<B> {
	fn min() -> usize {
		20
	}
}

impl<B> Max for Packet<B> {
	fn max() -> usize {
		60
	}
}

impl<B: Deref<Target = [u8]>> Size for Packet<B> {
	fn size(&self) -> usize {
		self.header() as usize * 4
	}
}

impl<B: Deref<Target = [u8]>> Packet<B> {
	pub fn version(&self) -> u8 {
		self.buffer[0] >> 4
	}

	pub fn header(&self) -> u8 {
		self.buffer[0] & 0xf
	}

	pub fn dscp(&self) -> u8 {
		self.buffer[1] >> 2
	}

	pub fn ecn(&self) -> u8 {
		self.buffer[1] & 0x3
	}

	pub fn length(&self) -> u16 {
		(&self.buffer[2 ..]).read_u16::<BigEndian>().unwrap()
	}

	pub fn id(&self) -> u16 {
		(&self.buffer[4 ..]).read_u16::<BigEndian>().unwrap()
	}

	pub fn flags(&self) -> Flags {
		Flags::from_bits((&self.buffer[6 ..]).read_u16::<BigEndian>().unwrap() >> 13).unwrap()
	}

	pub fn offset(&self) -> u16 {
		(&self.buffer[6 ..]).read_u16::<BigEndian>().unwrap() & 0x1fff
	}

	pub fn ttl(&self) -> u8 {
		self.buffer[8]
	}

	pub fn protocol(&self) -> Protocol {
		self.buffer[9].into()
	}

	pub fn checksum(&self) -> u16 {
		(&self.buffer[10 ..]).read_u16::<BigEndian>().unwrap()
	}

	pub fn is_valid(&self) -> bool {
		checksum(P::header(self)) == self.checksum()
	}

	pub fn source(&self) -> Ipv4Addr {
		Ipv4Addr::new(
			self.buffer[12],
			self.buffer[13],
			self.buffer[14],
			self.buffer[15])
	}

	pub fn destination(&self) -> Ipv4Addr {
		Ipv4Addr::new(
			self.buffer[16],
			self.buffer[17],
			self.buffer[18],
			self.buffer[19])
	}

	pub fn options(&self) -> OptionIter {
		OptionIter {
			buffer: &self.buffer[20 .. (self.header() as usize * 4) - 20],
		}
	}
}

impl<B: Deref<Target = [u8]>> P for Packet<B> {
	fn header(&self) -> &[u8] {
		&self.buffer[.. self.header() as usize * 4]
	}

	fn payload(&self) -> &[u8] {
		&self.buffer[self.header() as usize * 4 ..]
	}
}

pub struct OptionIter<'a> {
	buffer: &'a [u8],
}

impl<'a> Iterator for OptionIter<'a> {
	type Item = Result<option::Option<&'a [u8]>>;

	fn next(&mut self) -> Option<Self::Item> {
		if self.buffer.is_empty() {
			return None;
		}
		
		match option::Option::new(self.buffer) {
			Ok(option) => {
				if option.number() == option::Number::End {
					return None;
				}

				self.buffer = &self.buffer[option.length() ..];
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
		assert!(ip::v4::Packet::new(&[0; 10][..]).is_err());
		assert!(ip::v4::Packet::new(&[0; 19][..]).is_err());
		assert!(ip::v4::Packet::new(&[0; 20][..]).is_ok());
	}

	#[test]
	fn values() {
		let packet: [u8; 20] = [0x45, 0x00, 0x00, 0x34, 0x2d, 0x87, 0x00, 0x00, 0x2c, 0x06, 0x5c, 0x74, 0x42, 0x66, 0x01, 0x6c, 0xc0, 0xa8, 0x00, 0x4f];
		let packet = ip::v4::Packet::new(&packet[..]).unwrap();

		assert_eq!(packet.version(), 4);
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
		let packet = ip::v4::Packet::new(packet).unwrap();

		assert_eq!(packet.checksum(), 0x5c74);
		assert!(packet.is_valid());
	}
}
