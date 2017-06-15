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
use byteorder::{ReadBytesExt, BigEndian};

use error::*;
use packet::{Packet as P, AsPacket};
use ip;
use tcp::Flags;
use tcp::checksum;
use tcp::option;

/// TCP packet parser.
pub struct Packet<B> {
	buffer: B,
}

sized!(Packet,
	header {
		min: 20,
		max: 60,
		size: p => p.offset() as usize * 4,
	}

	payload {
		min:  0,
		max:  u16::max_value() as usize - 60,
		size: p => p.buffer.as_ref().len() - (p.offset() as usize * 4),
	});

impl<B: AsRef<[u8]>> fmt::Debug for Packet<B> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("tcp::Packet")
			.field("source", &self.source())
			.field("destination", &self.destination())
			.field("sequence", &self.sequence())
			.field("acknowledgment", &self.acknowledgment())
			.field("offset", &self.offset())
			.field("flags", &self.flags())
			.field("window", &self.window())
			.field("checksum", &self.checksum())
			.field("pointer", &self.pointer())
			.field("payload", &self.payload())
			.finish()
	}
}

impl<B: AsRef<[u8]>> Packet<B> {
	/// Parse a TCP packet, checking the buffer contents are correct.
	pub fn new(buffer: B) -> Result<Packet<B>> {
		use size::header::Min;

		let packet = Packet {
			buffer: buffer,
		};

		if packet.buffer.as_ref().len() < Self::min() {
			return Err(ErrorKind::SmallBuffer.into());
		}

		if packet.buffer.as_ref().len() < packet.offset() as usize * 4 {
			return Err(ErrorKind::SmallBuffer.into());
		}

		Ok(packet)
	}

	/// Convert the packet to its owned version.
	///
	/// # Notes
	///
	/// It would be nice if `ToOwned` could be implemented, but `Packet` already
	/// implements `Clone` and the impl would conflict.
	pub fn to_owned(&self) -> Packet<Vec<u8>> {
		Packet::new(self.buffer.as_ref().to_vec()).unwrap()
	}
}

impl<B: AsRef<[u8]>> AsRef<[u8]> for Packet<B> {
	fn as_ref(&self) -> &[u8] {
		use size::Size;

		&self.buffer.as_ref()[.. self.size()]
	}
}

impl<'a, B: AsRef<[u8]>> AsPacket<'a, Packet<&'a [u8]>> for B {
	fn as_packet(&self) -> Result<Packet<&[u8]>> {
		Packet::new(self.as_ref())
	}
}

impl<B: AsRef<[u8]>> P for Packet<B> {
	fn header(&self) -> &[u8] {
		&self.buffer.as_ref()[.. self.offset() as usize * 4]
	}

	fn payload(&self) -> &[u8] {
		&self.buffer.as_ref()[self.offset() as usize * 4 ..]
	}
}

impl<B: AsRef<[u8]>> Packet<B> {
	/// Source port.
	pub fn source(&self) -> u16 {
		(&self.buffer.as_ref()[0 ..]).read_u16::<BigEndian>().unwrap()
	}

	/// Destination port.
	pub fn destination(&self) -> u16 {
		(&self.buffer.as_ref()[2 ..]).read_u16::<BigEndian>().unwrap()
	}

	/// Packet sequence.
	pub fn sequence(&self) -> u32 {
		(&self.buffer.as_ref()[4 ..]).read_u32::<BigEndian>().unwrap()
	}

	/// Optional acknowledgment.
	pub fn acknowledgment(&self) -> u32 {
		(&self.buffer.as_ref()[8 ..]).read_u32::<BigEndian>().unwrap()
	}

	/// Data offset.
	pub fn offset(&self) -> u8 {
		self.buffer.as_ref()[12] >> 4
	}

	/// Packet flags.
	pub fn flags(&self) -> Flags {
		Flags::from_bits((&self.buffer.as_ref()[12 ..])
			.read_u16::<BigEndian>().unwrap() & 0b1_1111_1111).unwrap()
	}

	/// Packet window.
	pub fn window(&self) -> u16 {
		(&self.buffer.as_ref()[14 ..]).read_u16::<BigEndian>().unwrap()
	}

	/// Packet checksum.
	pub fn checksum(&self) -> u16 {
		(&self.buffer.as_ref()[16 ..]).read_u16::<BigEndian>().unwrap()
	}

	/// Verify the packet is valid by calculating the checksum.
	pub fn is_valid<I: AsRef<[u8]>>(&self, ip: &ip::Packet<I>) -> bool {
		checksum(ip, self.buffer.as_ref()) == self.checksum()
	}

	/// Urgent pointer.
	pub fn pointer(&self) -> u16 {
		(&self.buffer.as_ref()[18 ..]).read_u16::<BigEndian>().unwrap()
	}

	/// TCP options for the packet.
	pub fn options(&self) -> OptionIter {
		OptionIter {
			buffer: &self.buffer.as_ref()[20 .. (self.offset() as usize * 4)],
		}
	}
}

/// Iterator over TCP packet options.
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
	use packet::Packet;
	use ip;
	use tcp;

	#[test]
	fn values() {
		let raw = [0x45u8, 0x00, 0x00, 0x3c, 0xc8, 0xa5, 0x40, 0x00, 0x40, 0x06, 0x9f, 0xd5, 0xc0, 0xa8, 0x01, 0x89, 0x08, 0x08, 0x08, 0x08, 0x9b, 0x8a, 0x00, 0x50, 0xde, 0x67, 0xc7, 0x4a, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x72, 0x10, 0x3f, 0x5f, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x59, 0x2b, 0x29, 0x97, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07];

		let ip  = ip::v4::Packet::new(&raw[..]).unwrap();
		let tcp = tcp::Packet::new(ip.payload()).unwrap();

		assert!(ip.is_valid());
		assert!(tcp.is_valid(&ip::Packet::from(&ip)));

		assert_eq!(tcp.flags(), tcp::flag::SYN);
		assert_eq!(tcp.destination(), 80);
	}
}
