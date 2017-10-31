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
use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};

use error::*;
use packet::{Packet as P, PacketMut as PM, AsPacket, AsPacketMut};
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
	/// Create a TCP packet without checking the buffer.
	pub fn unchecked(buffer: B) -> Packet<B> {
		Packet { buffer }
	}

	/// Parse a TCP packet, checking the buffer contents are correct.
	pub fn new(buffer: B) -> Result<Packet<B>> {
		use size::header::Min;

		let packet = Packet::unchecked(buffer);

		if packet.buffer.as_ref().len() < Self::min() {
			return Err(ErrorKind::SmallBuffer.into());
		}

		if packet.buffer.as_ref().len() < packet.offset() as usize * 4 {
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
		let offset = self.offset() as usize;
		self.buffer.as_ref().split_at(offset * 4)
	}
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> PM for Packet<B> {
	fn split_mut(&mut self) -> (&mut [u8], &mut [u8]) {
		let offset = self.offset() as usize;
		self.buffer.as_mut().split_at_mut(offset * 4)
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

impl<B: AsRef<[u8]> + AsMut<[u8]>> Packet<B> {
	/// Source port.
	pub fn set_source(&mut self, value: u16) -> Result<&mut Self> {
		Cursor::new(&mut self.header_mut()[0 ..])
			.write_u16::<BigEndian>(value)?;

		Ok(self)
	}

	/// Destination port.
	pub fn set_destination(&mut self, value: u16) -> Result<&mut Self> {
		Cursor::new(&mut self.header_mut()[2 ..])
			.write_u16::<BigEndian>(value)?;

		Ok(self)
	}

	/// Packet sequence.
	pub fn set_sequence(&mut self, value: u32) -> Result<&mut Self> {
		Cursor::new(&mut self.header_mut()[4 ..])
			.write_u32::<BigEndian>(value)?;

		Ok(self)
	}

	/// Optional acknowledgment.
	pub fn set_acknowledgment(&mut self, value: u32) -> Result<&mut Self> {
		Cursor::new(&mut self.header_mut()[8 ..])
			.write_u32::<BigEndian>(value)?;

		Ok(self)
	}

	/// Packet flags.
	pub fn set_flags(&mut self, value: Flags) -> Result<&mut Self> {
		let old = self.header()[12] & 0b1111_0000;

		Cursor::new(&mut self.header_mut()[12 ..])
			.write_u16::<BigEndian>((u16::from(old)) << 12 | value.bits())?;

		Ok(self)
	}

	/// Packet window.
	pub fn set_window(&mut self, value: u16) -> Result<&mut Self> {
		Cursor::new(&mut self.header_mut()[14 ..])
			.write_u16::<BigEndian>(value)?;

		Ok(self)
	}

	/// Urgent pointer.
	pub fn set_pointer(&mut self, value: u16) -> Result<&mut Self> {
		Cursor::new(&mut self.header_mut()[18 ..])
			.write_u16::<BigEndian>(value)?;

		Ok(self)
	}

	/// Create a checksumed setter.
	pub fn checked<'a, 'b, BI: AsRef<[u8]> + 'b>(&'a mut self, ip: &'b ip::Packet<BI>) -> Checked<'a, 'b, B, BI> {
		Checked {
			packet: self,
			ip:     ip,
		}
	}

	/// Set the checksum value.
	pub fn set_checksum(&mut self, value: u16) -> Result<&mut Self> {
		Cursor::new(&mut self.header_mut()[16 ..])
			.write_u16::<BigEndian>(value)?;

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
	where BP: AsRef<[u8]> + AsMut<[u8]> + 'a,
	      BI: AsRef<[u8]> + 'b
{
	packet: &'a mut Packet<BP>,
	ip:     &'b ip::Packet<BI>,
}

impl<'a, 'b, BP, BI> Checked<'a, 'b, BP, BI>
	where BP: AsRef<[u8]> + AsMut<[u8]> + 'a,
	      BI: AsRef<[u8]> + 'b
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

	/// Packet sequence.
	pub fn set_sequence(&mut self, value: u32) -> Result<&mut Self> {
		self.packet.set_sequence(value)?;
		Ok(self)
	}

	/// Optional acknowledgment.
	pub fn set_acknowledgment(&mut self, value: u32) -> Result<&mut Self> {
		self.packet.set_acknowledgment(value)?;
		Ok(self)
	}

	/// Packet flags.
	pub fn set_flags(&mut self, value: Flags) -> Result<&mut Self> {
		self.packet.set_flags(value)?;
		Ok(self)
	}

	/// Packet window.
	pub fn set_window(&mut self, value: u16) -> Result<&mut Self> {
		self.packet.set_window(value)?;
		Ok(self)
	}

	/// Urgent pointer.
	pub fn set_pointer(&mut self, value: u16) -> Result<&mut Self> {
		self.packet.set_pointer(value)?;
		Ok(self)
	}
}

impl<'a, 'b, BP, BI> Drop for Checked<'a, 'b, BP, BI>
	where BP: AsRef<[u8]> + AsMut<[u8]> + 'a,
	      BI: AsRef<[u8]> + 'b
{
	fn drop(&mut self) {
		self.packet.update_checksum(self.ip).unwrap();
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
	use packet::{Packet, PacketMut};
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

	#[test]
	fn mutable() {
		let mut raw = [0x45u8, 0x00, 0x00, 0x3c, 0xc8, 0xa5, 0x40, 0x00, 0x40, 0x06, 0x9f, 0xd5, 0xc0, 0xa8, 0x01, 0x89, 0x08, 0x08, 0x08, 0x08, 0x9b, 0x8a, 0x00, 0x50, 0xde, 0x67, 0xc7, 0x4a, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x72, 0x10, 0x3f, 0x5f, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x59, 0x2b, 0x29, 0x97, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07];

		let mut ip    = ip::v4::Packet::new(&mut raw[..]).unwrap();
		let (ip, tcp) = ip.split_mut();
		let     ip    = ip::Packet::from(ip::v4::Packet::unchecked(ip));
		let mut tcp   = tcp::Packet::new(tcp).unwrap();

		assert!(tcp.is_valid(&ip));
		assert_eq!(tcp.destination(), 80);

		tcp.set_destination(9001).unwrap();
		assert_eq!(tcp.destination(), 9001);
		assert!(!tcp.is_valid(&ip));

		tcp.update_checksum(&ip).unwrap();
		assert!(tcp.is_valid(&ip));
	}

	#[test]
	fn mutable_checked() {
		let mut raw = [0x45u8, 0x00, 0x00, 0x3c, 0xc8, 0xa5, 0x40, 0x00, 0x40, 0x06, 0x9f, 0xd5, 0xc0, 0xa8, 0x01, 0x89, 0x08, 0x08, 0x08, 0x08, 0x9b, 0x8a, 0x00, 0x50, 0xde, 0x67, 0xc7, 0x4a, 0x00, 0x00, 0x00, 0x00, 0xa0, 0x02, 0x72, 0x10, 0x3f, 0x5f, 0x00, 0x00, 0x02, 0x04, 0x05, 0xb4, 0x04, 0x02, 0x08, 0x0a, 0x59, 0x2b, 0x29, 0x97, 0x00, 0x00, 0x00, 0x00, 0x01, 0x03, 0x03, 0x07];

		let mut ip        = ip::v4::Packet::new(&mut raw[..]).unwrap();
		let (ip, mut tcp) = ip.split_mut();
		let     ip        = ip::Packet::from(ip::v4::Packet::unchecked(ip));
		let mut tcp       = tcp::Packet::new(tcp).unwrap();

		assert!(tcp.is_valid(&ip));
		assert_eq!(tcp.destination(), 80);

		tcp.checked(&ip).set_destination(9001).unwrap();
		assert_eq!(tcp.destination(), 9001);
		assert!(tcp.is_valid(&ip));
	}
}
