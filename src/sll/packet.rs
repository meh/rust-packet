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

use crate::error::*;
use crate::packet::{Packet as P, PacketMut as PM, AsPacket, AsPacketMut};
use crate::ether::Protocol;

#[derive(Debug, PartialEq, Eq)]
pub enum PacketType {
	LinuxSllHost,
	LinuxSllBroadcast,
	LinuxSllMulticast,
	LinuxSllOtherhost,
	LinuxSllOutgoing,
}

impl From<u16> for PacketType {
	fn from(value: u16) -> PacketType {
		use self::PacketType::*;

		match value {
			0x0000 => LinuxSllHost,
			0x0001 => LinuxSllBroadcast,
			0x0002 => LinuxSllMulticast,
			0x0003 => LinuxSllOtherhost,
			0x0004 => LinuxSllOutgoing,
			_ => panic!("Could not make PacketType"),
		}
	}
}

impl Into<u16> for PacketType {
	fn into(self) -> u16 {
		use self::PacketType::*;

		match self {
			LinuxSllHost => 0x0000,
			LinuxSllBroadcast => 0x0001,
			LinuxSllMulticast => 0x0002,
			LinuxSllOtherhost => 0x0003,
			LinuxSllOutgoing => 0x0004,
		}
	}
}




/// SLL frame parser.
pub struct Packet<B> {
	pub(crate) buffer: B,
}

sized!(Packet,
	header {
		min:  16,
		max:  16,
		size: 16,
	}

	payload {
		min:  0,
		max:  1484,
		size: p => p.buffer.as_ref().len() - 16,
	});

impl<B: AsRef<[u8]>> fmt::Debug for Packet<B> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("SLL::Packet")
			.field("packet type", &self.packet_type())
			.field("link layer address type", &self.ll_address_type())
			.field("link layer address length", &self.ll_address_length())
			.field("unused", &self.unused())
			.field("protocol", &self.protocol())
			.field("payload", &self.payload())
			.finish()
	}
}

impl<B: AsRef<[u8]>> Packet<B> {
	/// Create an SLL frame without checking the buffer.
	pub fn unchecked(buffer: B) -> Packet<B> {
		Packet { buffer }
	}

	/// Parse an SLL frame, checking the buffer contents are correct.
	pub fn new(buffer: B) -> Result<Packet<B>> {
		use crate::size::header::Min;

		let packet = Packet::unchecked(buffer);

		if packet.buffer.as_ref().len() < Self::min() {
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
		Packet::unchecked(self.buffer.as_ref().to_vec())
	}
}

impl<B: AsRef<[u8]>> AsRef<[u8]> for Packet<B> {
	fn as_ref(&self) -> &[u8] {
		use crate::size::Size;

		&self.buffer.as_ref()[.. self.size()]
	}
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]> for Packet<B> {
	fn as_mut(&mut self) -> &mut [u8] {
		use crate::size::Size;

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
		self.buffer.as_ref().split_at(16)
	}
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> PM for Packet<B> {
	fn split_mut(&mut self) -> (&mut [u8], &mut [u8]) {
		self.buffer.as_mut().split_at_mut(16)
	}
}

impl<B: AsRef<[u8]>> Packet<B> {
	/// packet type
	pub fn packet_type(&self) -> PacketType {
		match (&self.buffer.as_ref()[0 ..]).read_u16::<BigEndian>().unwrap().into() {
			0 => PacketType::LinuxSllHost,
			1 => PacketType::LinuxSllBroadcast,
			2 => PacketType::LinuxSllOtherhost,
			4 => PacketType::LinuxSllOutgoing,
			_ => panic!("error"),
		}
		//match self.buffer.as_ref()[0 .. ].into()
	}

	// /// SLL Addr Type
	pub fn ll_address_type(&self) -> u16 {
		(&self.buffer.as_ref()[2..4]).read_u16::<BigEndian>().unwrap().into()
	}

	// /// SLL Addr Length
	pub fn ll_address_length(&self) -> u16 {
		(&self.buffer.as_ref()[4..6]).read_u16::<BigEndian>().unwrap().into()
	}

	pub fn unused(&self) -> u64 {
		(&self.buffer.as_ref()[6 ..]).read_u64::<BigEndian>().unwrap().into()
	}

	// /// Protocol of the inner packet.
	pub fn protocol(&self) -> Protocol {
		(&self.buffer.as_ref()[14 ..]).read_u16::<BigEndian>().unwrap().into()
	}

}

impl<B: AsRef<[u8]> + AsMut<[u8]>> Packet<B> {

	pub fn set_packet_type(&mut self, value: PacketType) -> Result<&mut Self> {
		Cursor::new(&mut self.buffer.as_mut()[0 ..])
			.write_u16::<BigEndian>(value.into())?;

		Ok(self)		
	}

	pub fn set_ll_address_type(&mut self, value: u16) -> Result<&mut Self> {
		Cursor::new(&mut self.buffer.as_mut()[2 ..])
			.write_u16::<BigEndian>(value)?;
		
		Ok(self)
	}

	pub fn set_ll_address_length(&mut self, value: u16) -> Result<&mut Self> {
		Cursor::new(&mut self.buffer.as_mut()[4 ..])
			.write_u16::<BigEndian>(value)?;
		
		Ok(self)
	}

	pub fn set_unused(&mut self, value: u64) -> Result<&mut Self> {
		Cursor::new(&mut self.buffer.as_mut()[6 ..])
			.write_u64::<BigEndian>(value)?;
		
		Ok(self)
	}

 	// /// Inner protocol.
	pub fn set_protocol(&mut self, value: Protocol) -> Result<&mut Self> {
		Cursor::new(&mut self.buffer.as_mut()[14 ..])
			.write_u16::<BigEndian>(value.into())?;

		Ok(self)
	}
}

#[cfg(test)]
mod test {
	use crate::packet::Packet;
	use crate::ether;
	use crate::sll;
	use crate::ip;
	use crate::sll::packet::PacketType;
	use crate::tcp;

	#[test]
	fn values() {
		let raw = [0x00u8, 0x00, 0xff, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x45, 0x00, 0x00, 0x28, 0xfd, 0x00, 0x40, 0x00, 0x40, 0x06, 0x65, 0xe7, 0x12, 0xad, 0xbb, 0x39, 0x0a, 0x00, 0x00, 0x02, 0x01, 0xbb, 0x9f, 0xf5, 0x3f, 0x8d, 0x15, 0xd7, 0xbe, 0x71, 0x2d, 0xe8, 0x50, 0x10, 0x7f, 0xb0, 0x74, 0xcd, 0x00, 0x00];
		

		let sll = sll::Packet::new(&raw[..]).unwrap();
		let ip    = ip::v4::Packet::new(sll.payload()).unwrap();
		let tcp   = tcp::Packet::new(ip.payload()).unwrap();

		assert!(ip.is_valid());
		assert!(tcp.is_valid(&ip::Packet::from(&ip)));

		assert_eq!(sll.packet_type(), PacketType::LinuxSllHost);
		assert_eq!(sll.ll_address_type(), 65534);
		assert_eq!(sll.ll_address_length(), 0);
		assert_eq!(sll.protocol(), ether::Protocol::Ipv4);
	}
}
