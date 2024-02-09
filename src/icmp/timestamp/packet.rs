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
use log::error;

use crate::error::*;
use crate::packet::{Packet as P, PacketMut as PM, AsPacket, AsPacketMut};
use crate::icmp::Kind;
use crate::icmp::packet::Checked;

/// Timestamp Request/Reply packet parser.
pub struct Packet<B> {
	buffer: B,
}

sized!(Packet,
	header {
		min:  20,
		max:  20,
		size: 20,
	}

	payload {
		min:  0,
		max:  0,
		size: 0,
	});

impl<B: AsRef<[u8]>> fmt::Debug for Packet<B> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("icmp::timestamp::Packet")
			.field("request", &self.is_request())
			.field("identifier", &self.identifier())
			.field("sequence", &self.sequence())
			.field("originate", &self.payload())
			.field("receive", &self.payload())
			.field("transmit", &self.payload())
			.finish()
	}
}

impl<B: AsRef<[u8]>> Packet<B> {
	/// Create a Timestamp Request/Reply packet without checking the buffer.
	pub fn unchecked(buffer: B) -> Packet<B> {
		Packet { buffer }
	}

	/// Parse a Timestamp Request/Reply packet, checking the buffer contents
	/// are correct.
	pub fn new(buffer: B) -> Result<Packet<B>> {
		use crate::size::header::Min;

		let packet = Packet::unchecked(buffer);

		if packet.buffer.as_ref().len() < Self::min() {
			error!("buffer is too short for the packet minimum length: {} < {}", packet.buffer.as_ref().len(), Self::min());
			Err(Error::SmallBuffer)?
		}

		match Kind::from(packet.buffer.as_ref()[0]) {
			Kind::TimestampRequest |
			Kind::TimestampReply =>
				(),

			_ =>
				Err(Error::InvalidPacket)?
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
		self.buffer.as_ref().split_at(8)
	}
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> PM for Packet<B> {
	fn split_mut(&mut self) -> (&mut [u8], &mut [u8]) {
		self.buffer.as_mut().split_at_mut(8)
	}
}

impl<B: AsRef<[u8]>> Packet<B> {
	/// Check if it's a Request packet.
	pub fn is_request(&self) -> bool {
		Kind::from(self.buffer.as_ref()[0]) == Kind::TimestampRequest
	}

	/// Check if it's a Reply packet.
	pub fn is_reply(&self) -> bool {
		Kind::from(self.buffer.as_ref()[0]) == Kind::TimestampReply
	}

	/// Packet identifier.
	pub fn identifier(&self) -> u16 {
		(&self.buffer.as_ref()[4 ..]).read_u16::<BigEndian>().unwrap()
	}

	/// Packet sequence.
	pub fn sequence(&self) -> u16 {
		(&self.buffer.as_ref()[6 ..]).read_u16::<BigEndian>().unwrap()
	}

	/// Creation timestamp.
	pub fn originate(&self) -> u32 {
		(&self.buffer.as_ref()[8 ..]).read_u32::<BigEndian>().unwrap()
	}

	/// Reception timestamp.
	pub fn receive(&self) -> u32 {
		(&self.buffer.as_ref()[12 ..]).read_u32::<BigEndian>().unwrap()
	}

	/// Transmission timestamp.
	pub fn transmit(&self) -> u32 {
		(&self.buffer.as_ref()[16 ..]).read_u32::<BigEndian>().unwrap()
	}
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> Packet<B> {
	/// Make the packet an Echo Request.
	pub fn make_request(&mut self) -> Result<&mut Self> {
		self.buffer.as_mut()[0] = Kind::EchoRequest.into();

		Ok(self)
	}

	/// Make the packet an Echo Reply.
	pub fn make_reply(&mut self) -> Result<&mut Self> {
		self.buffer.as_mut()[0] = Kind::EchoReply.into();

		Ok(self)
	}

	/// Packet identifier.
	pub fn set_identifier(&mut self, value: u16) -> Result<&mut Self> {
		Cursor::new(&mut self.buffer.as_mut()[4 ..])
			.write_u16::<BigEndian>(value)?;

		Ok(self)
	}

	/// Packet sequence.
	pub fn set_sequence(&mut self, value: u16) -> Result<&mut Self> {
		Cursor::new(&mut self.buffer.as_mut()[6 ..])
			.write_u16::<BigEndian>(value)?;

		Ok(self)
	}

	/// Creation timestamp.
	pub fn set_originate(&mut self, value: u32) -> Result<&mut Self> {
		Cursor::new(&mut self.buffer.as_mut()[8 ..])
			.write_u32::<BigEndian>(value)?;

		Ok(self)
	}

	/// Reception timestamp.
	pub fn set_receive(&mut self, value: u32) -> Result<&mut Self> {
		Cursor::new(&mut self.buffer.as_mut()[12 ..])
			.write_u32::<BigEndian>(value)?;

		Ok(self)
	}

	/// Transmission timestamp.
	pub fn set_transmit(&mut self, value: u32) -> Result<&mut Self> {
		Cursor::new(&mut self.buffer.as_mut()[16 ..])
			.write_u32::<BigEndian>(value)?;

		Ok(self)
	}

	/// Create a checksumed setter.
	pub fn checked(&mut self) -> Checked<'_, Self> {
		Checked {
			packet: self
		}
	}
}

impl<'a, B: AsRef<[u8]> + AsMut<[u8]> + 'a> Checked<'a, Packet<B>> {
	/// Make the packet an Echo Request.
	pub fn make_request(&mut self) -> Result<&mut Self> {
		self.packet.make_request()?;
		Ok(self)
	}

	/// Make the packet an Echo Reply.
	pub fn make_reply(&mut self) -> Result<&mut Self> {
		self.packet.make_reply()?;
		Ok(self)
	}

	/// Packet identifier.
	pub fn set_identifier(&mut self, value: u16) -> Result<&mut Self> {
		self.packet.set_identifier(value)?;
		Ok(self)
	}

	/// Packet sequence.
	pub fn set_sequence(&mut self, value: u16) -> Result<&mut Self> {
		self.packet.set_sequence(value)?;
		Ok(self)
	}

	/// Creation timestamp.
	pub fn set_originate(&mut self, value: u32) -> Result<&mut Self> {
		self.packet.set_originate(value)?;
		Ok(self)
	}

	/// Reception timestamp.
	pub fn set_receive(&mut self, value: u32) -> Result<&mut Self> {
		self.packet.set_receive(value)?;
		Ok(self)
	}

	/// Transmission timestamp.
	pub fn set_transmit(&mut self, value: u32) -> Result<&mut Self> {
		self.packet.set_transmit(value)?;
		Ok(self)
	}
}
