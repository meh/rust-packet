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
use icmp::Kind;

/// Echo Request/Reply packet parser.
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
		size: p => p.buffer.as_ref().len() - 8,
	});

impl<B: AsRef<[u8]>> fmt::Debug for Packet<B> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("icmp::echo::Packet")
			.field("request", &self.is_request())
			.field("identifier", &self.identifier())
			.field("sequence", &self.sequence())
			.field("payload", &self.payload())
			.finish()
	}
}

impl<B: AsRef<[u8]>> Packet<B> {
	/// Parse an Echo Request/Reply packet, checking the buffer contents are
	/// correct.
	pub fn new(buffer: B) -> Result<Packet<B>> {
		use size::header::Min;

		let packet = Packet {
			buffer: buffer,
		};

		if packet.buffer.as_ref().len() < Self::min() {
			return Err(ErrorKind::SmallBuffer.into());
		}

		match Kind::from(packet.buffer.as_ref()[0]) {
			Kind::EchoRequest |
			Kind::EchoReply =>
				(),

			_ =>
				return Err(ErrorKind::InvalidPacket.into())
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
		&self.buffer.as_ref()[.. 8]
	}

	fn payload(&self) -> &[u8] {
		&self.buffer.as_ref()[8 ..]
	}
}

impl<B: AsRef<[u8]>> Packet<B> {
	/// Check if it's a Request packet.
	pub fn is_request(&self) -> bool {
		Kind::from(self.buffer.as_ref()[0]) == Kind::EchoRequest
	}

	/// Check if it's a Reply packet.
	pub fn is_reply(&self) -> bool {
		Kind::from(self.buffer.as_ref()[0]) == Kind::EchoReply
	}

	/// Packet identifier.
	pub fn identifier(&self) -> u16 {
		(&self.buffer.as_ref()[4 ..]).read_u16::<BigEndian>().unwrap()
	}

	/// Packet sequence.
	pub fn sequence(&self) -> u16 {
		(&self.buffer.as_ref()[6 ..]).read_u16::<BigEndian>().unwrap()
	}
}
