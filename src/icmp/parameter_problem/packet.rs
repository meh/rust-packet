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

use error::*;
use packet::{Packet as P, AsPacket, AsPacketMut};
use size;
use ip;
use icmp::Kind;

/// Parameter Problem packet parser.
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
		min:  <ip::v4::Packet<()> as size::header::Min>::min(),
		max:  <ip::v4::Packet<()> as size::header::Max>::max(),
		size: p => {
			if let Ok(ip) = p.packet() {
				size::header::Size::size(&ip)
			}
			else {
				p.buffer.as_ref().len() - 8
			}
		},
	});

impl<B: AsRef<[u8]>> fmt::Debug for Packet<B> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("icmp::parameter_problem::Packet")
			.field("pointer", &self.pointer())
			.field("packet", &self.packet())
			.finish()
	}
}

impl<B: AsRef<[u8]>> Packet<B> {
	/// Parse a Parameter Problem packet, checking the buffer contents
	/// are correct.
	pub fn new(buffer: B) -> Result<Packet<B>> {
		use size::header::Min;

		let packet = Packet {
			buffer: buffer,
		};

		if packet.buffer.as_ref().len() < Self::min() {
			return Err(ErrorKind::SmallBuffer.into());
		}

		match Kind::from(packet.buffer.as_ref()[0]) {
			Kind::ParameterProblem =>
				(),

			_ =>
				return Err(ErrorKind::InvalidPacket.into())
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
		&self.buffer.as_ref()[.. 5]
	}

	fn payload(&self) -> &[u8] {
		&self.buffer.as_ref()[8 ..]
	}
}

impl<B: AsRef<[u8]>> Packet<B> {
	/// Pointer to the packet area that caused the problem.
	pub fn pointer(&self) -> u8 {
		self.buffer.as_ref()[4]
	}

	/// The packet that caused the problem.
	pub fn packet(&self) -> Result<ip::v4::Packet<&[u8]>> {
		ip::v4::Packet::new(&self.buffer.as_ref()[8 ..])
	}
}
