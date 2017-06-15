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
use byteorder::{ReadBytesExt, BigEndian};

use error::*;
use packet::{Packet as P, PacketMut as PM, AsPacket, AsPacketMut};
use icmp::Kind;
use icmp::checksum;

/// ICMP packet parser.
pub struct Packet<B> {
	buffer: B,
}

sized!(Packet,
	header {
		min:  4,
		max:  4,
		size: 4,
	}

	payload {
		min:  0,
		size: p => p.buffer.as_ref().len() - 4,
	});

impl<B: AsRef<[u8]>> fmt::Debug for Packet<B> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct(if self.is_valid() { "icmp::Packet" } else { "icmp::Packet!" })
			.field("kind", &self.kind())
			.field("code", &self.code())
			.field("checksum", &self.checksum())
			.field("payload", &self.payload())
			.finish()
	}
}

impl<B: AsRef<[u8]>> Packet<B> {
	/// Parse an ICMP packet, checking the buffer contents are correct.
	pub fn new(buffer: B) -> Result<Packet<B>> {
		use size::header::Min;

		let packet = Packet {
			buffer: buffer,
		};

		if packet.buffer.as_ref().len() < Self::min() {
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
		&self.buffer.as_ref()[.. 4]
	}

	fn payload(&self) -> &[u8] {
		&self.buffer.as_ref()[4 ..]
	}
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> PM for Packet<B> {
	fn header_mut(&mut self) -> &mut [u8] {
		&mut self.buffer.as_mut()[.. 4]
	}

	fn payload_mut(&mut self) -> &mut [u8] {
		&mut self.buffer.as_mut()[4 ..]
	}
}

macro_rules! kind {
	($(#[$attr:meta])* fn $module:ident) => (
		$(#[$attr])*
		pub fn $module(&self) -> Result<::icmp::$module::Packet<&B>> {
			::icmp::$module::Packet::new(&self.buffer)
		}
	)
}

impl<B: AsRef<[u8]>> Packet<B> {
	/// Packet type.
	pub fn kind(&self) -> Kind {
		Kind::from(self.buffer.as_ref()[0])
	}

	/// Packet code.
	pub fn code(&self) -> u8 {
		self.buffer.as_ref()[1]
	}

	/// Packet checksum.
	pub fn checksum(&self) -> u16 {
		(&self.buffer.as_ref()[2 ..]).read_u16::<BigEndian>().unwrap()
	}

	/// Verify the packet is valid by calculating the checksum.
	pub fn is_valid(&self) -> bool {
		checksum(self.buffer.as_ref()) == self.checksum()
	}

	kind!(/// Parse an Echo Request/Reply packet.
		fn echo);

	kind!(/// Parse a Timestamp Request/Reply packet.
		fn timestamp);

	kind!(/// Parse an Information Request/Reply packet.
		fn information);

	kind!(/// Parse a Parameter Problem packet.
		fn parameter_problem);

	kind!(/// Parse a Redirect Message packet.
		fn redirect_message);

	kind!(/// Parse a Source Quench, Destination Unreachable or Time Exceeded packet.
		fn previous);
}
