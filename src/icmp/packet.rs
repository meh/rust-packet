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
use packet::Packet as P;
use icmp::Kind;
use icmp::checksum;

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
	pub fn new(buffer: B) -> Result<Packet<B>> {
		use size::header::Min;

		let packet = Packet {
			buffer: buffer,
		};

		if packet.buffer.as_ref().len() < Self::min() {
			return Err(ErrorKind::InvalidPacket.into());
		}

		Ok(packet)
	}
}

macro_rules! kind {
	($module:ident) => (
		pub fn $module(&self) -> Result<::icmp::$module::Packet<&B>> {
			::icmp::$module::Packet::new(&self.buffer)
		}
	)
}

impl<B: AsRef<[u8]>> Packet<B> {
	pub fn kind(&self) -> Kind {
		Kind::from(self.buffer.as_ref()[0])
	}

	pub fn code(&self) -> u8 {
		self.buffer.as_ref()[1]
	}

	pub fn checksum(&self) -> u16 {
		(&self.buffer.as_ref()[2 ..]).read_u16::<BigEndian>().unwrap()
	}

	pub fn is_valid(&self) -> bool {
		checksum(self.buffer.as_ref()) == self.checksum()
	}

	kind!(echo);
	kind!(timestamp);
	kind!(information);
	kind!(parameter_problem);
	kind!(redirect_message);
	kind!(previous);
}

impl<B: AsRef<[u8]>> P for Packet<B> {
	fn header(&self) -> &[u8] {
		&self.buffer.as_ref()[.. 4]
	}

	fn payload(&self) -> &[u8] {
		&self.buffer.as_ref()[4 ..]
	}
}
