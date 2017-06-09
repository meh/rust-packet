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
use size::Min;
use packet::Packet as P;
use icmp::Kind;
use icmp::checksum;

pub struct Packet<B> {
	buffer: B,
}

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
		if buffer.as_ref().len() < Self::min() {
			return Err(ErrorKind::InvalidPacket.into());
		}

		let packet = Packet {
			buffer: buffer,
		};

		Ok(packet)
	}
}

impl<B> Min for Packet<B> {
	fn min() -> usize {
		8
	}
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

	pub fn echo(&self) -> Result<echo::Packet<&B>> {
		echo::Packet::new(&self.buffer)
	}

	pub fn timestamp(&self) -> Result<timestamp::Packet<&B>> {
		timestamp::Packet::new(&self.buffer)
	}

	pub fn information(&self) -> Result<information::Packet<&B>> {
		information::Packet::new(&self.buffer)
	}

	pub fn parameter_problem(&self) -> Result<parameter_problem::Packet<&B>> {
		parameter_problem::Packet::new(&self.buffer)
	}

	pub fn redirect_message(&self) -> Result<redirect_message::Packet<&B>> {
		redirect_message::Packet::new(&self.buffer)
	}

	pub fn previous(&self) -> Result<previous::Packet<&B>> {
		previous::Packet::new(&self.buffer)
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

pub mod echo {
	use std::fmt;
	use byteorder::{ReadBytesExt, BigEndian};

	use error::*;
	use size::{Min, Size};
	use packet::Packet as P;
	use icmp::Kind;

	pub struct Packet<B> {
		buffer: B,
	}

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
		pub fn new(buffer: B) -> Result<Packet<B>> {
			if buffer.as_ref().len() < Self::min() {
				return Err(ErrorKind::InvalidPacket.into());
			}

			let packet = Packet {
				buffer: buffer,
			};

			match Kind::from(packet.buffer.as_ref()[0]) {
				Kind::EchoRequest |
				Kind::EchoReply =>
					(),

				_ =>
					return Err(ErrorKind::InvalidPacket.into())
			}

			Ok(packet)
		}
	}

	impl<B> Min for Packet<B> {
		fn min() -> usize {
			8
		}
	}

	impl<B: AsRef<[u8]>> Size for Packet<B> {
		fn size(&self) -> usize {
			self.buffer.as_ref().len()
		}
	}

	impl<B: AsRef<[u8]>> Packet<B> {
		pub fn is_request(&self) -> bool {
			Kind::from(self.buffer.as_ref()[0]) == Kind::EchoRequest
		}

		pub fn is_reply(&self) -> bool {
			Kind::from(self.buffer.as_ref()[0]) == Kind::EchoReply
		}

		pub fn identifier(&self) -> u16 {
			(&self.buffer.as_ref()[4 ..]).read_u16::<BigEndian>().unwrap()
		}

		pub fn sequence(&self) -> u16 {
			(&self.buffer.as_ref()[6 ..]).read_u16::<BigEndian>().unwrap()
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
}

pub mod timestamp {
	use std::fmt;
	use byteorder::{ReadBytesExt, BigEndian};

	use error::*;
	use size::{Min, Max, Size};
	use packet::Packet as P;
	use icmp::Kind;

	pub struct Packet<B> {
		buffer: B,
	}

	impl<B: AsRef<[u8]>> fmt::Debug for Packet<B> {
		fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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
		pub fn new(buffer: B) -> Result<Packet<B>> {
			if buffer.as_ref().len() < Self::min() {
				return Err(ErrorKind::InvalidPacket.into());
			}

			let packet = Packet {
				buffer: buffer,
			};

			match Kind::from(packet.buffer.as_ref()[0]) {
				Kind::TimestampRequest |
				Kind::TimestampReply =>
					(),

				_ =>
					return Err(ErrorKind::InvalidPacket.into())
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
			20
		}
	}

	impl<B: AsRef<[u8]>> Size for Packet<B> {
		fn size(&self) -> usize {
			20
		}
	}

	impl<B: AsRef<[u8]>> Packet<B> {
		pub fn is_request(&self) -> bool {
			Kind::from(self.buffer.as_ref()[0]) == Kind::TimestampRequest
		}

		pub fn is_reply(&self) -> bool {
			Kind::from(self.buffer.as_ref()[0]) == Kind::TimestampReply
		}

		pub fn identifier(&self) -> u16 {
			(&self.buffer.as_ref()[4 ..]).read_u16::<BigEndian>().unwrap()
		}

		pub fn sequence(&self) -> u16 {
			(&self.buffer.as_ref()[6 ..]).read_u16::<BigEndian>().unwrap()
		}

		pub fn originate(&self) -> u32 {
			(&self.buffer.as_ref()[8 ..]).read_u32::<BigEndian>().unwrap()
		}

		pub fn receive(&self) -> u32 {
			(&self.buffer.as_ref()[12 ..]).read_u32::<BigEndian>().unwrap()
		}

		pub fn transmit(&self) -> u32 {
			(&self.buffer.as_ref()[16 ..]).read_u32::<BigEndian>().unwrap()
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
}

pub mod information {
	use std::fmt;
	use byteorder::{ReadBytesExt, BigEndian};

	use error::*;
	use size::{Min, Max, Size};
	use packet::Packet as P;
	use icmp::Kind;

	pub struct Packet<B> {
		buffer: B,
	}

	impl<B: AsRef<[u8]>> fmt::Debug for Packet<B> {
		fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
			f.debug_struct("icmp::information::Packet")
				.field("request", &self.is_request())
				.field("identifier", &self.identifier())
				.field("sequence", &self.sequence())
				.finish()
		}
	}

	impl<B: AsRef<[u8]>> Packet<B> {
		pub fn new(buffer: B) -> Result<Packet<B>> {
			if buffer.as_ref().len() < Self::min() {
				return Err(ErrorKind::InvalidPacket.into());
			}

			let packet = Packet {
				buffer: buffer,
			};

			match Kind::from(packet.buffer.as_ref()[0]) {
				Kind::InformationRequest |
				Kind::InformationReply =>
					(),

				_ =>
					return Err(ErrorKind::InvalidPacket.into())
			}

			Ok(packet)
		}
	}

	impl<B> Min for Packet<B> {
		fn min() -> usize {
			8
		}
	}

	impl<B> Max for Packet<B> {
		fn max() -> usize {
			8
		}
	}

	impl<B: AsRef<[u8]>> Size for Packet<B> {
		fn size(&self) -> usize {
			8
		}
	}

	impl<B: AsRef<[u8]>> Packet<B> {
		pub fn is_request(&self) -> bool {
			Kind::from(self.buffer.as_ref()[0]) == Kind::InformationRequest
		}

		pub fn is_reply(&self) -> bool {
			Kind::from(self.buffer.as_ref()[0]) == Kind::InformationReply
		}

		pub fn identifier(&self) -> u16 {
			(&self.buffer.as_ref()[4 ..]).read_u16::<BigEndian>().unwrap()
		}

		pub fn sequence(&self) -> u16 {
			(&self.buffer.as_ref()[6 ..]).read_u16::<BigEndian>().unwrap()
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
}

pub mod parameter_problem {
	use std::fmt;

	use error::*;
	use size::{Min, Size};
	use packet::Packet as P;
	use ip;
	use icmp::Kind;

	pub struct Packet<B> {
		buffer: B,
	}

	impl<B: AsRef<[u8]>> fmt::Debug for Packet<B> {
		fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
			f.debug_struct("icmp::parameter_problem::Packet")
				.field("pointer", &self.pointer())
				.field("packet", &self.packet())
				.finish()
		}
	}

	impl<B: AsRef<[u8]>> Packet<B> {
		pub fn new(buffer: B) -> Result<Packet<B>> {
			if buffer.as_ref().len() < Self::min() {
				return Err(ErrorKind::InvalidPacket.into());
			}

			let packet = Packet {
				buffer: buffer,
			};

			match Kind::from(packet.buffer.as_ref()[0]) {
				Kind::ParameterProblem =>
					(),

				_ =>
					return Err(ErrorKind::InvalidPacket.into())
			}

			Ok(packet)
		}
	}

	impl<B> Min for Packet<B> {
		fn min() -> usize {
			8
		}
	}

	impl<B: AsRef<[u8]>> Size for Packet<B> {
		fn size(&self) -> usize {
			self.buffer.as_ref().len()
		}
	}

	impl<B: AsRef<[u8]>> Packet<B> {
		pub fn pointer(&self) -> u8 {
			self.buffer.as_ref()[4]
		}

		pub fn packet(&self) -> Result<ip::v4::Packet<&[u8]>> {
			ip::v4::Packet::new(&self.buffer.as_ref()[8 ..])
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
}

pub mod redirect_message {
	use std::fmt;
	use std::net::Ipv4Addr;

	use error::*;
	use size::{Min, Size};
	use packet::Packet as P;
	use ip;
	use icmp::Kind;

	pub struct Packet<B> {
		buffer: B,
	}

	impl<B: AsRef<[u8]>> fmt::Debug for Packet<B> {
		fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
			f.debug_struct("icmp::redirect_message::Packet")
				.field("gateway", &self.gateway())
				.field("packet", &self.packet())
				.finish()
		}
	}

	impl<B: AsRef<[u8]>> Packet<B> {
		pub fn new(buffer: B) -> Result<Packet<B>> {
			if buffer.as_ref().len() < Self::min() {
				return Err(ErrorKind::InvalidPacket.into());
			}

			let packet = Packet {
				buffer: buffer,
			};

			match Kind::from(packet.buffer.as_ref()[0]) {
				Kind::RedirectMessage =>
					(),

				_ =>
					return Err(ErrorKind::InvalidPacket.into())
			}

			Ok(packet)
		}
	}

	impl<B> Min for Packet<B> {
		fn min() -> usize {
			8
		}
	}

	impl<B: AsRef<[u8]>> Size for Packet<B> {
		fn size(&self) -> usize {
			self.buffer.as_ref().len()
		}
	}

	impl<B: AsRef<[u8]>> Packet<B> {
		pub fn gateway(&self) -> Ipv4Addr {
			Ipv4Addr::new(
				self.buffer.as_ref()[4],
				self.buffer.as_ref()[5],
				self.buffer.as_ref()[6],
				self.buffer.as_ref()[7])
		}

		pub fn packet(&self) -> Result<ip::v4::Packet<&[u8]>> {
			ip::v4::Packet::new(&self.buffer.as_ref()[8 ..])
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
}

pub mod previous {
	use std::fmt;

	use error::*;
	use size::{Min, Size};
	use packet::Packet as P;
	use ip;
	use icmp::Kind;

	pub struct Packet<B> {
		buffer: B,
	}

	impl<B: AsRef<[u8]>> fmt::Debug for Packet<B> {
		fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
			f.debug_struct("icmp::previous::Packet")
				.field("packet", &self.packet())
				.finish()
		}
	}

	impl<B: AsRef<[u8]>> Packet<B> {
		pub fn new(buffer: B) -> Result<Packet<B>> {
			if buffer.as_ref().len() < Self::min() {
				return Err(ErrorKind::InvalidPacket.into());
			}

			let packet = Packet {
				buffer: buffer,
			};

			match Kind::from(packet.buffer.as_ref()[0]) {
				Kind::SourceQuench |
				Kind::DestinationUnreachable |
				Kind::TimeExceeded =>
					(),

				_ =>
					return Err(ErrorKind::InvalidPacket.into())
			}

			Ok(packet)
		}
	}

	impl<B> Min for Packet<B> {
		fn min() -> usize {
			8
		}
	}

	impl<B: AsRef<[u8]>> Size for Packet<B> {
		fn size(&self) -> usize {
			self.buffer.as_ref().len()
		}
	}

	impl<B: AsRef<[u8]>> Packet<B> {
		pub fn packet(&self) -> Result<ip::v4::Packet<&[u8]>> {
			ip::v4::Packet::new(&self.buffer.as_ref()[8 ..])
		}
	}

	impl<B: AsRef<[u8]>> P for Packet<B> {
		fn header(&self) -> &[u8] {
			&self.buffer.as_ref()[.. 4]
		}

		fn payload(&self) -> &[u8] {
			&self.buffer.as_ref()[8 ..]
		}
	}
}
