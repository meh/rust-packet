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

use error::*;
use size;
use packet::Packet as P;

pub struct Option<B> {
	buffer: B,
}

sized!(Option,
	header {
		min: 1,
		max: 2,
		size: p => match p.length() {
			1 => 1,
			_ => 2,
		},
	}

	payload {
		min:  0,
		max:  32,
		size: p => match p.length() {
			1 => 0,
			n => n as usize - 2,
		},
	});

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum Number {
	End,
	NoOperation,
	MaximumSegmentSize,
	WindowScale,
	SelectiveAcknowledgmentPermitted,
	SelectiveAcknowledgment,
	Timestamp,

	Unknown(u8),
}

impl<B: AsRef<[u8]>> fmt::Debug for Option<B> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("tcp::Option")
			.field("number", &self.number())
			.field("length", &self.length())
			.field("payload", &self.payload())
			.finish()
	}
}

impl<B: AsRef<[u8]>> Option<B> {
	pub fn new(buffer: B) -> Result<Option<B>> {
		let option = Option {
			buffer: buffer,
		};

		if option.buffer.as_ref().len() < <Self as size::header::Min>::min() {
			return Err(ErrorKind::InvalidPacket.into());
		}

		if option.buffer.as_ref().len() < option.length() as usize {
			return Err(ErrorKind::InvalidPacket.into());
		}

		Ok(option)
	}
}

impl<B: AsRef<[u8]>> Option<B> {
	pub fn number(&self) -> Number {
		self.buffer.as_ref()[0].into()
	}

	pub fn length(&self) -> u8 {
		match self.number() {
			Number::End |
			Number::NoOperation =>
				1,

			_ =>
				self.buffer.as_ref()[1]
		}
	}
}

impl<B: AsRef<[u8]>> P for Option<B> {
	fn header(&self) -> &[u8] {
		match self.length() {
			1 =>
				&self.buffer.as_ref()[.. 1],

			_ =>
				&self.buffer.as_ref()[.. 2],
		}
	}

	fn payload(&self) -> &[u8] {
		match self.length() {
			1 =>
				&[],

			length =>
				&self.buffer.as_ref()[2 .. length as usize]
		}
	}
}

impl From<u8> for Number {
	fn from(value: u8) -> Self {
		use self::Number::*;

		match value {
			0 => End,
			1 => NoOperation,
			2 => MaximumSegmentSize,
			3 => WindowScale,
			4 => SelectiveAcknowledgmentPermitted,
			5 => SelectiveAcknowledgment,
			8 => Timestamp,
			n => Unknown(n),
		}
	}
}

impl Into<u8> for Number {
	fn into(self) -> u8 {
		use self::Number::*;

		match self {
			End                              => 0,
			NoOperation                      => 1,
			MaximumSegmentSize               => 2,
			WindowScale                      => 3,
			SelectiveAcknowledgmentPermitted => 4,
			SelectiveAcknowledgment          => 5,
			Timestamp                        => 8,
			Unknown(n)                       => n,
		}
	}
}
