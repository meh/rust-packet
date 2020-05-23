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

use crate::error::*;
use crate::size;
use crate::packet::{Packet as P, PacketMut as PM, AsPacket, AsPacketMut};

/// TCP option parser.
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

/// TCP option number.
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum Number {
	///
	End,

	///
	NoOperation,

	///
	MaximumSegmentSize,

	///
	WindowScale,

	///
	SelectiveAcknowledgmentPermitted,

	///
	SelectiveAcknowledgment,

	///
	Timestamp,

	///
	Unknown(u8),
}

impl<B: AsRef<[u8]>> fmt::Debug for Option<B> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("tcp::Option")
			.field("number", &self.number())
			.field("length", &self.length())
			.field("payload", &self.payload())
			.finish()
	}
}

impl<B: AsRef<[u8]>> Option<B> {
	/// Parse a TCP option, checking the buffer contents are correct.
	pub fn new(buffer: B) -> Result<Option<B>> {
		let option = Option {
			buffer: buffer,
		};

		if option.buffer.as_ref().len() < <Self as size::header::Min>::min() {
			Err(Error::SmallBuffer)?
		}

		if option.buffer.as_ref().len() < option.length() as usize {
			Err(Error::SmallBuffer)?
		}

		Ok(option)
	}
}

impl<B: AsRef<[u8]>> AsRef<[u8]> for Option<B> {
	fn as_ref(&self) -> &[u8] {
		use crate::size::Size;

		&self.buffer.as_ref()[.. self.size()]
	}
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]> for Option<B> {
	fn as_mut(&mut self) -> &mut [u8] {
		use crate::size::Size;

		let size = self.size();
		&mut self.buffer.as_mut()[.. size]
	}
}

impl<'a, B: AsRef<[u8]>> AsPacket<'a, Option<&'a [u8]>> for B {
	fn as_packet(&self) -> Result<Option<&[u8]>> {
		Option::new(self.as_ref())
	}
}

impl<'a, B: AsRef<[u8]> + AsMut<[u8]>> AsPacketMut<'a, Option<&'a mut [u8]>> for B {
	fn as_packet_mut(&mut self) -> Result<Option<&mut [u8]>> {
		Option::new(self.as_mut())
	}
}

impl<B: AsRef<[u8]>> P for Option<B> {
	fn split(&self) -> (&[u8], &[u8]) {
		match self.length() {
			1 =>
				self.buffer.as_ref().split_at(1),

			length =>
				self.buffer.as_ref()[.. length as usize].split_at(2),
		}
	}
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> PM for Option<B> {
	fn split_mut(&mut self) -> (&mut [u8], &mut [u8]) {
		match self.length() {
			1 =>
				self.buffer.as_mut().split_at_mut(1),

			length =>
				self.buffer.as_mut()[.. length as usize].split_at_mut(2),
		}
	}
}

impl<B: AsRef<[u8]>> Option<B> {
	/// Option number.
	pub fn number(&self) -> Number {
		self.buffer.as_ref()[0].into()
	}

	/// Option length.
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
