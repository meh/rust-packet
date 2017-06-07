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
use size::{Min, Size};
use packet::Packet as P;

pub struct Option<B> {
	buffer: B,
}

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum Class {
	Control,
	Debugging,
	Reserved(u8),
}

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum Number {
	End,
	NoOperation,
	Security,
	LooseSourceRoute,
	TimeStamp,
	ExtendedSecurity,
	CommercialSecurity,
	RecordRoute,
	StreamId,
	StrictSourceRoute,
	ExperimentalMeasurement,
	MtuProbe,
	MtuReply,
	ExperimentalFlowControl,
	ExperimentalAccessControl,
	ImiTrafficDescriptor,
	ExtendedInternetProtocol,
	TraceRoute,
	AddressExtension,
	RouterAlert,
	SelectiveDirectedBroadcast,
	DynamicPacketState,
	UpstreamMulticastPacket,
	QuickStart,

	Unknown(u8),
}

impl<B: AsRef<[u8]>> fmt::Debug for Option<B> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("ip::v4::Option")
			.field("is_copied", &self.is_copied())
			.field("class", &self.class())
			.field("number", &self.number())
			.field("length", &self.length())
			.field("payload", &self.payload())
			.finish()
	}
}

impl<B: AsRef<[u8]>> Option<B> {
	pub fn new(buffer: B) -> Result<Option<B>> {
		if buffer.as_ref().len() < 1 {
			return Err(ErrorKind::InvalidPacket.into());
		}

		let option = Option {
			buffer: buffer,
		};

		if option.buffer.as_ref().len() < option.length() {
			return Err(ErrorKind::InvalidPacket.into());
		}

		Ok(option)
	}
}

impl<B> Min for Option<B> {
	fn min() -> usize {
		1
	}
}

impl<B: AsRef<[u8]>> Size for Option<B> {
	fn size(&self) -> usize {
		self.length()
	}
}

impl<B: AsRef<[u8]>> Option<B> {
	pub fn is_copied(&self) -> bool {
		self.buffer.as_ref()[0] >> 7 == 1
	}

	pub fn class(&self) -> Class {
		match ((self.buffer.as_ref()[0] >> 5) & 0b011).into() {
			0 => Class::Control,
			2 => Class::Debugging,
			v => Class::Reserved(v),
		}
	}

	pub fn number(&self) -> Number {
		(self.buffer.as_ref()[0] & 0b11111).into()
	}

	pub fn length(&self) -> usize {
		match self.number() {
			Number::End |
			Number::NoOperation =>
				1,

			_ =>
				self.buffer.as_ref()[1] as usize
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
				&self.buffer.as_ref()[2 .. length]
		}
	}
}

impl From<u8> for Class {
	fn from(value: u8) -> Self {
		use self::Class::*;

		match value {
			0 => Control,
			1 => Reserved(1),
			2 => Debugging,
			3 => Reserved(3),
			_ => panic!("invalid IPv4 option class"),
		}
	}
}

impl Into<u8> for Class {
	fn into(self) -> u8 {
		match self {
			Class::Control     => 0,
			Class::Debugging   => 2,
			Class::Reserved(n) => n,
		}
	}
}

impl From<u8> for Number {
	fn from(value: u8) -> Self {
		use self::Number::*;

		match value {
			0  => End,
			1  => NoOperation,
			2  => Security,
			3  => LooseSourceRoute,
			4  => TimeStamp,
			5  => ExtendedSecurity,
			6  => CommercialSecurity,
			7  => RecordRoute,
			8  => StreamId,
			9  => StrictSourceRoute,
			10 => ExperimentalMeasurement,
			11 => MtuProbe,
			12 => MtuReply,
			13 => ExperimentalFlowControl,
			14 => ExperimentalAccessControl,
			16 => ImiTrafficDescriptor,
			17 => ExtendedInternetProtocol,
			18 => TraceRoute,
			19 => AddressExtension,
			20 => RouterAlert,
			21 => SelectiveDirectedBroadcast,
			23 => DynamicPacketState,
			24 => UpstreamMulticastPacket,
			25 => QuickStart,
			n  => Number::Unknown(n),
		}
	}
}

impl Into<u8> for Number {
	fn into(self) -> u8 {
		use self::Number::*;

		match self {
			End                        => 0,
			NoOperation                => 1,
			Security                   => 2,
			LooseSourceRoute           => 3,
			TimeStamp                  => 4,
			ExtendedSecurity           => 5,
			CommercialSecurity         => 6,
			RecordRoute                => 7,
			StreamId                   => 8,
			StrictSourceRoute          => 9,
			ExperimentalMeasurement    => 10,
			MtuProbe                   => 11,
			MtuReply                   => 12,
			ExperimentalFlowControl    => 13,
			ExperimentalAccessControl  => 14,
			ImiTrafficDescriptor       => 16,
			ExtendedInternetProtocol   => 17,
			TraceRoute                 => 18,
			AddressExtension           => 19,
			RouterAlert                => 20,
			SelectiveDirectedBroadcast => 21,
			DynamicPacketState         => 23,
			UpstreamMulticastPacket    => 24,
			QuickStart                 => 25,
			Number::Unknown(n)         => n,
		}
	}
}
