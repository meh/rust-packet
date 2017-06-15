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
use packet::{Packet as P, PacketMut as PM, AsPacket, AsPacketMut};

/// IPv4 Option parser.
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

/// IPv4 Option class.
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum Class {
	///
	Control,

	///
	Debugging,

	///
	Reserved(u8),
}

/// IPv4 Option number.
#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum Number {
	///
	End,

	///
	NoOperation,

	///
	Security,

	///
	LooseSourceRoute,

	///
	TimeStamp,

	///
	ExtendedSecurity,

	///
	CommercialSecurity,

	///
	RecordRoute,

	///
	StreamId,

	///
	StrictSourceRoute,

	///
	ExperimentalMeasurement,

	///
	MtuProbe,

	///
	MtuReply,

	///
	ExperimentalFlowControl,

	///
	ExperimentalAccessControl,

	///
	ImiTrafficDescriptor,

	///
	ExtendedInternetProtocol,

	///
	TraceRoute,

	///
	AddressExtension,

	///
	RouterAlert,

	///
	SelectiveDirectedBroadcast,

	///
	DynamicPacketState,

	///
	UpstreamMulticastPacket,

	///
	QuickStart,

	///
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
	/// Parse an IPv4 option, checking the buffer contents are correct.
	pub fn new(buffer: B) -> Result<Option<B>> {
		use size::header::Min;

		let option = Option {
			buffer: buffer,
		};

		if option.buffer.as_ref().len() < Self::min() {
			return Err(ErrorKind::SmallBuffer.into());
		}

		if option.buffer.as_ref().len() < option.length() as usize {
			return Err(ErrorKind::SmallBuffer.into());
		}

		Ok(option)
	}
}

impl<B: AsRef<[u8]>> AsRef<[u8]> for Option<B> {
	fn as_ref(&self) -> &[u8] {
		use size::Size;

		&self.buffer.as_ref()[.. self.size()]
	}
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]> for Option<B> {
	fn as_mut(&mut self) -> &mut [u8] {
		use size::Size;

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

impl<B: AsRef<[u8]> + AsMut<[u8]>> PM for Option<B> {
	fn header_mut(&mut self) -> &mut [u8] {
		match self.length() {
			1 =>
				&mut self.buffer.as_mut()[.. 1],

			_ =>
				&mut self.buffer.as_mut()[.. 2],
		}
	}

	fn payload_mut(&mut self) -> &mut [u8] {
		match self.length() {
			1 =>
				&mut [],

			length =>
				&mut self.buffer.as_mut()[2 .. length as usize]
		}
	}
}

impl<B: AsRef<[u8]>> Option<B> {
	/// Whether the option has to be copied in fragments.
	pub fn is_copied(&self) -> bool {
		self.buffer.as_ref()[0] >> 7 == 1
	}

	/// Option class.
	pub fn class(&self) -> Class {
		match ((self.buffer.as_ref()[0] >> 5) & 0b011).into() {
			0 => Class::Control,
			2 => Class::Debugging,
			v => Class::Reserved(v),
		}
	}

	/// Option number.
	pub fn number(&self) -> Number {
		(self.buffer.as_ref()[0] & 0b11111).into()
	}

	/// Packet length
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
