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

#[derive(Eq, PartialEq, Copy, Clone, Debug)]
pub enum Kind {
	EchoReply,
	DestinationUnreachable,
	SourceQuench,
	RedirectMessage,
	EchoRequest,
	RouterAdvertisement,
	RouterSolicitation,
	TimeExceeded,
	ParameterProblem,
	TimestampRequest,
	TimestampReply,
	InformationRequest,
	InformationReply,
	AddressMaskRequest,
	AddressMaskReply,
	TraceRoute,
	Unknown(u8),
}

impl From<u8> for Kind {
	fn from(value: u8) -> Kind {
		use self::Kind::*;

		match value {
			0  => EchoReply,
			3  => DestinationUnreachable,
			4  => SourceQuench,
			5  => RedirectMessage,
			8  => EchoRequest,
			9  => RouterAdvertisement,
			10 => RouterSolicitation,
			11 => TimeExceeded,
			12 => ParameterProblem,
			13 => TimestampRequest,
			14 => TimestampReply,
			15 => InformationRequest,
			16 => InformationReply,
			17 => AddressMaskRequest,
			18 => AddressMaskReply,
			30 => TraceRoute,
			v  => Unknown(v),
		}
	}
}

impl Into<u8> for Kind {
	fn into(self) -> u8 {
		use self::Kind::*;

		match self {
			EchoReply              => 0,
			DestinationUnreachable => 3,
			SourceQuench           => 4,
			RedirectMessage        => 5,
			EchoRequest            => 8,
			RouterAdvertisement    => 9,
			RouterSolicitation     => 10,
			TimeExceeded           => 11,
			ParameterProblem       => 12,
			TimestampRequest       => 13,
			TimestampReply         => 14,
			InformationRequest     => 15,
			InformationReply       => 16,
			AddressMaskRequest     => 17,
			AddressMaskReply       => 18,
			TraceRoute             => 30,
			Unknown(v)             => v,
		}
	}
}
