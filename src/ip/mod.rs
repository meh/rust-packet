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

#[derive(Debug)]
pub enum Packet<B: AsRef<[u8]>> {
	V4(v4::Packet<B>),
	V6(v6::Packet<B>),
}

impl<B: AsRef<[u8]>> From<v4::Packet<B>> for Packet<B> {
	fn from(value: v4::Packet<B>) -> Packet<B> {
		Packet::V4(value)
	}
}

impl<B: AsRef<[u8]>> From<v6::Packet<B>> for Packet<B> {
	fn from(value: v6::Packet<B>) -> Packet<B> {
		Packet::V6(value)
	}
}

impl<'a, B: AsRef<[u8]> + Clone> From<&'a v4::Packet<B>> for Packet<B> {
	fn from(value: &'a v4::Packet<B>) -> Packet<B> {
		Packet::V4(value.clone())
	}
}

impl<'a, B: AsRef<[u8]> + Clone> From<&'a v6::Packet<B>> for Packet<B> {
	fn from(value: &'a v6::Packet<B>) -> Packet<B> {
		Packet::V6(value.clone())
	}
}

pub mod v4;
pub mod v6;

mod protocol;
pub use self::protocol::Protocol;
