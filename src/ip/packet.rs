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

use error::*;
use packet::{Packet as P, PacketMut as PM, AsPacket, AsPacketMut};
use size;
use ip::{v4, v6};

/// Generic IP packet.
#[derive(Debug)]
pub enum Packet<B: AsRef<[u8]>> {
	/// IPv4 packet.
	V4(v4::Packet<B>),

	/// IPv6 packet.
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

impl<B: AsRef<[u8]>> AsRef<[u8]> for Packet<B> {
	fn as_ref(&self) -> &[u8] {
		match *self {
			Packet::V4(ref packet) =>
				packet.as_ref(),

			Packet::V6(ref packet) =>
				packet.as_ref(),
		}
	}
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]> for Packet<B> {
	fn as_mut(&mut self) -> &mut [u8] {
		match *self {
			Packet::V4(ref mut packet) =>
				packet.as_mut(),

			Packet::V6(ref mut packet) =>
				packet.as_mut(),
		}
	}
}

impl<'a, B: AsRef<[u8]>> AsPacket<'a, Packet<&'a [u8]>> for B {
	fn as_packet(&self) -> Result<Packet<&[u8]>> {
		if let Ok(packet) = v4::Packet::new(self.as_ref()) {
			return Ok(Packet::V4(packet));
		}

		if let Ok(packet) = v6::Packet::new(self.as_ref()) {
			return Ok(Packet::V6(packet));
		}

		Err(ErrorKind::InvalidPacket.into())
	}
}

impl<'a, B: AsRef<[u8]> + AsMut<[u8]>> AsPacketMut<'a, Packet<&'a mut [u8]>> for B {
	fn as_packet_mut(&mut self) -> Result<Packet<&mut [u8]>> {
		if v4::Packet::new(self.as_ref()).is_ok() {
			return Ok(Packet::V4(v4::Packet::new(self.as_mut()).unwrap()));
		}

		if v6::Packet::new(self.as_ref()).is_ok() {
			return Ok(Packet::V6(v6::Packet::new(self.as_mut()).unwrap()));
		}

		Err(ErrorKind::InvalidPacket.into())
	}
}

impl<B: AsRef<[u8]>> P for Packet<B> {
	fn header(&self) -> &[u8] {
		match *self {
			Packet::V4(ref packet) =>
				P::header(packet),

			Packet::V6(ref packet) =>
				P::header(packet),
		}
	}

	fn payload(&self) -> &[u8] {
		match *self {
			Packet::V4(ref packet) =>
				P::payload(packet),

			Packet::V6(ref packet) =>
				P::payload(packet),
		}
	}
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> PM for Packet<B> {
	fn header_mut(&mut self) -> &mut [u8] {
		match *self {
			Packet::V4(ref mut packet) =>
				PM::header_mut(packet),

			Packet::V6(ref mut packet) =>
				PM::header_mut(packet),
		}
	}

	fn payload_mut(&mut self) -> &mut [u8] {
		match *self {
			Packet::V4(ref mut packet) =>
				PM::payload_mut(packet),

			Packet::V6(ref mut packet) =>
				PM::payload_mut(packet),
		}
	}
}

impl<B: AsRef<[u8]>> size::header::Size for Packet<B> {
	fn size(&self) -> usize {
		match *self {
			Packet::V4(ref packet) =>
				size::header::Size::size(packet),

			Packet::V6(ref packet) =>
				size::header::Size::size(packet),
		}
	}
}

impl<B: AsRef<[u8]>> size::payload::Size for Packet<B> {
	fn size(&self) -> usize {
		match *self {
			Packet::V4(ref packet) =>
				size::payload::Size::size(packet),

			Packet::V6(ref packet) =>
				size::payload::Size::size(packet),
		}
	}
}
