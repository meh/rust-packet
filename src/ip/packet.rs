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

use crate::error::*;
use crate::packet::{Packet as P, PacketMut as PM, AsPacket, AsPacketMut};
use crate::size;
use crate::ip::{v4, v6};

/// Generic IP packet.
#[derive(Debug)]
pub enum Packet<B: AsRef<[u8]>> {
	/// IPv4 packet.
	V4(v4::Packet<B>),

	/// IPv6 packet.
	V6(v6::Packet<B>),
}

impl<B: AsRef<[u8]>> Packet<B> {
	/// Create an IP packet without checking the buffer.
	///
	/// # Note
	///
	/// This still checks the version field to pick an IPv4 or IPv6 packet.
	pub fn unchecked(buffer: B) -> Packet<B> {
		match buffer.as_ref()[0] >> 4 {
			4 =>
				Packet::V4(v4::Packet::unchecked(buffer)),

			6 =>
				Packet::V6(v6::Packet::unchecked(buffer)),

			_ =>
				panic!("not an IPv4 or IPv6 packet")
		}
	}

	/// Parse an IP packet without checking the payload.
	pub fn no_payload(buffer: B) -> Result<Packet<B>> {
		match buffer.as_ref()[0] >> 4 {
			4 =>
				v4::Packet::no_payload(buffer).map(Packet::V4),

			6 =>
				v6::Packet::no_payload(buffer).map(Packet::V6),

			_ =>
				Err(ErrorKind::InvalidPacket.into())
		}
	}

	/// Parse an IP packet, checking the buffer contents are correct.
	pub fn new(buffer: B) -> Result<Packet<B>> {
		match buffer.as_ref()[0] >> 4 {
			4 =>
				v4::Packet::new(buffer).map(Packet::V4),

			6 =>
				v6::Packet::new(buffer).map(Packet::V6),

			_ =>
				Err(ErrorKind::InvalidPacket.into())
		}
	}
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

impl<B: AsRef<[u8]>> Packet<B> {
	/// Convert the packet to its owned version.
	///
	/// # Notes
	///
	/// It would be nice if `ToOwned` could be implemented, but `Packet` already
	/// implements `Clone` and the impl would conflict.
	pub fn to_owned(&self) -> Packet<Vec<u8>> {
		match *self {
			Packet::V4(ref packet) =>
				Packet::V4(packet.to_owned()),

			Packet::V6(ref packet) =>
				Packet::V6(packet.to_owned()),
		}
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
		Packet::new(self.as_ref())
	}
}

impl<'a, B: AsRef<[u8]> + AsMut<[u8]>> AsPacketMut<'a, Packet<&'a mut [u8]>> for B {
	fn as_packet_mut(&mut self) -> Result<Packet<&mut [u8]>> {
		Packet::new(self.as_mut())
	}
}

impl<B: AsRef<[u8]>> P for Packet<B> {
	fn split(&self) -> (&[u8], &[u8]) {
		match *self {
			Packet::V4(ref packet) =>
				packet.split(),

			Packet::V6(ref packet) =>
				packet.split(),
		}
	}
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> PM for Packet<B> {
	fn split_mut(&mut self) -> (&mut [u8], &mut [u8]) {
		match *self {
			Packet::V4(ref mut packet) =>
				packet.split_mut(),

			Packet::V6(ref mut packet) =>
				packet.split_mut(),
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
