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
use std::net::Ipv6Addr;
use crate::error::*;
use crate::packet::{Packet as P, PacketMut as PM, AsPacket, AsPacketMut};
use crate::ip::Protocol;

/// IPv6 packet parser.
#[derive(Clone)]
pub struct Packet<B> {
	buffer: B,
}

sized!(Packet,
	header {
		min:  0,
		max:  0,
		size: 0,
	}

	payload {
		min:  0,
		max:  0,
		size: 0,
	});

impl<B: AsRef<[u8]>> fmt::Debug for Packet<B> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("ip::v6::Packet")
			.finish()
	}
}

impl<B: AsRef<[u8]>> Packet<B> {
	/// Create an IPv6 packet without checking the buffer.
	pub fn unchecked(buffer: B) -> Packet<B> {
		Packet { buffer }
	}

	/// Parse an IPv6 packet without checking the payload.
	pub fn no_payload(buffer: B) -> Result<Packet<B>> {
		use crate::size::header::Min;

		let packet = Packet::unchecked(buffer);

		if packet.buffer.as_ref().len() < Self::min() {
			Err(Error::SmallBuffer)?
		}

		if packet.buffer.as_ref()[0] >> 4 != 6 {
			Err(Error::InvalidPacket)?
		}

		Ok(packet)
	}

	/// Parse an IPv6 packet, checking the buffer contents are correct.
	pub fn new(buffer: B) -> Result<Packet<B>> {
		Packet::no_payload(buffer)
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
		Packet::unchecked(self.buffer.as_ref().to_vec())
	}
}

impl<B: AsRef<[u8]>> Packet<B> {
	/// Protocol of the inner packet.
	pub fn protocol(&self) -> Protocol {
		self.buffer.as_ref()[6].into()
	}

	/// Source IP address.
	pub fn source(&self) -> Ipv6Addr {
		Ipv6Addr::new(
			((self.buffer.as_ref()[8]) as u16 ) << 8 | self.buffer.as_ref()[9] as u16,
			((self.buffer.as_ref()[10]) as u16 ) << 8 | self.buffer.as_ref()[11] as u16,
			((self.buffer.as_ref()[12]) as u16 ) << 8 | self.buffer.as_ref()[13] as u16,
			((self.buffer.as_ref()[14]) as u16 ) << 8 | self.buffer.as_ref()[15] as u16,
			((self.buffer.as_ref()[16]) as u16 ) << 8 | self.buffer.as_ref()[17] as u16,
			((self.buffer.as_ref()[18]) as u16 ) << 8 | self.buffer.as_ref()[19] as u16,
			((self.buffer.as_ref()[20]) as u16 ) << 8 | self.buffer.as_ref()[21] as u16,
			((self.buffer.as_ref()[22]) as u16 ) << 8 | self.buffer.as_ref()[23] as u16,
			)
	}

	/// Destination IP address.
	pub fn destination(&self) -> Ipv6Addr {
		Ipv6Addr::new(
			((self.buffer.as_ref()[24]) as u16 ) << 8 | self.buffer.as_ref()[25] as u16,
			((self.buffer.as_ref()[26]) as u16 ) << 8 | self.buffer.as_ref()[27] as u16,
			((self.buffer.as_ref()[28]) as u16 ) << 8 | self.buffer.as_ref()[29] as u16,
			((self.buffer.as_ref()[30]) as u16 ) << 8 | self.buffer.as_ref()[31] as u16,
			((self.buffer.as_ref()[32]) as u16 ) << 8 | self.buffer.as_ref()[33] as u16,
			((self.buffer.as_ref()[34]) as u16 ) << 8 | self.buffer.as_ref()[35] as u16,
			((self.buffer.as_ref()[36]) as u16 ) << 8 | self.buffer.as_ref()[37] as u16,
			((self.buffer.as_ref()[38]) as u16 ) << 8 | self.buffer.as_ref()[39] as u16,
			)
	}
}

impl<B: AsRef<[u8]>> AsRef<[u8]> for Packet<B> {
	fn as_ref(&self) -> &[u8] {
		&[]
	}
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]> for Packet<B> {
	fn as_mut(&mut self) -> &mut [u8] {
		&mut []
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
		(&[], &[])
	}
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> PM for Packet<B> {
	fn split_mut(&mut self) -> (&mut [u8], &mut [u8]) {
		(&mut [], &mut [])
	}
}
