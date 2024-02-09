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
use std::io::Cursor;
use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};
use hwaddr::HwAddr;
use log::error;

use crate::error::*;
use crate::packet::{Packet as P, PacketMut as PM, AsPacket, AsPacketMut};
use crate::ether::Protocol;

/// Ethernet frame parser.
pub struct Packet<B> {
	pub(crate) buffer: B,
}

sized!(Packet,
	header {
		min:  14,
		max:  14,
		size: 14,
	}

	payload {
		min:  0,
		max:  1486,
		size: p => p.buffer.as_ref().len() - 14,
	});

impl<B: AsRef<[u8]>> fmt::Debug for Packet<B> {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		f.debug_struct("ether::Packet")
			.field("destination", &self.source())
			.field("source", &self.destination())
			.field("protocol", &self.protocol())
			.field("payload", &self.payload())
			.finish()
	}
}

impl<B: AsRef<[u8]>> Packet<B> {
	/// Create an Ethernet frame without checking the buffer.
	pub fn unchecked(buffer: B) -> Packet<B> {
		Packet { buffer }
	}

	/// Parse an Ethernet frame, checking the buffer contents are correct.
	pub fn new(buffer: B) -> Result<Packet<B>> {
		use crate::size::header::Min;

		let packet = Packet::unchecked(buffer);

		if packet.buffer.as_ref().len() < Self::min() {
			error!("buffer is too short for the packet minimum length: {} < {}", packet.buffer.as_ref().len(), Self::min());
			Err(Error::SmallBuffer)?
		}

		Ok(packet)
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

impl<B: AsRef<[u8]>> AsRef<[u8]> for Packet<B> {
	fn as_ref(&self) -> &[u8] {
		use crate::size::Size;

		&self.buffer.as_ref()[.. self.size()]
	}
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]> for Packet<B> {
	fn as_mut(&mut self) -> &mut [u8] {
		use crate::size::Size;

		let size = self.size();
		&mut self.buffer.as_mut()[.. size]
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
		self.buffer.as_ref().split_at(14)
	}
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> PM for Packet<B> {
	fn split_mut(&mut self) -> (&mut [u8], &mut [u8]) {
		self.buffer.as_mut().split_at_mut(14)
	}
}

impl<B: AsRef<[u8]>> Packet<B> {
	/// MAC address for the destination.
	pub fn destination(&self) -> HwAddr {
		self.buffer.as_ref()[0 .. 6].into()
	}

	/// MAC address for the source.
	pub fn source(&self) -> HwAddr {
		self.buffer.as_ref()[6 .. 12].into()
	}

	/// Protocol of the inner packet.
	pub fn protocol(&self) -> Protocol {
		(&self.buffer.as_ref()[12 ..]).read_u16::<BigEndian>().unwrap().into()
	}
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> Packet<B> {
	/// Destination MAC address.
	pub fn set_destination(&mut self, value: HwAddr) -> Result<&mut Self> {
		self.buffer.as_mut()[0 .. 6].copy_from_slice(&value.octets());

		Ok(self)
	}

	/// Source MAC address.
	pub fn set_source(&mut self, value: HwAddr) -> Result<&mut Self> {
		self.buffer.as_mut()[6 .. 12].copy_from_slice(&value.octets());

		Ok(self)
	}

	/// Inner protocol.
	pub fn set_protocol(&mut self, value: Protocol) -> Result<&mut Self> {
		Cursor::new(&mut self.buffer.as_mut()[12 ..])
			.write_u16::<BigEndian>(value.into())?;

		Ok(self)
	}
}

#[cfg(test)]
mod test {
	use crate::packet::Packet;
	use crate::ether;
	use crate::ip;
	use crate::udp;

	#[test]
	fn values() {
		let raw = [0x00u8, 0x23, 0x69, 0x63, 0x59, 0xbe, 0xe4, 0xb3, 0x18, 0x26, 0x63, 0xa3, 0x08, 0x00, 0x45, 0x00, 0x00, 0x42, 0x47, 0x07, 0x40, 0x00, 0x40, 0x11, 0x6e, 0xcc, 0xc0, 0xa8, 0x01, 0x89, 0xc0, 0xa8, 0x01, 0xfe, 0xba, 0x2f, 0x00, 0x35, 0x00, 0x2e, 0x1d, 0xf8, 0xbc, 0x81, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x61, 0x70, 0x69, 0x0c, 0x73, 0x74, 0x65, 0x61, 0x6d, 0x70, 0x6f, 0x77, 0x65, 0x72, 0x65, 0x64, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x00, 0x01];

		let ether = ether::Packet::new(&raw[..]).unwrap();
		let ip    = ip::v4::Packet::new(ether.payload()).unwrap();
		let udp   = udp::Packet::new(ip.payload()).unwrap();

		assert!(ip.is_valid());
		assert!(udp.is_valid(&ip::Packet::from(&ip)));

		assert_eq!(ether.destination(), "00:23:69:63:59:be".parse().unwrap());
		assert_eq!(ether.source(), "e4:b3:18:26:63:a3".parse().unwrap());
		assert_eq!(ether.protocol(), ether::Protocol::Ipv4);
	}
}
