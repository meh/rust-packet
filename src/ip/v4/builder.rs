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

use std::io::Cursor;
use std::net::Ipv4Addr;
use byteorder::{WriteBytesExt, BigEndian};

use crate::error::*;
use crate::buffer::{self, Buffer};
use crate::builder::{Builder as Build, Finalization};
use crate::packet::{AsPacket, AsPacketMut};
use crate::ip::Protocol;
use crate::ip::v4::Packet;
use crate::ip::v4::Flags;
use crate::ip::v4::checksum;

/// IPv4 packet builder.
#[derive(Debug)]
#[allow(dead_code)]
pub struct Builder<B: Buffer = buffer::Dynamic> {
	buffer:    B,
	finalizer: Finalization,

	options: bool,
	payload: bool,
}

impl<B: Buffer> Build<B> for Builder<B> {
	fn with(mut buffer: B) -> Result<Self> {
		use crate::size::header::Min;
		buffer.next(Packet::<()>::min())?;

		// Set version to 4 and header length to the minimum.
		//
		// XXX: This is needed for shit to work. The builder uses setters on the
		//      `ip::v4::Packet` which expect the header length to be set. While the TCP
		//      and UDP builders base their finalizer on extracting the parent IP
		//      packet.
		buffer.data_mut()[0] = (4 << 4) | ((Packet::<()>::min() / 4) as u8);

		Ok(Builder {
			buffer:    buffer,
			finalizer: Default::default(),

			options: false,
			payload: false,
		})
	}

	fn finalizer(&mut self) -> &mut Finalization {
		&mut self.finalizer
	}

	fn build(mut self) -> Result<B::Inner> {
		self.prepare();

		let mut buffer = self.buffer.into_inner();
		self.finalizer.finalize(buffer.as_mut())?;
		Ok(buffer)
	}
}

impl Default for Builder<buffer::Dynamic> {
	fn default() -> Self {
		Builder::with(buffer::Dynamic::default()).unwrap()
	}
}

impl<'a, B: Buffer> AsPacket<'a, Packet<&'a [u8]>> for Builder<B> {
	fn as_packet(&self) -> Result<Packet<&[u8]>> {
		Packet::new(self.buffer.data())
	}
}

impl<'a, B: Buffer> AsPacketMut<'a, Packet<&'a mut [u8]>> for Builder<B> {
	fn as_packet_mut(&mut self) -> Result<Packet<&mut [u8]>> {
		Packet::new(self.buffer.data_mut())
	}
}

macro_rules! protocol {
	($(#[$attr:meta])* fn $module:ident($protocol:ident)) => (
		$(#[$attr])*
		pub fn $module(mut self) -> Result<crate::$module::Builder<B>> {
			if self.payload {
				Err(Error::AlreadyDefined)?
			}

			self = self.protocol(Protocol::$protocol)?;
			self.prepare();

			let mut builder = crate::$module::Builder::with(self.buffer)?;
			builder.finalizer().extend(self.finalizer);

			Ok(builder)
		}
	)
}

impl<B: Buffer> Builder<B> {
	/// Differentiated Services Code Point.
	pub fn dscp(mut self, value: u8) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_dscp(value)?;
		Ok(self)
	}

	/// Explicit Congestion Notification.
	pub fn ecn(mut self, value: u8) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_ecn(value)?;
		Ok(self)
	}

	/// Packet ID.
	pub fn id(mut self, value: u16) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_id(value)?;
		Ok(self)
	}

	/// Packet flags.
	pub fn flags(mut self, value: Flags) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_flags(value)?;
		Ok(self)
	}

	/// Packet fragment offset.
	pub fn offset(mut self, value: u16) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_offset(value)?;
		Ok(self)
	}

	/// Time to Live.
	pub fn ttl(mut self, value: u8) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_ttl(value)?;
		Ok(self)
	}

	/// Source address.
	pub fn source(mut self, value: Ipv4Addr) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_source(value)?;
		Ok(self)
	}

	/// Destination address.
	pub fn destination(mut self, value: Ipv4Addr) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_destination(value)?;
		Ok(self)
	}

	/// Inner protocol.
	pub fn protocol(mut self, value: Protocol) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_protocol(value)?;
		Ok(self)
	}

	/// Payload for the packet.
	pub fn payload<'a, T: IntoIterator<Item = &'a u8>>(mut self, value: T) -> Result<Self> {
		if self.payload {
			Err(Error::AlreadyDefined)?
		}

		self.payload = true;

		for byte in value {
			self.buffer.more(1)?;
			*self.buffer.data_mut().last_mut().unwrap() = *byte;
		}

		Ok(self)
	}

	fn prepare(&mut self) {
		let offset = self.buffer.offset();
		let length = self.buffer.length();

		self.finalizer.add(move |out| {
			// Set the version to 4 and the header length.
			let header = length / 4;
			out[offset] = (4 << 4) | header as u8;

			// Calculate and write the total length of the packet.
			let length = length + (out.len() - (offset + length));
			Cursor::new(&mut out[offset + 2 ..])
				.write_u16::<BigEndian>(length as u16)?;

			// Calculate and write the checksum.
			let checksum = checksum(&out[offset .. offset + header * 4]);
			Cursor::new(&mut out[offset + 10 ..])
				.write_u16::<BigEndian>(checksum)?;

			Ok(())
		});
	}

	protocol!(/// Build an ICMP packet.
		fn icmp(Icmp));

	protocol!(/// Build a TCP packet.
		fn tcp(Tcp));

	protocol!(/// Build a UDP packet.
		fn udp(Udp));
}

#[cfg(test)]
mod test {
	use std::net::Ipv4Addr;
	use crate::builder::Builder;
	use crate::ip;
	use crate::tcp;

	#[test]
	fn icmp() {
		let packet = ip::v4::Builder::default()
			.id(0x2d87).unwrap()
			.ttl(64).unwrap()
			.source("66.102.1.108".parse().unwrap()).unwrap()
			.destination("192.168.0.79".parse().unwrap()).unwrap()
			.icmp().unwrap()
				.echo().unwrap().request().unwrap()
					.identifier(42).unwrap()
					.sequence(2).unwrap()
					.payload(b"test").unwrap()
					.build().unwrap();

		let packet = ip::v4::Packet::new(packet).unwrap();

		assert_eq!(packet.id(), 0x2d87);
		assert!(packet.flags().is_empty());
		assert_eq!(packet.length(), 32);
		assert_eq!(packet.ttl(), 64);
		assert_eq!(packet.protocol(), ip::Protocol::Icmp);
		assert_eq!(packet.source(), "66.102.1.108".parse::<Ipv4Addr>().unwrap());
		assert_eq!(packet.destination(), "192.168.0.79".parse::<Ipv4Addr>().unwrap());
		assert!(packet.is_valid());
	}

	#[test]
	fn tcp() {
		let packet = ip::v4::Builder::default()
			.id(0x2d87).unwrap()
			.ttl(64).unwrap()
			.source("66.102.1.108".parse().unwrap()).unwrap()
			.destination("192.168.0.79".parse().unwrap()).unwrap()
			.tcp().unwrap()
				.source(1337).unwrap()
				.destination(9001).unwrap()
				.flags(tcp::flag::SYN).unwrap()
				.build().unwrap();

		let packet = ip::v4::Packet::new(packet).unwrap();
		assert_eq!(packet.id(), 0x2d87);
		assert!(packet.flags().is_empty());
		assert_eq!(packet.length(), 40);
		assert_eq!(packet.ttl(), 64);
		assert_eq!(packet.protocol(), ip::Protocol::Tcp);
		assert_eq!(packet.source(), "66.102.1.108".parse::<Ipv4Addr>().unwrap());
		assert_eq!(packet.destination(), "192.168.0.79".parse::<Ipv4Addr>().unwrap());
		assert!(packet.is_valid());
	}
}
