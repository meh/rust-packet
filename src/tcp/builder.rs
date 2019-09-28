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
use byteorder::{WriteBytesExt, BigEndian};

use crate::error::*;
use crate::buffer::{self, Buffer};
use crate::builder::{Builder as Build, Finalization};
use crate::packet::{AsPacket, AsPacketMut};
use crate::ip;
use crate::tcp::Packet;
use crate::tcp::Flags;
use crate::tcp::checksum;

/// TCP packet builder.
#[derive(Debug)]
pub struct Builder<B: Buffer = buffer::Dynamic> {
	buffer:    B,
	finalizer: Finalization,

	ip:      (usize, usize),
	options: bool,
	payload: bool,
	payload_length: usize,
}

impl<B: Buffer> Build<B> for Builder<B> {
	fn with(mut buffer: B) -> Result<Self> {
		let ip = (buffer.offset(), buffer.length());

		use crate::size::header::Min;
		buffer.next(Packet::<()>::min())?;

		// Set data offset to the minimum.
		//
		// XXX: This is needed for shit to work. The builder uses setters on the
		//      `tcp::Packet` which expect the data offset to be set.
		buffer.data_mut()[12] = ((Packet::<()>::min() / 4) as u8) << 4;

		Ok(Builder {
			buffer:    buffer,
			finalizer: Default::default(),

			ip:      ip,
			options: false,
			payload: false,
			payload_length: 0,
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

impl<B: Buffer> Builder<B> {
	/// Source port.
	pub fn source(mut self, value: u16) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_source(value)?;
		Ok(self)
	}

	/// Destination port.
	pub fn destination(mut self, value: u16) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_destination(value)?;
		Ok(self)
	}

	/// Packet sequence.
	pub fn sequence(mut self, value: u32) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_sequence(value)?;
		Ok(self)
	}

	/// Optional acknowledgment.
	pub fn acknowledgment(mut self, value: u32) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_acknowledgment(value)?;
		Ok(self)
	}

	/// Packet flags.
	pub fn flags(mut self, value: Flags) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_flags(value)?;
		Ok(self)
	}

	/// Packet window.
	pub fn window(mut self, value: u16) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_window(value)?;
		Ok(self)
	}

	/// Urgent pointer.
	pub fn pointer(mut self, value: u16) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_pointer(value)?;
		Ok(self)
	}

	/// Payload for the packet.
	pub fn payload<'a, T: IntoIterator<Item = &'a u8>>(mut self, value: T) -> Result<Self> {
		if self.payload {
			return Err(ErrorKind::AlreadyDefined.into());
		}

		self.payload = true;

		for byte in value {
			self.buffer.more(1)?;
			self.payload_length += 1;
			*self.buffer.data_mut().last_mut().unwrap() = *byte;
		}

		Ok(self)
	}

	fn prepare(&mut self) {
		let ip     = self.ip;
		let length = self.buffer.length();
		let payload_length = self.payload_length;

		self.finalizer.add(move |out| {
			// Split the buffer into IP and TCP parts.
			let (before, after) = out.split_at_mut(ip.0 + ip.1);
			let ip              = &mut before[ip.0 ..];
			let tcp             = &mut after[.. length];

			// Set the TCP data offset.
			let flags  = tcp[12] & 0b1111;

			let offset = ((length - payload_length) / 4) as u8;
			tcp[12] = offset << 4 | flags;

			// Calculate the checksum by parsing back the IP packet and set it.
			let checksum = checksum(&ip::Packet::no_payload(&ip)?, tcp);
			Cursor::new(&mut tcp[16 ..])
				.write_u16::<BigEndian>(checksum)?;

			Ok(())
		});
	}
}

#[cfg(test)]
mod test {
	use std::net::Ipv4Addr;
	use crate::builder::Builder;
	use crate::packet::Packet;
	use crate::ip;
	use crate::tcp;

	#[test]
	fn simple() {
		let packet = ip::v4::Builder::default()
			.id(0x2d87).unwrap()
			.ttl(64).unwrap()
			.source("66.102.1.108".parse().unwrap()).unwrap()
			.destination("192.168.0.79".parse().unwrap()).unwrap()
			.tcp().unwrap()
				.source(1337).unwrap()
				.destination(9001).unwrap()
				.flags(tcp::flag::SYN).unwrap()
				.payload(b"lol").unwrap()
				.build().unwrap();

		let ip = ip::v4::Packet::new(packet).unwrap();
		assert_eq!(ip.id(), 0x2d87);
		assert!(ip.flags().is_empty());
		assert_eq!(ip.length(), 43);
		assert_eq!(ip.ttl(), 64);
		assert_eq!(ip.protocol(), ip::Protocol::Tcp);
		assert_eq!(ip.source(), "66.102.1.108".parse::<Ipv4Addr>().unwrap());
		assert_eq!(ip.destination(), "192.168.0.79".parse::<Ipv4Addr>().unwrap());
		assert!(ip.is_valid());

		let tcp = tcp::Packet::new(ip.payload()).unwrap();
		assert_eq!(tcp.source(), 1337);
		assert_eq!(tcp.destination(), 9001);
		assert_eq!(tcp.flags(), tcp::flag::SYN);
		assert!(tcp.is_valid(&ip::Packet::from(&ip)));
	}
}
