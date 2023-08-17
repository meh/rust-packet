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
use crate::icmp::builder;
use crate::icmp::Kind;
use crate::icmp::information::Packet;

/// Information Request/Reply packet builder.
pub struct Builder<B: Buffer = buffer::Dynamic> {
	buffer:    B,
	finalizer: Finalization,

	kind: bool,
	payload: bool,
}

impl<B: Buffer> Build<B> for Builder<B> {
	fn with(mut buffer: B) -> Result<Self> {
		buffer.next(8)?;

		Ok(Builder {
			buffer:    buffer,
			finalizer: Default::default(),

			kind: false,
			payload: false,
		})
	}

	fn finalizer(&mut self) -> &mut Finalization {
		&mut self.finalizer
	}

	fn build(mut self) -> Result<B::Inner> {
		if !self.kind {
			Err(Error::InvalidPacket)?
		}

		builder::prepare(&mut self.finalizer, &self.buffer);

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
	/// Make it a request.
	pub fn request(mut self) -> Result<Self> {
		self.kind = true;
		self.buffer.data_mut()[0] = Kind::InformationRequest.into();

		Ok(self)
	}

	/// Make it a reply.
	pub fn reply(mut self) -> Result<Self> {
		self.kind = true;
		self.buffer.data_mut()[0] = Kind::InformationReply.into();

		Ok(self)
	}

	/// Packet identifier.
	pub fn identifier(mut self, value: u16) -> Result<Self> {
		Cursor::new(&mut self.buffer.data_mut()[4 ..])
			.write_u16::<BigEndian>(value)?;

		Ok(self)
	}

	/// Packet sequence.
	pub fn sequence(mut self, value: u16) -> Result<Self> {
		Cursor::new(&mut self.buffer.data_mut()[6 ..])
			.write_u16::<BigEndian>(value)?;

		Ok(self)
	}

	/// Payload for the packet.
	pub fn payload<'a, T: IntoIterator<Item = &'a u8>>(mut self, value: T) -> Result<Self> {
		if self.payload {
			Err(Error::InvalidPacket)?
		}

		self.payload = true;

		for byte in value {
			self.buffer.more(1)?;
			*self.buffer.data_mut().last_mut().unwrap() = *byte;
		}

		Ok(self)
	}
}

#[cfg(test)]
mod tests {
	use std::net::Ipv4Addr;
	use crate::{icmp, ip, Packet};
	use crate::ip::Protocol::Icmp;
	use super::*;

	#[test]
	fn information_reply() {
		let buffer = ip::v4::Builder::default()
			.source(Ipv4Addr::new(127, 0, 0, 1)).unwrap()
			.destination(Ipv4Addr::new(127, 0, 0, 16)).unwrap()
			.icmp().unwrap()
			.information().unwrap()
			.reply().unwrap()
			.payload("test payload".as_bytes()).unwrap()
			.build()
			.unwrap();

		let packet = ip::v4::Packet::new(&buffer).unwrap();
		assert_eq!(packet.source(), Ipv4Addr::new(127, 0, 0, 1));
		assert_eq!(packet.destination(), Ipv4Addr::new(127, 0, 0, 16));
		assert_eq!(packet.protocol(), Icmp);
		let string = packet.as_ref().to_vec().into_iter().map(|x| format!("{:02X?} ", x)).collect::<String>();
		let packet= icmp::Packet::new(packet.split().1.to_vec()).unwrap();
		assert_eq!(packet.kind(), Kind::InformationReply);
		assert_eq!(packet.payload()[4..].as_ref(), b"test payload");
	}
}