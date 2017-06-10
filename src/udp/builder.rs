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

use error::*;
use buffer::{self, Buffer};
use builder::{Builder as Build, Finalization};
use ip;
use udp::Packet;
use udp::checksum;

pub struct Builder<B: Buffer = buffer::Dynamic> {
	buffer:    B,
	finalizer: Finalization,

	ip:      (usize, usize),
	payload: bool,
}

impl<B: Buffer> Build<B> for Builder<B> {
	fn with(mut buffer: B) -> Result<Self> {
		let ip = (buffer.offset(), buffer.length());

		use size::header::Min;
		buffer.next(Packet::<()>::min())?;

		Ok(Builder {
			buffer:    buffer,
			finalizer: Default::default(),

			ip:      ip,
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

impl<B: Buffer> Builder<B> {
	pub fn source(mut self, value: u16) -> Result<Self> {
		Cursor::new(&mut self.buffer.data_mut()[0 ..])
			.write_u16::<BigEndian>(value)?;

		Ok(self)
	}

	pub fn destination(mut self, value: u16) -> Result<Self> {
		Cursor::new(&mut self.buffer.data_mut()[2 ..])
			.write_u16::<BigEndian>(value)?;

		Ok(self)
	}

	pub fn payload<'a, T: IntoIterator<Item = &'a u8>>(mut self, value: T) -> Result<Self> {
		if self.payload {
			return Err(ErrorKind::InvalidPacket.into());
		}

		self.payload = true;

		for byte in value.into_iter() {
			self.buffer.more(1)?;
			*self.buffer.data_mut().last_mut().unwrap() = *byte;
		}

		Ok(self)
	}

	fn prepare(&mut self) {
		let ip     = self.ip;
		let length = self.buffer.length();

		self.finalizer.add(move |out| {
			let (before, after) = out.split_at_mut(ip.0 + ip.1);
			let ip              = &mut before[ip.0 ..];
			let udp             = &mut after[.. length];

			Cursor::new(&mut udp[4 ..])
				.write_u16::<BigEndian>(length as u16)?;

			let checksum: Result<u16> = if let Ok(packet) = ip::v4::Packet::new(&ip) {
				Ok(checksum(&ip::Packet::from(packet), udp))
			}
			else if let Ok(packet) = ip::v6::Packet::new(&ip) {
				Ok(checksum(&ip::Packet::from(packet), udp))
			}
			else {
				Err(ErrorKind::InvalidPacket.into())
			};

			Cursor::new(&mut udp[6 ..])
				.write_u16::<BigEndian>(checksum?)?;

			Ok(())
		});
	}
}

#[cfg(test)]
mod test {
	use std::net::Ipv4Addr;
	use builder::Builder;
	use packet::Packet;
	use ip;
	use udp;

	#[test]
	fn simple() {
		let packet = ip::v4::Builder::default()
			.id(0x2d87).unwrap()
			.ttl(64).unwrap()
			.source("66.102.1.108".parse().unwrap()).unwrap()
			.destination("192.168.0.79".parse().unwrap()).unwrap()
			.udp().unwrap()
				.source(1337).unwrap()
				.destination(9001).unwrap()
				.build().unwrap();

		let ip = ip::v4::Packet::new(packet).unwrap();
		assert_eq!(ip.id(), 0x2d87);
		assert!(ip.flags().is_empty());
		assert_eq!(ip.length(), 28);
		assert_eq!(ip.ttl(), 64);
		assert_eq!(ip.protocol(), ip::Protocol::Udp);
		assert_eq!(ip.source(), "66.102.1.108".parse::<Ipv4Addr>().unwrap());
		assert_eq!(ip.destination(), "192.168.0.79".parse::<Ipv4Addr>().unwrap());
		assert!(ip.is_valid());

		let udp = udp::Packet::new(ip.payload()).unwrap();
		assert_eq!(udp.source(), 1337);
		assert_eq!(udp.destination(), 9001);
		assert!(udp.is_valid(&ip::Packet::from(&ip)));
	}
}
