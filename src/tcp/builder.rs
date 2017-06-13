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
use tcp::Packet;
use tcp::Flags;
use tcp::checksum;

#[derive(Debug)]
pub struct Builder<B: Buffer = buffer::Dynamic> {
	buffer:    B,
	finalizer: Finalization,

	ip:      (usize, usize),
	options: bool,
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

	pub fn sequence(mut self, value: u32) -> Result<Self> {
		Cursor::new(&mut self.buffer.data_mut()[4 ..])
			.write_u32::<BigEndian>(value)?;

		Ok(self)
	}

	pub fn acknowledgment(mut self, value: u32) -> Result<Self> {
		Cursor::new(&mut self.buffer.data_mut()[8 ..])
			.write_u32::<BigEndian>(value)?;

		Ok(self)
	}

	pub fn offset(mut self, value: u8) -> Result<Self> {
		if value > 0b1111 {
			return Err(ErrorKind::InvalidValue.into());
		}

		let old = self.buffer.data()[12];
		self.buffer.data_mut()[12] = (old & 0b1111) | value << 4;

		Ok(self)
	}

	pub fn flags(mut self, value: Flags) -> Result<Self> {
		let old = self.buffer.data()[12] & 0b1111_0000;

		Cursor::new(&mut self.buffer.data_mut()[12 ..])
			.write_u16::<BigEndian>(value.bits())?;

		self.buffer.data_mut()[12] |= old;

		Ok(self)
	}

	pub fn window(mut self, value: u16) -> Result<Self> {
		Cursor::new(&mut self.buffer.data_mut()[14 ..])
			.write_u16::<BigEndian>(value)?;

		Ok(self)
	}

	pub fn pointer(mut self, value: u16) -> Result<Self> {
		Cursor::new(&mut self.buffer.data_mut()[18 ..])
			.write_u16::<BigEndian>(value)?;

		Ok(self)
	}

	pub fn payload<'a, T: IntoIterator<Item = &'a u8>>(mut self, value: T) -> Result<Self> {
		if self.payload {
			return Err(ErrorKind::AlreadyDefined.into());
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
			let tcp             = &mut after[.. length];

			let checksum: Result<u16> = if let Ok(packet) = ip::v4::Packet::new(&ip) {
				Ok(checksum(&ip::Packet::from(packet), tcp))
			}
			else if let Ok(packet) = ip::v6::Packet::new(&ip) {
				Ok(checksum(&ip::Packet::from(packet), tcp))
			}
			else {
				Err(ErrorKind::InvalidPacket.into())
			};

			Cursor::new(&mut tcp[16 ..])
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
	use tcp;

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
				.build().unwrap();

		let ip = ip::v4::Packet::new(packet).unwrap();
		assert_eq!(ip.id(), 0x2d87);
		assert!(ip.flags().is_empty());
		assert_eq!(ip.length(), 40);
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
