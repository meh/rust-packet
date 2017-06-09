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
use icmp::checksum;

pub struct Builder<B: Buffer = buffer::Dynamic> {
	buffer:    B,
	finalizer: Finalization,
}

impl<B: Buffer> Build<B> for Builder<B> {
	fn with(buffer: B) -> Result<Self> {
		Ok(Builder {
			buffer:    buffer,
			finalizer: Default::default(),
		})
	}

	fn finalizer(&mut self) -> &mut Finalization {
		&mut self.finalizer
	}

	fn build(self) -> Result<B::Inner> {
		Err(ErrorKind::InvalidPacket.into())
	}
}

impl Default for Builder<buffer::Dynamic> {
	fn default() -> Self {
		Builder::with(buffer::Dynamic::default()).unwrap()
	}
}

impl<B: Buffer> Builder<B> {
	pub fn echo(self) -> Result<echo::Builder<B>> {
		let mut echo = echo::Builder::with(self.buffer)?;
		echo.finalizer().extend(self.finalizer.into());

		Ok(echo)
	}

	pub fn timestamp(self) -> Result<timestamp::Builder<B>> {
		let mut timestamp = timestamp::Builder::with(self.buffer)?;
		timestamp.finalizer().extend(self.finalizer.into());

		Ok(timestamp)
	}
}

fn prepare<B: Buffer>(finalizer: &mut Finalization, buffer: &B) {
	let offset = buffer.offset();
	let length = buffer.length();

	finalizer.add(move |out| {
		let checksum = checksum(&out[offset .. offset + length]);
		Cursor::new(&mut out[offset + 2 ..])
			.write_u16::<BigEndian>(checksum)?;

		Ok(())
	});
}

pub mod echo {
	use std::io::Cursor;
	use byteorder::{WriteBytesExt, BigEndian};

	use error::*;
	use buffer::{self, Buffer};
	use builder::{Builder as Build, Finalization};
	use icmp::Kind;

	pub struct Builder<B: Buffer = buffer::Dynamic> {
		buffer:    B,
		finalizer: Finalization,

		kind:    bool,
		payload: bool,
	}

	impl<B: Buffer> Build<B> for Builder<B> {
		fn with(mut buffer: B) -> Result<Self> {
			buffer.next(8)?;

			Ok(Builder {
				buffer:    buffer,
				finalizer: Default::default(),

				kind:    false,
				payload: false,
			})
		}

		fn finalizer(&mut self) -> &mut Finalization {
			&mut self.finalizer
		}

		fn build(mut self) -> Result<B::Inner> {
			if !self.kind {
				return Err(ErrorKind::InvalidPacket.into());
			}

			super::prepare(&mut self.finalizer, &self.buffer);

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
		pub fn request(mut self) -> Result<Self> {
			self.kind = true;
			self.buffer.data_mut()[0] = Kind::EchoRequest.into();

			Ok(self)
		}

		pub fn reply(mut self) -> Result<Self> {
			self.kind = true;
			self.buffer.data_mut()[0] = Kind::EchoReply.into();

			Ok(self)
		}

		pub fn identifier(mut self, value: u16) -> Result<Self> {
			Cursor::new(&mut self.buffer.data_mut()[4 ..])
				.write_u16::<BigEndian>(value)?;

			Ok(self)
		}

		pub fn sequence(mut self, value: u16) -> Result<Self> {
			Cursor::new(&mut self.buffer.data_mut()[6 ..])
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
	}
}

pub mod timestamp {
	use std::io::Cursor;
	use byteorder::{WriteBytesExt, BigEndian};

	use error::*;
	use buffer::{self, Buffer};
	use builder::{Builder as Build, Finalization};
	use icmp::Kind;

	pub struct Builder<B: Buffer = buffer::Dynamic> {
		buffer:    B,
		finalizer: Finalization,

		kind: bool,
	}

	impl<B: Buffer> Build<B> for Builder<B> {
		fn with(mut buffer: B) -> Result<Self> {
			buffer.next(20)?;

			Ok(Builder {
				buffer:    buffer,
				finalizer: Default::default(),

				kind: false,
			})
		}

		fn finalizer(&mut self) -> &mut Finalization {
			&mut self.finalizer
		}

		fn build(mut self) -> Result<B::Inner> {
			if !self.kind {
				return Err(ErrorKind::InvalidPacket.into());
			}

			super::prepare(&mut self.finalizer, &self.buffer);

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
		pub fn request(mut self) -> Result<Self> {
			self.kind = true;
			self.buffer.data_mut()[0] = Kind::TimestampRequest.into();

			Ok(self)
		}

		pub fn reply(mut self) -> Result<Self> {
			self.kind = true;
			self.buffer.data_mut()[0] = Kind::TimestampReply.into();

			Ok(self)
		}

		pub fn identifier(mut self, value: u16) -> Result<Self> {
			Cursor::new(&mut self.buffer.data_mut()[4 ..])
				.write_u16::<BigEndian>(value)?;

			Ok(self)
		}

		pub fn sequence(mut self, value: u16) -> Result<Self> {
			Cursor::new(&mut self.buffer.data_mut()[6 ..])
				.write_u16::<BigEndian>(value)?;

			Ok(self)
		}

		pub fn originate(mut self, value: u32) -> Result<Self> {
			Cursor::new(&mut self.buffer.data_mut()[8 ..])
				.write_u32::<BigEndian>(value)?;

			Ok(self)
		}

		pub fn receive(mut self, value: u32) -> Result<Self> {
			Cursor::new(&mut self.buffer.data_mut()[12 ..])
				.write_u32::<BigEndian>(value)?;

			Ok(self)
		}

		pub fn transmit(mut self, value: u32) -> Result<Self> {
			Cursor::new(&mut self.buffer.data_mut()[16 ..])
				.write_u32::<BigEndian>(value)?;

			Ok(self)
		}
	}
}

pub mod information {
	use std::io::Cursor;
	use byteorder::{WriteBytesExt, BigEndian};

	use error::*;
	use buffer::{self, Buffer};
	use builder::{Builder as Build, Finalization};
	use icmp::Kind;

	pub struct Builder<B: Buffer = buffer::Dynamic> {
		buffer:    B,
		finalizer: Finalization,

		kind: bool,
	}

	impl<B: Buffer> Build<B> for Builder<B> {
		fn with(mut buffer: B) -> Result<Self> {
			buffer.next(8)?;

			Ok(Builder {
				buffer:    buffer,
				finalizer: Default::default(),

				kind: false,
			})
		}

		fn finalizer(&mut self) -> &mut Finalization {
			&mut self.finalizer
		}

		fn build(mut self) -> Result<B::Inner> {
			if !self.kind {
				return Err(ErrorKind::InvalidPacket.into());
			}

			super::prepare(&mut self.finalizer, &self.buffer);

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
		pub fn request(mut self) -> Result<Self> {
			self.kind = true;
			self.buffer.data_mut()[0] = Kind::InformationRequest.into();

			Ok(self)
		}

		pub fn reply(mut self) -> Result<Self> {
			self.kind = true;
			self.buffer.data_mut()[0] = Kind::InformationReply.into();

			Ok(self)
		}

		pub fn identifier(mut self, value: u16) -> Result<Self> {
			Cursor::new(&mut self.buffer.data_mut()[4 ..])
				.write_u16::<BigEndian>(value)?;

			Ok(self)
		}

		pub fn sequence(mut self, value: u16) -> Result<Self> {
			Cursor::new(&mut self.buffer.data_mut()[6 ..])
				.write_u16::<BigEndian>(value)?;

			Ok(self)
		}
	}
}

#[cfg(test)]
mod test {
	use builder::Builder;
	use packet::Packet;
	use icmp;

	#[test]
	fn simple() {
		let packet = icmp::Builder::default()
			.echo().unwrap().request().unwrap()
				.identifier(42).unwrap()
				.sequence(2).unwrap()
				.payload(b"test").unwrap()
				.build().unwrap();

		let packet = icmp::Packet::new(packet).unwrap();
		assert_eq!(packet.kind(), icmp::Kind::EchoRequest);
	}
}
