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
use icmp::builder;
use icmp::Kind;

#[derive(Debug)]
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
