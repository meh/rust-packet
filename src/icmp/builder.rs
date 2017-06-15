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
use icmp::{echo, timestamp, information};

/// ICMP packet builder.
#[derive(Debug)]
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
	/// Build an Echo Request/Reply packet.
	pub fn echo(self) -> Result<echo::Builder<B>> {
		let mut echo = echo::Builder::with(self.buffer)?;
		echo.finalizer().extend(self.finalizer);

		Ok(echo)
	}

	/// Create a Timestamp Request/Reply packet.
	pub fn timestamp(self) -> Result<timestamp::Builder<B>> {
		let mut timestamp = timestamp::Builder::with(self.buffer)?;
		timestamp.finalizer().extend(self.finalizer);

		Ok(timestamp)
	}
}

pub(in icmp) fn prepare<B: Buffer>(finalizer: &mut Finalization, buffer: &B) {
	let offset = buffer.offset();
	let length = buffer.length();

	finalizer.add(move |out| {
		let checksum = checksum(&out[offset .. offset + length]);
		Cursor::new(&mut out[offset + 2 ..])
			.write_u16::<BigEndian>(checksum)?;

		Ok(())
	});
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
