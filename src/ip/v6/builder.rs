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




use crate::error::*;
use crate::buffer::{self, Buffer};
use crate::builder::{Builder as Build, Finalization};

/// IPv6 packet builder.
#[allow(dead_code)]
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
		Err(Error::InvalidPacket)
	}
}

impl Default for Builder<buffer::Dynamic> {
	fn default() -> Self {
		Builder::with(buffer::Dynamic::default()).unwrap()
	}
}
