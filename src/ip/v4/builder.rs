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

use buffer::{self, Buffer};
use size::Min;
use ip::Protocol;
use ip::v4::Packet;
use ip::v4::Flags;
use ip::v4::option;

pub struct Builder<B = buffer::Dynamic> {
	buffer: B,
}

impl Default for Builder<buffer::Dynamic> {
	fn default() -> Self {
		Builder {
			buffer: buffer::Dynamic::default(),
		}
	}
}

impl<B: Buffer> Builder<B> {
	pub fn new(buffer: B) -> Builder<B> {
		Builder {
			buffer: buffer,
		}
	}
}
