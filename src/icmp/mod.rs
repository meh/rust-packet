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

mod kind;
pub use self::kind::Kind;

pub mod code;

mod packet;
pub use self::packet::*;

pub mod builder;
pub use self::builder::Builder;

pub fn checksum(buffer: &[u8]) -> u16 {
	use std::io::Cursor;
	use byteorder::{ReadBytesExt, BigEndian};

	let mut acc = 0xffffu32;
	let mut buf = Cursor::new(buffer);

	while let Ok(value) = buf.read_u16::<BigEndian>() {
		// Skip checksum field.
		if buf.position() == 4 {
			continue;
		}

		acc += value as u32;

		if acc > 0xffff {
			acc -= 0xffff;
		}
	}

	!acc as u16
}
