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

/// IPv4 flags.
pub mod flag;
pub use self::flag::Flags;

/// IPv4 option parser and builder.
pub mod option;
pub use self::option::Option;

mod packet;
pub use self::packet::Packet;

mod builder;
pub use self::builder::Builder;

/// Calculate the checksum for an IPv4 packet.
pub fn checksum(buffer: &[u8]) -> u16 {
	use std::io::Cursor;
	use byteorder::{ReadBytesExt, BigEndian};

	let mut result = 0xffffu32;
	let mut buffer = Cursor::new(buffer);

	while let Ok(value) = buffer.read_u16::<BigEndian>() {
		// Skip checksum field.
		if buffer.position() == 12 {
			continue;
		}

		result += u32::from(value);

		if result > 0xffff {
			result -= 0xffff;
		}
	}

	!result as u16
}
