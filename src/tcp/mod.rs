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

/// TCP flags.
pub mod flag;
pub use self::flag::Flags;

/// TCP options.
pub mod option;
pub use self::option::Option;

mod packet;
pub use self::packet::Packet;

mod builder;
pub use self::builder::Builder;

use ip;
use ip::Protocol;

/// Calculate the checksum for a TCP packet.
///
/// # Note
///
/// Since the checksum for UDP packets includes a pseudo-header based on the
/// enclosing IP packet, one has to be given.
pub fn checksum<B: AsRef<[u8]>>(ip: &ip::Packet<B>, buffer: &[u8]) -> u16 {
	use std::io::Cursor;
	use byteorder::{WriteBytesExt, ReadBytesExt, BigEndian};

	let mut prefix = [0u8; 40];
	match *ip {
		ip::Packet::V4(ref packet) => {
			prefix[0 .. 4].copy_from_slice(&packet.source().octets());
			prefix[4 .. 8].copy_from_slice(&packet.destination().octets());

			prefix[9] = Protocol::Tcp.into();
			Cursor::new(&mut prefix[10 ..])
				.write_u16::<BigEndian>(buffer.len() as u16).unwrap();
		}

		ip::Packet::V6(ref packet) => {
			unimplemented!();
		}
	};

	let mut result = 0xffffu32;
	let mut buffer = Cursor::new(buffer);
	let mut prefix = match *ip {
		ip::Packet::V4(_) =>
			Cursor::new(&prefix[0 .. 12]),

		ip::Packet::V6(_) =>
			Cursor::new(&prefix[0 .. 40]),
	};

	while let Ok(value) = prefix.read_u16::<BigEndian>() {
		result += u32::from(value);

		if result > 0xffff {
			result -= 0xffff;
		}
	}

	while let Ok(value) = buffer.read_u16::<BigEndian>() {
		// Skip checksum field.
		if buffer.position() == 18 {
			continue;
		}

		result += u32::from(value);

		if result > 0xffff {
			result -= 0xffff;
		}
	}

	!result as u16
}
