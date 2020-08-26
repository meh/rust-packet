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

use crate::ip;
use crate::ip::Protocol;

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

		ip::Packet::V6(ref _packet) => {
			unimplemented!();
		}
	};

	let mut result = 0x0000u32;
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

	if let Ok(value) = buffer.read_u8() {
		// if we have a trailing byte, make a padded 16-bit value.
		let value = (value as u16) << 8;

		result += u32::from(value);

		if result > 0xffff {
			result -= 0xffff;
		}
	}

	!result as u16
}

#[cfg(test)]
mod tests {
	use crate::{tcp, ip, Packet};
	use crate::tcp::checksum;

	#[test]
	fn test_checksum() {
		let raw = [
			// IPv4
			0x45, 0x00, 0x00, 0xc9, 0xeb, 0xbe, 0x40, 0x00, 0x40, 0x06, 0x3a, 0x6e, 0x0a, 0x00,
			0x00, 0x02, 0x0a, 0x00, 0x00, 0x01,
			// TCP
			0x85, 0x82, 0x56, 0x01, 0xfb, 0xcd, 0xd4, 0x09, 0x63, 0x72, 0x03, 0xe8,
			0x80, 0x18, 0x01, 0xf9, 0xa1, 0xca, 0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0xf6, 0x4a,
			0xb5, 0x4f, 0x5f, 0xc6, 0xd4, 0x99,
			// data
			0x03, 0xbb, 0x30, 0xb9, 0xd3, 0xda, 0x24, 0x2d, 0x8b, 0xd0, 0x10, 0x4b, 0xd3, 0x65,
			0xba, 0x1a, 0x43, 0xf8, 0x08, 0xd0, 0x98, 0x29, 0x5d, 0x08, 0x64, 0x31, 0x09, 0xc8,
			0xdc, 0xb7, 0x02, 0xef, 0x5c, 0xae, 0x34, 0xfd, 0x1f, 0xf9, 0x6d, 0x18, 0x4a, 0x2a,
			0x3a, 0xec, 0x50, 0xb7, 0xae, 0xef, 0x85, 0x86, 0x7d, 0x7b, 0x22, 0x54, 0xfd, 0xec,
			0x3f, 0x53, 0x09, 0x18, 0xa8, 0x6d, 0x3d, 0x78, 0x25, 0x1c, 0x74, 0x47, 0x81, 0x98,
			0x88, 0xe6, 0x26, 0x94, 0x17, 0xfc, 0x8a, 0xec, 0xc5, 0xc4, 0x56, 0xad, 0xca, 0x0f,
			0x02, 0x5c, 0x7d, 0x00, 0xa7, 0x91, 0xc3, 0xf0, 0x71, 0x05, 0xb0, 0xe6, 0xa3, 0xa7,
			0xee, 0x70, 0x4b, 0xfd, 0x27, 0xa4, 0x95, 0xcc, 0xd1, 0xa7, 0x5a, 0x78, 0x37, 0x49,
			0x36, 0x30, 0xe3, 0x46, 0xf6, 0x23, 0x4d, 0x48, 0x27, 0xad, 0x5a, 0x25, 0xf9, 0x3f,
			0xc3, 0xd4, 0x28, 0xe3, 0x24, 0xf7, 0xd0, 0x8b, 0x44, 0x8b, 0xa2, 0x5d, 0x10, 0xa2,
			0xfe, 0x1f, 0x9c, 0x5b, 0x62, 0x84, 0xc1, 0x8f, 0x21
		];

		let ip  = ip::v4::Packet::new(&raw[..]).unwrap();
		let tcp = tcp::Packet::new(ip.payload()).unwrap();

		assert_eq!(checksum(&ip::Packet::V4(ip), ip.payload()), tcp.checksum());
	}
}
