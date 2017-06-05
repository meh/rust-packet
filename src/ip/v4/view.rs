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

use std::net::Ipv4Addr;

use ip::v4::Flags;

#[repr(C)]
pub struct View {
	version_and_header: u8,
	dscp_and_ecn:       u8,
	length:             u16,

	id:               u16,
	flags_and_offset: u16,

	ttl:      u8,
	protocol: u8,
	checksum: u16,

	source:      u32,
	destination: u32,

	options: [u32],
}

impl View {
	fn version(&self) -> u8 {
		self.version_and_header >> 4
	}

	fn header(&self) -> u8 {
		self.version_and_header & 0xf
	}

	fn dscp(&self) -> u8 {
		self.dscp_and_ecn >> 2
	}

	fn ecn(&self) -> u8 {
		self.dscp_and_ecn & 0x3
	}

	fn length(&self) -> u16 {
		self.length.from_be()
	}

	fn id(&self) -> u16 {
		self.id.from_be()
	}

	fn flags(&self) -> Flags {
		Flags::from_bits(self.flags_and_offset.from_be() >> 13)
	}

	fn offset(&self) -> u16 {
		self.flags_and_offset.from_be() & 0x1fff
	}

	fn ttl(&self) -> u8 {
		self.ttl
	}

	fn protocol(&self) -> u8 {
		self.protocol
	}

	fn checksum(&self) -> u16 {
		self.checksum
	}

	fn source(&self) -> Ipv4Addr {
		Ipv4Addr::new(
			((self.source      ) & 0xff) as u8,
			((self.source >>  8) & 0xff) as u8,
			((self.source >> 16) & 0xff) as u8,
			((self.source >> 24) & 0xff) as u8))
	}

	fn destination(&self) -> Ipv4Addr {
		Ipv4Addr::new(
			((self.destination      ) & 0xff) as u8,
			((self.destination >>  8) & 0xff) as u8,
			((self.destination >> 16) & 0xff) as u8,
			((self.destination >> 24) & 0xff) as u8))
	}

	fn options(&self) -> &[u32] {
		&self.options
	}
}
