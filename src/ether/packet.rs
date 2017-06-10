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

use std::fmt;
use byteorder::{ReadBytesExt, BigEndian};
use hwaddr::HwAddr;

use error::*;
use packet::Packet as P;
use ether::Protocol;

pub struct Packet<B> {
	buffer: B,
}

sized!(Packet,
	header {
		min:  14,
		max:  14,
		size: 14,
	}

	payload {
		min:  0,
		max:  1486,
		size: p => p.buffer.as_ref().len() - 14,
	});

impl<B: AsRef<[u8]>> fmt::Debug for Packet<B> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("ether::Packet")
			.field("destination", &self.source())
			.field("source", &self.destination())
			.field("protocol", &self.protocol())
			.field("payload", &self.payload())
			.finish()
	}
}

impl<B: AsRef<[u8]>> Packet<B> {
	pub fn new(buffer: B) -> Result<Packet<B>> {
		use size::header::Min;

		let packet = Packet {
			buffer: buffer,
		};

		if packet.buffer.as_ref().len() < Self::min() {
			return Err(ErrorKind::SmallBuffer.into());
		}

		Ok(packet)
	}

	pub fn to_owned(&self) -> Packet<Vec<u8>> {
		Packet::new(self.buffer.as_ref().to_vec()).unwrap()
	}
}

impl<B: AsRef<[u8]>> AsRef<[u8]> for Packet<B> {
	fn as_ref(&self) -> &[u8] {
		use size::Size;

		&self.buffer.as_ref()[.. self.size()]
	}
}

impl<B: AsRef<[u8]>> P for Packet<B> {
	fn header(&self) -> &[u8] {
		&self.buffer.as_ref()[.. 14]
	}

	fn payload(&self) -> &[u8] {
		&self.buffer.as_ref()[14 ..]
	}
}

impl<B: AsRef<[u8]>> Packet<B> {
	pub fn destination(&self) -> HwAddr {
		self.buffer.as_ref()[0 .. 6].into()
	}

	pub fn source(&self) -> HwAddr {
		self.buffer.as_ref()[6 .. 12].into()
	}

	pub fn protocol(&self) -> Protocol {
		(&self.buffer.as_ref()[12 ..]).read_u16::<BigEndian>().unwrap().into()
	}
}

#[cfg(test)]
mod test {
	use packet::Packet;
	use ether;
	use ip;
	use udp;

	#[test]
	fn values() {
		let raw = [0x00u8, 0x23, 0x69, 0x63, 0x59, 0xbe, 0xe4, 0xb3, 0x18, 0x26, 0x63, 0xa3, 0x08, 0x00, 0x45, 0x00, 0x00, 0x42, 0x47, 0x07, 0x40, 0x00, 0x40, 0x11, 0x6e, 0xcc, 0xc0, 0xa8, 0x01, 0x89, 0xc0, 0xa8, 0x01, 0xfe, 0xba, 0x2f, 0x00, 0x35, 0x00, 0x2e, 0x1d, 0xf8, 0xbc, 0x81, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x61, 0x70, 0x69, 0x0c, 0x73, 0x74, 0x65, 0x61, 0x6d, 0x70, 0x6f, 0x77, 0x65, 0x72, 0x65, 0x64, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x00, 0x01];

		let ether = ether::Packet::new(&raw[..]).unwrap();
		let ip    = ip::v4::Packet::new(ether.payload()).unwrap();
		let udp   = udp::Packet::new(ip.payload()).unwrap();

		assert!(ip.is_valid());
		assert!(udp.is_valid(&ip::Packet::from(&ip)));
		
		assert_eq!(ether.destination(), "00:23:69:63:59:be".parse().unwrap());
		assert_eq!(ether.source(), "e4:b3:18:26:63:a3".parse().unwrap());
		assert_eq!(ether.protocol(), ether::Protocol::Ipv4);
	}
}
