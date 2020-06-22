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
use std::io::Cursor;
use byteorder::{ReadBytesExt, WriteBytesExt, BigEndian};
use hwaddr::HwAddr;
use std::net::Ipv4Addr;

use error::*;
use packet::{Packet as P, PacketMut as PM, AsPacket, AsPacketMut};

/// ARP packet parser.
pub struct Packet<B> {
	pub(crate) buffer: B,
}

sized!(Packet,
	header {
		min:  28,
		max:  28,
		size: 28,
	}

	payload {
		min:  0,
		max:  18,
		size: p => p.buffer.as_ref().len() - 28,
	});

impl<B: AsRef<[u8]>> fmt::Debug for Packet<B> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("arp::Packet")
			.field("hardware_type", &self.hardware_type())
			.field("protocol_type", &self.protocol_type())
			.field("hardware_address_length", &self.hardware_address_length())
                        .field("protocol_address_length", &self.protocol_address_length())
			.field("operation", &self.operation())
			.field("sender_hardware_address", &self.sender_hardware_address())
			.field("sender_protocol_address", &self.sender_protocol_address())
			.field("target_hardware_address", &self.target_hardware_address())
			.field("target_protocol_address", &self.target_protocol_address())
			.finish()
	}
}

impl<B: AsRef<[u8]>> Packet<B> {
	/// Create a ARP packet without checking.
	pub fn unchecked(buffer: B) -> Packet<B> {
		Packet { buffer }
	}

	/// Parse an ARP packet, checking the buffer contents are correct.
	pub fn new(buffer: B) -> Result<Packet<B>> {
		use size::header::Min;
		let packet = Packet::unchecked(buffer);

		if packet.buffer.as_ref().len() < Self::min() {
			return Err(ErrorKind::SmallBuffer.into());
		}

		Ok(packet)
	}
}

impl<B: AsRef<[u8]>> Packet<B> {
	/// Convert the packet to its owned version.
	///
	/// # Notes
	///
	/// It would be nice if `ToOwned` could be implemented, but `Packet` already
	/// implements `Clone` and the impl would conflict.
	pub fn to_owned(&self) -> Packet<Vec<u8>> {
		Packet {
			buffer: self.buffer.as_ref().to_vec(),
		}
	}
}

impl<B: AsRef<[u8]>> AsRef<[u8]> for Packet<B> {
	fn as_ref(&self) -> &[u8] {
		use size::Size;

		&self.buffer.as_ref()[.. self.size()]
	}
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]> for Packet<B> {
	fn as_mut(&mut self) -> &mut [u8] {
		use size::Size;

		let size = self.size();
		&mut self.buffer.as_mut()[.. size]
	}
}

impl<'a, B: AsRef<[u8]>> AsPacket<'a, Packet<&'a [u8]>> for B {
	fn as_packet(&self) -> Result<Packet<&[u8]>> {
		Packet::new(self.as_ref())
	}
}

impl<'a, B: AsRef<[u8]> + AsMut<[u8]>> AsPacketMut<'a, Packet<&'a mut [u8]>> for B {
	fn as_packet_mut(&mut self) -> Result<Packet<&mut [u8]>> {
		Packet::new(self.as_mut())
	}
}

impl<B: AsRef<[u8]>> P for Packet<B> {
	fn split(&self) -> (&[u8], &[u8]) {
            self.buffer.as_ref().split_at(28)
	}
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> PM for Packet<B> {
	fn split_mut(&mut self) -> (&mut [u8], &mut [u8]) {
		self.buffer.as_mut().split_at_mut(28)
	}
}

impl<B: AsRef<[u8]>> Packet<B> {

        pub fn hardware_type(&self) -> u16 {
		(&self.buffer.as_ref()[0 ..]).read_u16::<BigEndian>().unwrap()
	}

	pub fn protocol_type(&self) -> u16 {
		(&self.buffer.as_ref()[2 ..]).read_u16::<BigEndian>().unwrap()
	}

	pub fn hardware_address_length(&self) -> u8 {
		(&self.buffer.as_ref()[4 ..]).read_u8().unwrap()
	}

	pub fn protocol_address_length(&self) -> u8 {
		(&self.buffer.as_ref()[5 ..]).read_u8().unwrap()
	}
	
	pub fn operation(&self) -> u16 {
		(&self.buffer.as_ref()[6 ..]).read_u16::<BigEndian>().unwrap()
	}
	
	pub fn sender_hardware_address(&self) -> HwAddr {
		self.buffer.as_ref()[8 .. 14].into()
	}

	pub fn sender_protocol_address(&self) -> Ipv4Addr {
            Ipv4Addr::new(
            self.buffer.as_ref()[14],
            self.buffer.as_ref()[15],
            self.buffer.as_ref()[16],
            self.buffer.as_ref()[17])
	}

	pub fn target_hardware_address(&self) -> HwAddr {
		self.buffer.as_ref()[18 .. 24].into()
	}
	
	pub fn target_protocol_address(&self) -> Ipv4Addr {
            Ipv4Addr::new(
            self.buffer.as_ref()[24],
            self.buffer.as_ref()[25],
            self.buffer.as_ref()[26],
            self.buffer.as_ref()[27])
	}
	
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> Packet<B> {
	/// Source port.
	pub fn set_hardware_type(&mut self, value: u16) -> Result<&mut Self> {
		Cursor::new(&mut self.header_mut()[0 ..])
			.write_u16::<BigEndian>(value)?;
		Ok(self)
	}

	pub fn set_protocol_type(&mut self, value: u16) -> Result<&mut Self> {
		Cursor::new(&mut self.header_mut()[2 ..])
			.write_u16::<BigEndian>(value)?;
		Ok(self)
	}

	pub fn set_hardware_address_length(&mut self, value: u8) -> Result<&mut Self> {
		Cursor::new(&mut self.header_mut()[4 ..])
			.write_u8(value)?;

		Ok(self)
	}

	pub fn set_protocol_address_length(&mut self, value: u8) -> Result<&mut Self> {
		Cursor::new(&mut self.header_mut()[5 ..])
			.write_u8(value)?;
		Ok(self)
	}

	pub fn set_operation(&mut self, value: u16) -> Result<&mut Self> {
		Cursor::new(&mut self.header_mut()[6 ..])
			.write_u16::<BigEndian>(value)?;
		Ok(self)
	}

	pub fn set_sender_hardware_address(&mut self, value: HwAddr) -> Result<&mut Self> {
		self.buffer.as_mut()[8 .. 14].copy_from_slice(&value.octets());
		Ok(self)
	}

	pub fn set_sender_protocol_address(&mut self, value: Ipv4Addr) -> Result<&mut Self> {
		self.header_mut()[14 .. 18].copy_from_slice(&value.octets());
		Ok(self)
	}

	pub fn set_target_hardware_address(&mut self, value: HwAddr) -> Result<&mut Self> {
		self.buffer.as_mut()[18 .. 24].copy_from_slice(&value.octets());
		Ok(self)
	}
	
	pub fn set_target_protocol_address(&mut self, value: Ipv4Addr) -> Result<&mut Self> {
		self.header_mut()[24 .. 28].copy_from_slice(&value.octets());
		Ok(self)
	}
}


#[cfg(test)]
mod test {
	use packet::{Packet, PacketMut};
	use ip;
	use udp;

	#[test]
	fn values() {
		let raw = [0x45u8, 0x00, 0x00, 0x42, 0x47, 0x07, 0x40, 0x00, 0x40, 0x11, 0x6e, 0xcc, 0xc0, 0xa8, 0x01, 0x89, 0xc0, 0xa8, 0x01, 0xfe, 0xba, 0x2f, 0x00, 0x35, 0x00, 0x2e, 0x1d, 0xf8, 0xbc, 0x81, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x61, 0x70, 0x69, 0x0c, 0x73, 0x74, 0x65, 0x61, 0x6d, 0x70, 0x6f, 0x77, 0x65, 0x72, 0x65, 0x64, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x00, 0x01];

		let ip  = ip::v4::Packet::new(&raw[..]).unwrap();
		let udp = udp::Packet::new(ip.payload()).unwrap();

		assert!(ip.is_valid());
		assert!(udp.is_valid(&ip::Packet::from(&ip)));

		assert_eq!(udp.destination(), 53);
	}

	#[test]
	fn mutable() {
		let mut raw = [0x45u8, 0x00, 0x00, 0x42, 0x47, 0x07, 0x40, 0x00, 0x40, 0x11, 0x6e, 0xcc, 0xc0, 0xa8, 0x01, 0x89, 0xc0, 0xa8, 0x01, 0xfe, 0xba, 0x2f, 0x00, 0x35, 0x00, 0x2e, 0x1d, 0xf8, 0xbc, 0x81, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x61, 0x70, 0x69, 0x0c, 0x73, 0x74, 0x65, 0x61, 0x6d, 0x70, 0x6f, 0x77, 0x65, 0x72, 0x65, 0x64, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x00, 0x01];

		let mut ip    = ip::v4::Packet::new(&mut raw[..]).unwrap();
		let (ip, udp) = ip.split_mut();
		let     ip    = ip::Packet::from(ip::v4::Packet::unchecked(ip));
		let mut udp   = udp::Packet::new(udp).unwrap();

		assert!(udp.is_valid(&ip));
		assert_eq!(udp.destination(), 53);

		udp.set_destination(9001).unwrap();
		assert_eq!(udp.destination(), 9001);
		assert!(!udp.is_valid(&ip));

		udp.update_checksum(&ip).unwrap();
		assert!(udp.is_valid(&ip));
	}

	#[test]
	fn mutable_checked() {
		let mut raw = [0x45u8, 0x00, 0x00, 0x42, 0x47, 0x07, 0x40, 0x00, 0x40, 0x11, 0x6e, 0xcc, 0xc0, 0xa8, 0x01, 0x89, 0xc0, 0xa8, 0x01, 0xfe, 0xba, 0x2f, 0x00, 0x35, 0x00, 0x2e, 0x1d, 0xf8, 0xbc, 0x81, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x61, 0x70, 0x69, 0x0c, 0x73, 0x74, 0x65, 0x61, 0x6d, 0x70, 0x6f, 0x77, 0x65, 0x72, 0x65, 0x64, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x1c, 0x00, 0x01];

		let mut ip        = ip::v4::Packet::new(&mut raw[..]).unwrap();
		let (ip, mut udp) = ip.split_mut();
		let     ip        = ip::Packet::from(ip::v4::Packet::unchecked(ip));
		let mut udp       = udp::Packet::new(udp).unwrap();

		assert!(udp.is_valid(&ip));
		assert_eq!(udp.destination(), 53);

		udp.checked(&ip).set_destination(9001).unwrap();
		assert_eq!(udp.destination(), 9001);
		assert!(udp.is_valid(&ip));
	}
}
