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
use std::net::Ipv4Addr;
use hwaddr::HwAddr;
use byteorder::{WriteBytesExt, BigEndian};

use error::*;
use buffer::{self, Buffer};
use builder::{Builder as Build, Finalization};
use packet::{AsPacket, AsPacketMut};
use arp::Packet;


#[derive(Debug)]
pub struct Builder<B: Buffer = buffer::Dynamic> {
	buffer:    B,
	finalizer: Finalization,

	payload: bool,
}


impl<B: Buffer> Build<B> for Builder<B> {
	fn with(mut buffer: B) -> Result<Self> {
		use size::header::Min;
		buffer.next(Packet::<()>::min())?;

		Ok(Builder {
			buffer:    buffer,
			finalizer: Default::default(),

			payload: false,
		})
	}

	fn finalizer(&mut self) -> &mut Finalization {
		&mut self.finalizer
	}

	fn build(self) -> Result<B::Inner> {
		let mut buffer = self.buffer.into_inner();
		self.finalizer.finalize(buffer.as_mut())?;
		Ok(buffer)
	}
}

impl Default for Builder<buffer::Dynamic> {
	fn default() -> Self {
		Builder::with(buffer::Dynamic::default()).unwrap()
	}
}

impl<'a, B: Buffer> AsPacket<'a, Packet<&'a [u8]>> for Builder<B> {
	fn as_packet(&self) -> Result<Packet<&[u8]>> {
		Packet::new(self.buffer.data())
	}
}

impl<'a, B: Buffer> AsPacketMut<'a, Packet<&'a mut [u8]>> for Builder<B> {
	fn as_packet_mut(&mut self) -> Result<Packet<&mut [u8]>> {
		Packet::new(self.buffer.data_mut())
	}
}


impl<B: Buffer> Builder<B> {

	pub fn hardware_type(mut self, value: u16) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_hardware_type(value)?;
		Ok(self)
	}

	pub fn protocol_type(mut self, value: u16) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_protocol_type(value)?;
		Ok(self)
	}
	
	pub fn hardware_address_length(mut self, value: u8) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_hardware_address_length(value)?;
		Ok(self)
	}

	pub fn protocol_address_length(mut self, value: u8) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_protocol_address_length(value)?;
		Ok(self)
	}
	
	pub fn operation(mut self, value: u16) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_operation(value)?;
		Ok(self)
	}
	
	pub fn sender_hardware_address(mut self, value: HwAddr) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_sender_hardware_address(value)?;
		Ok(self)
	}

	pub fn sender_protocol_address(mut self, value: Ipv4Addr) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_sender_protocol_address(value)?;
		Ok(self)
	}

	pub fn target_hardware_address(mut self, value: HwAddr) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_target_hardware_address(value)?;
		Ok(self)
	}

	pub fn target_protocol_address(mut self, value: Ipv4Addr) -> Result<Self> {
		Packet::unchecked(self.buffer.data_mut()).set_target_protocol_address(value)?;
		Ok(self)
	}	
	
}
