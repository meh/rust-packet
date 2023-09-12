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

use byteorder::{BigEndian, WriteBytesExt};
use hwaddr::HwAddr;
use std::io::Cursor;

use crate::buffer::{self, Buffer};
use crate::builder::{Builder as Build, Finalization};
use crate::error::*;
use crate::ether::Packet;
use crate::ether::Protocol;
use crate::packet::{AsPacket, AsPacketMut};

/// Ethernet frame builder.
#[derive(Debug)]
pub struct Builder<B: Buffer = buffer::Dynamic> {
    buffer: B,
    finalizer: Finalization,

    payload: bool,
}

impl<B: Buffer> Build<B> for Builder<B> {
    fn with(mut buffer: B) -> Result<Self> {
        use crate::size::header::Min;
        buffer.next(Packet::<()>::min())?;

        Ok(Builder {
            buffer,
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
    /// MAC address for the destination.
    pub fn destination(mut self, value: HwAddr) -> Result<Self> {
        Packet::unchecked(self.buffer.data_mut()).set_destination(value)?;

        Ok(self)
    }

    /// MAC address for the source.
    pub fn source(mut self, value: HwAddr) -> Result<Self> {
        Packet::unchecked(self.buffer.data_mut()).set_source(value)?;

        Ok(self)
    }

    /// Protocol of the inner packet.
    pub fn protocol(mut self, value: Protocol) -> Result<Self> {
        Packet::unchecked(self.buffer.data_mut()).set_protocol(value)?;

        Ok(self)
    }

    /// Payload for the frame.
    pub fn payload<'a, T: IntoIterator<Item = &'a u8>>(mut self, value: T) -> Result<Self> {
        if self.payload {
            Err(Error::AlreadyDefined)?
        }

        self.payload = true;

        for byte in value {
            self.buffer.more(1)?;
            *self.buffer.data_mut().last_mut().unwrap() = *byte;
        }

        Ok(self)
    }

    /// Build an IP packet inside the Ethernet frame.
    pub fn ip(mut self) -> Result<crate::ip::Builder<B>> {
        if self.payload {
            Err(Error::AlreadyDefined)?
        }

        let offset = self.buffer.offset();
        let length = self.buffer.length();

        self.finalizer.add(move |out| {
            match out[offset + length] >> 4 {
                4 => Cursor::new(&mut out[offset + 12..])
                    .write_u16::<BigEndian>(Protocol::Ipv4.into())?,

                6 => Cursor::new(&mut out[offset + 12..])
                    .write_u16::<BigEndian>(Protocol::Ipv6.into())?,

                _ => unreachable!(),
            }

            Ok(())
        });

        let mut ip = crate::ip::Builder::with(self.buffer)?;
        ip.finalizer().extend(self.finalizer);

        Ok(ip)
    }
}

#[cfg(test)]
mod test {
    use crate::builder::Builder;
    use crate::ether;
    use crate::ip;
    use crate::packet::Packet;
    use crate::udp;
    use std::net::Ipv4Addr;

    #[test]
    fn simple() {
        let packet = ether::Builder::default()
            .destination("00:23:69:63:59:be".parse().unwrap())
            .unwrap()
            .source("e4:b3:18:26:63:a3".parse().unwrap())
            .unwrap()
            .ip()
            .unwrap()
            .v4()
            .unwrap()
            .id(0x2d87)
            .unwrap()
            .ttl(64)
            .unwrap()
            .source("66.102.1.108".parse().unwrap())
            .unwrap()
            .destination("192.168.0.79".parse().unwrap())
            .unwrap()
            .udp()
            .unwrap()
            .source(1337)
            .unwrap()
            .destination(9001)
            .unwrap()
            .build()
            .unwrap();

        let ether = ether::Packet::new(packet).unwrap();
        assert_eq!(ether.destination(), "00:23:69:63:59:be".parse().unwrap());
        assert_eq!(ether.source(), "e4:b3:18:26:63:a3".parse().unwrap());
        assert_eq!(ether.protocol(), ether::Protocol::Ipv4);

        let ip = ip::v4::Packet::new(ether.payload()).unwrap();
        assert_eq!(ip.id(), 0x2d87);
        assert!(ip.flags().is_empty());
        assert_eq!(ip.length(), 28);
        assert_eq!(ip.ttl(), 64);
        assert_eq!(ip.protocol(), ip::Protocol::Udp);
        assert_eq!(ip.source(), "66.102.1.108".parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            ip.destination(),
            "192.168.0.79".parse::<Ipv4Addr>().unwrap()
        );
        assert!(ip.is_valid());

        let udp = udp::Packet::new(ip.payload()).unwrap();
        assert_eq!(udp.source(), 1337);
        assert_eq!(udp.destination(), 9001);
        assert!(udp.is_valid(&ip::Packet::from(&ip)));
    }
}
