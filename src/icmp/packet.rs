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

use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use std::fmt;
use std::io::Cursor;

use crate::error::*;
use crate::icmp::checksum;
use crate::icmp::Kind;
use crate::packet::{AsPacket, AsPacketMut, Packet as P, PacketMut as PM};

/// ICMP packet parser.
pub struct Packet<B> {
    buffer: B,
}

sized!(Packet,
header {
    min:  4,
    max:  4,
    size: 4,
}

payload {
    min:  0,
    size: p => p.buffer.as_ref().len() - 4,
});

impl<B: AsRef<[u8]>> fmt::Debug for Packet<B> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct(if self.is_valid() {
            "icmp::Packet"
        } else {
            "icmp::Packet!"
        })
        .field("kind", &self.kind())
        .field("code", &self.code())
        .field("checksum", &self.checksum())
        .field("payload", &self.payload())
        .finish()
    }
}

impl<B: AsRef<[u8]>> Packet<B> {
    /// Create an ICMP packet without checking the buffer.
    pub fn unchecked(buffer: B) -> Packet<B> {
        Packet { buffer }
    }

    /// Parse an ICMP packet, checking the buffer contents are correct.
    pub fn new(buffer: B) -> Result<Packet<B>> {
        use crate::size::header::Min;

        let packet = Packet::unchecked(buffer);

        if packet.buffer.as_ref().len() < Self::min() {
            Err(Error::SmallBuffer)?
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
        Packet::unchecked(self.buffer.as_ref().to_vec())
    }
}

impl<B: AsRef<[u8]>> AsRef<[u8]> for Packet<B> {
    fn as_ref(&self) -> &[u8] {
        use crate::size::Size;

        &self.buffer.as_ref()[..self.size()]
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> AsMut<[u8]> for Packet<B> {
    fn as_mut(&mut self) -> &mut [u8] {
        use crate::size::Size;

        let size = self.size();
        &mut self.buffer.as_mut()[..size]
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
        self.buffer.as_ref().split_at(4)
    }
}

impl<B: AsRef<[u8]> + AsMut<[u8]>> PM for Packet<B> {
    fn split_mut(&mut self) -> (&mut [u8], &mut [u8]) {
        self.buffer.as_mut().split_at_mut(4)
    }
}

macro_rules! kind {
	($(#[$attr:meta])* fn $module:ident[$mutable:ident]) => (
		$(#[$attr])*
		pub fn $module(&self) -> Result<crate::icmp::$module::Packet<&B>> {
			crate::icmp::$module::Packet::new(&self.buffer)
		}

		$(#[$attr])*
		pub fn $mutable(&mut self) -> Result<crate::icmp::$module::Packet<&mut B>> {
			crate::icmp::$module::Packet::new(&mut self.buffer)
		}
	)
}

impl<B: AsRef<[u8]>> Packet<B> {
    /// Packet type.
    pub fn kind(&self) -> Kind {
        Kind::from(self.buffer.as_ref()[0])
    }

    /// Packet code.
    pub fn code(&self) -> u8 {
        self.buffer.as_ref()[1]
    }

    /// Packet checksum.
    pub fn checksum(&self) -> u16 {
        (&self.buffer.as_ref()[2..])
            .read_u16::<BigEndian>()
            .unwrap()
    }

    /// Verify the packet is valid by calculating the checksum.
    pub fn is_valid(&self) -> bool {
        checksum(self.buffer.as_ref()) == self.checksum()
    }

    kind!(/// Parse an Echo Request/Reply packet.
		fn echo[echo_mut]);

    kind!(/// Parse a Timestamp Request/Reply packet.
		fn timestamp[timestamp_mut]);

    kind!(/// Parse an Information Request/Reply packet.
		fn information[information_mut]);

    kind!(/// Parse a Parameter Problem packet.
		fn parameter_problem[parameter_problem_mut]);

    kind!(/// Parse a Redirect Message packet.
		fn redirect_message[redirect_message_mut]);

    kind!(/// Parse a Source Quench, Destination Unreachable or Time Exceeded packet.
		fn previous[previous_mut]);
}

/// Checked wrapper for ICMP packets.
///
/// # Note
///
/// The checksum recalculation happens on `Drop`, so don't leak it.
pub struct Checked<'a, P: PM + AsRef<[u8]> + AsMut<[u8]>> {
    pub(in crate::icmp) packet: &'a mut P,
}

impl<'a, P: PM + AsRef<[u8]> + AsMut<[u8]> + 'a> Drop for Checked<'a, P> {
    fn drop(&mut self) {
        let checksum = checksum(self.packet.as_ref());
        Cursor::new(&mut self.packet.as_mut()[2..])
            .write_u16::<BigEndian>(checksum)
            .unwrap();
    }
}
