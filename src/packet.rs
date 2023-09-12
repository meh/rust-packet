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

use crate::error::*;

/// A network packet.
pub trait Packet {
    /// Return a slice to the packet header.
    fn header(&self) -> &[u8] {
        self.split().0
    }

    /// Return a slice to the packet payload.
    fn payload(&self) -> &[u8] {
        self.split().1
    }

    /// Return both slices.
    fn split(&self) -> (&[u8], &[u8]);
}

/// A mutable network packet.
pub trait PacketMut {
    /// Returns a slice to the packet header.
    fn header_mut(&mut self) -> &mut [u8] {
        self.split_mut().0
    }

    /// Returns a slice to the packet payload.
    fn payload_mut(&mut self) -> &mut [u8] {
        self.split_mut().1
    }

    /// Return both mutable slices.
    fn split_mut(&mut self) -> (&mut [u8], &mut [u8]);
}

/// A type convertible to a `Packet`.
///
/// # Example
///
/// ```
/// use packet::AsPacket;
/// use packet::ether;
///
/// let bytes  = [0x00u8, 0x23, 0x69, 0x63, 0x59, 0xbe, 0xe4, 0xb3, 0x18, 0x26, 0x63, 0xa3, 0x08, 0x00];
/// let packet: ether::Packet<_> = bytes.as_packet().unwrap();
///
/// assert_eq!(packet.destination(), "00:23:69:63:59:be".parse().unwrap());
/// ```
pub trait AsPacket<'a, P: Packet + 'a> {
    /// Try converting to a packet.
    fn as_packet(&'a self) -> Result<P>;
}

/// A type convertible to a `Packet`.
///
/// # Example
///
/// ```
/// use packet::AsPacketMut;
/// use packet::ether;
///
/// let mut bytes = [0x00u8, 0x23, 0x69, 0x63, 0x59, 0xbe, 0xe4, 0xb3, 0x18, 0x26, 0x63, 0xa3, 0x08, 0x00];
/// let mut packet: ether::Packet<_> = bytes.as_packet_mut().unwrap();
///
/// assert_eq!(packet.destination(), "00:23:69:63:59:be".parse().unwrap());
/// packet.set_destination("00:23:42:63:00:be".parse().unwrap());
/// assert_eq!(packet.destination(), "00:23:42:63:00:be".parse().unwrap());
/// ```
pub trait AsPacketMut<'a, P: PacketMut + 'a> {
    /// Try converting to a packet.
    fn as_packet_mut(&'a mut self) -> Result<P>;
}
