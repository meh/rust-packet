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

mod packet;
pub use self::packet::Packet;

mod builder;
pub use self::builder::Builder;

use crate::ip;
use crate::ip::Protocol;

/// Calculate the checksum for a UDP packet.
///
/// # Note
///
/// Since the checksum for UDP packets includes a pseudo-header based on the
/// enclosing IP packet, one has to be given.
pub fn checksum<B: AsRef<[u8]>>(ip: &ip::Packet<B>, buffer: &[u8]) -> u16 {
    use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
    use std::io::Cursor;

    let mut prefix = [0u8; 40];
    match *ip {
        ip::Packet::V4(ref packet) => {
            prefix[0..4].copy_from_slice(&packet.source().octets());
            prefix[4..8].copy_from_slice(&packet.destination().octets());

            prefix[9] = Protocol::Udp.into();
            Cursor::new(&mut prefix[10..])
                .write_u16::<BigEndian>(buffer.len() as u16)
                .unwrap();
        }

        ip::Packet::V6(ref _packet) => {
            unimplemented!();
        }
    };

    let mut result = 0x0000u32;
    let mut buffer = Cursor::new(buffer);
    let mut prefix = match *ip {
        ip::Packet::V4(_) => Cursor::new(&prefix[0..12]),

        ip::Packet::V6(_) => Cursor::new(&prefix[0..40]),
    };

    while let Ok(value) = prefix.read_u16::<BigEndian>() {
        result += u32::from(value);

        if result > 0xffff {
            result -= 0xffff;
        }
    }

    while let Ok(value) = buffer.read_u16::<BigEndian>() {
        // Skip checksum field.
        if buffer.position() == 8 {
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
    use crate::udp::checksum;
    use crate::{ip, udp, Packet};

    #[test]
    fn test_checksum() {
        let raw = [
            // IPv4
            0x45, 0x00, 0x00, 0x44, 0xad, 0x0b, 0x00, 0x00, 0x40, 0x11, 0x72, 0x72, 0xac, 0x14,
            0x02, 0xfd, 0xac, 0x14, 0x00, 0x06, // UDP
            0xe5, 0x87, 0x00, 0x35, 0x00, 0x30, 0xe3, 0x20, // data
            0xab, 0xc9, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x6d,
            0x63, 0x63, 0x6c, 0x65, 0x6c, 0x6c, 0x61, 0x6e, 0x02, 0x63, 0x73, 0x05, 0x6d, 0x69,
            0x61, 0x6d, 0x69, 0x03, 0x65, 0x64, 0x75, 0x00, 0x00, 0x01, 0x00, 0x01,
        ];

        let ip = ip::v4::Packet::new(&raw[..]).unwrap();
        let udp = udp::Packet::new(ip.payload()).unwrap();

        assert_eq!(checksum(&ip::Packet::V4(ip), ip.payload()), udp.checksum());
    }
}
