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
    use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
    use std::io::Cursor;

    let buffer_length = buffer.len();
    let mut prefix = [0u8; 40];
    match *ip {
        ip::Packet::V4(ref packet) => {
            prefix[0..4].copy_from_slice(&packet.source().octets());
            prefix[4..8].copy_from_slice(&packet.destination().octets());

            prefix[9] = Protocol::Tcp.into();
            Cursor::new(&mut prefix[10..])
                .write_u16::<BigEndian>(buffer.len() as u16)
                .unwrap();
        }

        ip::Packet::V6(ref _packet) => {
            unimplemented!();
        }
    };

    let mut result = 0u32;
    let mut buffer = Cursor::new(buffer);
    let mut prefix = match *ip {
        ip::Packet::V4(_) => Cursor::new(&prefix[0..12]),

        ip::Packet::V6(_) => Cursor::new(&prefix[0..40]),
    };

    while let Ok(value) = prefix.read_u16::<BigEndian>() {
        result += u32::from(value);
    }

    let mut bytes_read = 0;
    while let Ok(value) = buffer.read_u16::<BigEndian>() {
        bytes_read += 2;

        // Skip checksum field.
        if buffer.position() == 18 {
            continue;
        }

        result += u32::from(value);
    }

    // NOTE(kuriko): read_u16 may remain 1 byte in the buffer.
    //   read_u16 is based on `read_exact` which will throw an eof error when buffer is not filled.
    if bytes_read != buffer_length {
        // Deal with remaining 1 byte
        let rem = buffer.read_u8().unwrap() as u32;
        result += rem << 8;
    }

    // Avoid branches for better performance.
    while result >> 16 != 0 {
        result = (result & 0xffff) + (result >> 16);
    }

    !result as u16
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{tcp, Builder, Packet};

    #[test]
    fn test_tcp_checksum_on_odd_length() {
        use crate::packet::PacketMut;

        // The `raw_tcp` is dumpped from wireshark based on real tcp traffic.
        let mut raw_tcp = [
            0x45, 0x00, 0x00, 0x7d, 0xf5, 0x31, 0x40, 0x00, 0x40, 0x06, 0x31, 0x47, 0x0a, 0x00,
            0x00, 0x01, 0x0a, 0x00, 0x00, 0x02, 0x92, 0xae, 0x04, 0xd2, 0x2c, 0x2e, 0x5f, 0xf4,
            0x5a, 0xd2, 0xd5, 0xb0, 0x80, 0x18, 0x01, 0xf6, 0x91, 0x41, 0x00, 0x00, 0x01, 0x01,
            0x08, 0x0a, 0x8c, 0xa6, 0xbf, 0xb9, 0xdd, 0xc2, 0xa2, 0xc7, 0x47, 0x45, 0x54, 0x20,
            0x2f, 0x20, 0x48, 0x54, 0x54, 0x50, 0x2f, 0x31, 0x2e, 0x31, 0x0d, 0x0a, 0x48, 0x6f,
            0x73, 0x74, 0x3a, 0x20, 0x67, 0x6f, 0x6f, 0x64, 0x3a, 0x31, 0x32, 0x33, 0x34, 0x0d,
            0x0a, 0x55, 0x73, 0x65, 0x72, 0x2d, 0x41, 0x67, 0x65, 0x6e, 0x74, 0x3a, 0x20, 0x63,
            0x75, 0x72, 0x6c, 0x2f, 0x37, 0x2e, 0x38, 0x35, 0x2e, 0x30, 0x0d, 0x0a, 0x41, 0x63,
            0x63, 0x65, 0x70, 0x74, 0x3a, 0x20, 0x2a, 0x2f, 0x2a, 0x0d, 0x0a, 0x0d, 0x0a,
        ];

        let mut ip_parse = ip::v4::Packet::unchecked(&mut raw_tcp);
        let src_addr = ip_parse.source();
        let dst_addr = ip_parse.destination();

        // Ensure that the length of tcp packet is odd.
        assert!(ip_parse.payload().len() % 2 != 0);

        let mut tcp_parse = tcp::Packet::unchecked(ip_parse.payload_mut());
        let checksum_orig = tcp_parse.checksum();

        let fake_ip_header = ip::v4::Builder::default()
            .source(src_addr)
            .unwrap()
            .destination(dst_addr)
            .unwrap()
            .build()
            .unwrap();
        let fake_ip_header = ip::Packet::unchecked(&fake_ip_header);

        tcp_parse
            .update_checksum(&fake_ip_header)
            .expect("checksum update failed");
        let checksum = tcp_parse.checksum();
        assert_eq!(checksum_orig, checksum);
    }
}
