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

#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate bitflags;



mod error;
pub use crate::error::*;

/// Packet size traits.
#[macro_use]
pub mod size;
pub use crate::size::Size;

mod packet;
pub use crate::packet::{Packet, PacketMut, AsPacket, AsPacketMut};

/// Buffer abstractions, dynamic buffers and static buffers.
pub mod buffer;
pub use crate::buffer::Buffer;

/// Packet builder abstractions.
pub mod builder;
pub use crate::builder::Builder;

/// Ethernet packet parser and builder.
pub mod ether;

/// IPv4 and IPv6 packet parser and builder.
pub mod ip;

/// ICMP packet parser and builder.
pub mod icmp;

/// TCP packet parser and builder.
pub mod tcp;

/// UDP packet parser and builder.
pub mod udp;
