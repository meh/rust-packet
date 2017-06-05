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
extern crate byteorder;

mod error;
pub use error::*;

mod packet;
pub use packet::Packet;

pub mod buffer;
pub use buffer::Buffer;

pub mod size;
pub use size::Size;

pub mod ip;
