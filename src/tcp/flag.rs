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

use bitflags::bitflags;

bitflags! {
    /// TCP flags.
    #[derive(Debug, PartialEq, Eq)]
    pub struct Flags: u16 {
        ///
        const FIN = 0b0_0000_0001;

        ///
        const SYN = 0b0_0000_0010;

        ///
        const RST = 0b0_0000_0100;

        ///
        const PSH = 0b0_0000_1000;

        ///
        const ACK = 0b0_0001_0000;

        ///
        const URG = 0b0_0010_0000;

        ///
        const ECE = 0b0_0100_0000;

        ///
        const CWR = 0b0_1000_0000;

        ///
        const NS  = 0b1_0000_0000;
    }
}

pub const FIN: Flags = Flags::FIN;
pub const SYN: Flags = Flags::SYN;
pub const RST: Flags = Flags::RST;
pub const PSH: Flags = Flags::PSH;
pub const ACK: Flags = Flags::ACK;
pub const URG: Flags = Flags::URG;
pub const ECE: Flags = Flags::ECE;
pub const CWR: Flags = Flags::CWR;
pub const NS: Flags = Flags::NS;
