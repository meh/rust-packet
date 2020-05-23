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
	/// IPv4 packet flags.
	pub struct Flags: u16 {
		/// Do not fragment packets.
		const DONT_FRAGMENT = 0b010;

		/// More fragments are waiting.
		const MORE_FRAGMENTS = 0b100;
	}
}

pub const DONT_FRAGMENT: Flags  = Flags::DONT_FRAGMENT;
pub const MORE_FRAGMENTS: Flags = Flags::MORE_FRAGMENTS;
