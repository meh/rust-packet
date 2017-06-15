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

error_chain! {
	errors {
		/// The buffer is too small.
		SmallBuffer { }

		/// The packet is invalid.
		InvalidPacket { }

		/// The value is invalid for the field.
		InvalidValue { }

		/// The value has already been defined.
		AlreadyDefined { }
	}

	foreign_links {
		Io(::std::io::Error);
		Nul(::std::ffi::NulError);
	}
}
