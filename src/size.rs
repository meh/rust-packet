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

/// Sizes for the header part of a packet.
pub mod header {
	/// Minimum size of a packet header.
	pub trait Min {
		/// Get the minimum size.
		fn min() -> usize;
	}

	/// Maximum size of a packet header.
	pub trait Max {
		/// Get the maximum size.
		fn max() -> usize;
	}

	/// Actual size of the packet header.
	pub trait Size {
		/// Get the actual size.
		fn size(&self) -> usize;
	}
}

/// Sizes for the payload part of a packet.
pub mod payload {
	/// Minimum size of a packet payload.
	pub trait Min {
		/// Get the minimum size.
		fn min() -> usize;
	}

	/// Maximum size of a packet payload.
	pub trait Max {
		/// Get the maximum size.
		fn max() -> usize;
	}

	/// Actual size of the packet payload.
	pub trait Size {
		/// Get the actual size.
		fn size(&self) -> usize;
	}
}

/// Minimum size of a packet.
pub trait Min {
	/// Get the minimum size.
	fn min() -> usize;
}

/// Maximum size of a packet.
pub trait Max {
	/// Get the maximum size.
	fn max() -> usize;
}

/// Actual size of the packet.
pub trait Size {
	/// Get the actual size.
	fn size(&self) -> usize;
}

impl<T: header::Min + payload::Min> Min for T {
	fn min() -> usize {
		<Self as header::Min>::min() + <Self as payload::Min>::min()
	}
}

impl<T: header::Max + payload::Max> Max for T {
	fn max() -> usize {
		<Self as header::Max>::max() + <Self as payload::Max>::max()
	}
}

impl<T: header::Size + payload::Size> Size for T {
	fn size(&self) -> usize {
		<Self as header::Size>::size(self) + <Self as payload::Size>::size(self)
	}
}

macro_rules! sized {
	()                             => ();
	($name:ident, )                => ();
	($name:ident => $part:ident; ) => ();

	($name:ident, $part:ident { $($defs:tt)* } $($rest:tt)*) => (
		sized!($name => $part; $($defs)*);
		sized!($name, $($rest)*);
	);

	($name:ident => $part:ident; min: $value:expr, $($rest:tt)*) => (
		impl<B> crate::size::$part::Min for $name<B> {
			fn min() -> usize {
				$value
			}
		}

		sized!($name => $part; $($rest)*);
	);

	($name:ident => $part:ident; max: $value:expr, $($rest:tt)*) => (
		impl<B> crate::size::$part::Max for $name<B> {
			fn max() -> usize {
				$value
			}
		}

		sized!($name => $part; $($rest)*);
	);

	($name:ident => $part:ident; size: $value:expr, $($rest:tt)*) => (
		impl<B: AsRef<[u8]>> crate::size::$part::Size for $name<B> {
			fn size(&self) -> usize {
				$value
			}
		}

		sized!($name => $part; $($rest)*);
	);

	($name:ident => $part:ident; size: $packet:ident => $value:expr, $($rest:tt)*) => (
		impl<B: AsRef<[u8]>> crate::size::$part::Size for $name<B> {
			fn size(&self) -> usize {
				let $packet = self;
				$value
			}
		}

		sized!($name => $part; $($rest)*);
	);
}
