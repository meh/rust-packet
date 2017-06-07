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

use error::*;

pub trait Buffer {
	type Inner: AsMut<[u8]>;

	/// Convert the buffer into the inner type.
	fn into_inner(self) -> Self::Inner;

	/// Go to the next layer.
	fn next(&mut self, size: usize) -> Result<()>;

	/// Request more memory for the same layer.
	fn more(&mut self, size: usize) -> Result<()>;

	/// Clear the buffer.
	fn clear(&mut self);

	/// The number of bytes used by the buffer.
	fn used(&self) -> usize;

	/// Offset from the beginning of the buffer.
	fn offset(&self) -> usize;

	/// The length of the current layer.
	fn length(&self) -> usize;

	/// Get a slice over the current layer.
	fn data(&self) -> &[u8];

	/// Get a mutable slice over the current layer.
	fn data_mut(&mut self) -> &mut [u8];
}

mod dynamic;
pub use self::dynamic::Buffer as Dynamic;

mod slice;
pub use self::slice::Buffer as Slice;
