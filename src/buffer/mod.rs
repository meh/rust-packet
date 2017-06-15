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
use packet::Packet;

/// A buffer to build packets in.
///
/// A `Buffer` is composed of multiple layers, internally an `offset` and
/// `length` is used to keep track of the current layer, `data()` and
/// `data_mut()` will always return a slice to the current layer.
///
/// # Example
///
/// ```
/// use packet::buffer::{self, Buffer};
///
/// // Create a new dynamic buffer, `buffer::Dynamic` is backed by a `Vec<u8>`.
/// let mut buffer = buffer::Dynamic::new();
///
/// // Create a new layer for 20 bytes, calling `next()` increases the offset
/// // and zeroes the underlying memory.
/// buffer.next(20);
///
/// // Get more memory in the buffer.
/// buffer.more(4);
///
/// // Get the backing data for the buffer.
/// let data = buffer.into_inner();
/// assert_eq!(data.len(), 24);
/// ```
pub trait Buffer {
	/// Inner type used by the buffer.
	type Inner: AsMut<[u8]>;

	/// Convert the buffer into the inner type.
	fn into_inner(self) -> Self::Inner;

	/// Go to the next layer requesting the given size, zeroeing the layer.
	fn next(&mut self, size: usize) -> Result<()>;

	/// Request more memory for the same layer, zeroeing the new buffer area.
	fn more(&mut self, size: usize) -> Result<()>;

	/// Clear the buffer.
	fn clear(&mut self);

	/// Number of bytes used by the whole buffer.
	fn used(&self) -> usize;

	/// Offset from the beginning of the whole buffer.
	fn offset(&self) -> usize;

	/// Length of the current layer.
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
