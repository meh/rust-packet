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

use std::ops::{Deref, DerefMut};

use error::*;

/// A static buffer.
#[derive(Eq, PartialEq, Debug)]
pub struct Buffer<'a> {
	inner: &'a mut [u8],

	offset: usize,
	length: usize,
	used:   usize,
}

impl<'a> Buffer<'a> {
	/// Create a new static buffer wrapping the given slice.
	pub fn new(slice: &mut [u8]) -> Buffer {
		Buffer {
			inner: slice,

			offset: 0,
			length: 0,
			used:   0,
		}
	}
}

impl<'a> super::Buffer for Buffer<'a> {
	type Inner = &'a mut [u8];

	fn into_inner(self) -> Self::Inner {
		self.inner
	}

	fn next(&mut self, size: usize) -> Result<()> {
		if self.inner.len() < self.used + size {
			return Err(ErrorKind::SmallBuffer.into());
		}

		self.offset  = self.used;
		self.length  = size;
		self.used   += size;

		for byte in self.data_mut() {
			*byte = 0;
		}

		Ok(())
	}

	fn more(&mut self, size: usize) -> Result<()> {
		if self.inner.len() < self.used + size {
			return Err(ErrorKind::SmallBuffer.into());
		}

		self.offset  = self.used;
		self.length += size;
		self.used   += size;

		let length = self.length;
		for byte in &mut self.data_mut()[length - size ..] {
			*byte = 0;
		}

		Ok(())
	}

	fn clear(&mut self) {
		self.offset = 0;
		self.length = 0;
		self.used   = 0;
	}

	fn used(&self) -> usize {
		self.used
	}

	fn offset(&self) -> usize {
		self.offset
	}

	fn length(&self) -> usize {
		self.length
	}

	fn data(&self) -> &[u8] {
		&self.inner[self.offset .. self.offset + self.length]
	}

	fn data_mut(&mut self) -> &mut [u8] {
		&mut self.inner[self.offset .. self.offset + self.length]
	}
}

impl<'a> AsRef<[u8]> for Buffer<'a> {
	fn as_ref(&self) -> &[u8] {
		use super::Buffer;
		self.data()
	}
}

impl<'a> AsMut<[u8]> for Buffer<'a> {
	fn as_mut(&mut self) -> &mut [u8] {
		use super::Buffer;
		self.data_mut()
	}
}

impl<'a> Deref for Buffer<'a> {
	type Target = [u8];

	fn deref(&self) -> &Self::Target {
		use super::Buffer;
		self.data()
	}
}

impl<'a> DerefMut for Buffer<'a> {
	fn deref_mut(&mut self) -> &mut Self::Target {
		use super::Buffer;
		self.data_mut()
	}
}
