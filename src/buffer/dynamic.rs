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

/// A growable buffer.
#[derive(Clone, Eq, PartialEq, Default, Debug)]
pub struct Buffer {
	inner: Vec<u8>,

	offset: usize,
	length: usize,
}

impl Buffer {
	/// Create a new growable buffer.
	pub fn new() -> Self {
		Default::default()
	}
}

impl super::Buffer for Buffer {
	fn next(&mut self, size: usize) -> Result<(), ()> {
		self.offset += self.length;
		self.length  = size;

		let current = self.inner.len();
		self.inner.resize(current + size, 0);

		Ok(())
	}

	fn more(&mut self, size: usize) -> Result<(), ()> {
		self.length += size;

		let current = self.inner.len();
		self.inner.resize(current + size, 0);

		Ok(())
	}

	fn clear(&mut self) {
		self.inner.clear();
		self.offset = 0;
		self.length = 0;
	}

	fn used(&self) -> usize {
		self.inner.len()
	}

	fn data(&self) -> &[u8] {
		&self.inner[self.offset .. self.length]
	}

	fn data_mut(&mut self) -> &mut [u8] {
		&mut self.inner[self.offset .. self.length]
	}
}

impl Into<Vec<u8>> for Buffer {
	fn into(self) -> Vec<u8> {
		self.inner
	}
}

impl AsRef<[u8]> for Buffer {
	fn as_ref(&self) -> &[u8] {
		use super::Buffer;
		self.data()
	}
}

impl AsMut<[u8]> for Buffer {
	fn as_mut(&mut self) -> &mut [u8] {
		use super::Buffer;
		self.data_mut()
	}
}

impl Deref for Buffer {
	type Target = [u8];

	fn deref(&self) -> &Self::Target {
		use super::Buffer;
		self.data()
	}
}

impl DerefMut for Buffer {
	fn deref_mut(&mut self) -> &mut Self::Target {
		use super::Buffer;
		self.data_mut()
	}
}
