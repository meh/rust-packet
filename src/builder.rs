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

use std::fmt;

use error::*;
use buffer::Buffer;

pub trait Finalizer {
	fn finalize(self: Box<Self>, buffer: &mut [u8]) -> Result<()>;
}

impl<F: FnOnce(&mut [u8]) -> Result<()>> Finalizer for F {
	fn finalize(self: Box<F>, buffer: &mut [u8]) -> Result<()> {
		let f = *self;
		f(buffer)
	}
}

pub struct Finalization(Vec<Box<Finalizer>>);

impl Default for Finalization {
	fn default() -> Self {
		Finalization(Vec::new())
	}
}

impl fmt::Debug for Finalization {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("builder::Finalization")
			.field("length", &self.0.len())
			.finish()
	}
}

impl Finalization {
	pub fn add<F: FnOnce(&mut [u8]) -> Result<()> + 'static>(&mut self, finalizer: F) {
		self.0.push(Box::new(finalizer));
	}

	pub fn extend<I: IntoIterator<Item = Box<Finalizer>>>(&mut self, finalizers: I) {
		self.0.extend(finalizers.into_iter());
	}

	pub fn finalize(self, buffer: &mut [u8]) -> Result<()> {
		for finalizer in self.0.into_iter().rev() {
			finalizer.finalize(buffer)?;
		}

		Ok(())
	}
}

impl IntoIterator for Finalization {
	type Item     = Box<Finalizer>;
	type IntoIter = ::std::vec::IntoIter<Box<Finalizer>>;

	fn into_iter(self) -> ::std::vec::IntoIter<Box<Finalizer>> {
		self.0.into_iter()
	}
}

impl Into<Vec<Box<Finalizer>>> for Finalization {
	fn into(self) -> Vec<Box<Finalizer>> {
		self.0
	}
}

pub trait Builder<B: Buffer> {
	fn with(buffer: B) -> Result<Self> where Self: Sized;
	fn finalizer(&mut self) -> &mut Finalization;
	fn build(self) -> Result<B::Inner>;
}
