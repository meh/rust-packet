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

use std::{io, ffi};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
	#[error("the buffer is too small")]
	SmallBuffer,

	#[error("the packet is invalid")]
	InvalidPacket,

	#[error("the vaue is invalid for the field")]
	InvalidValue,

	#[error("the value has already been defined")]
	AlreadyDefined,

	#[error(transparent)]
	Io(#[from] io::Error),

	#[error(transparent)]
	Nul(#[from] ffi::NulError),
}

pub type Result<T> = ::std::result::Result<T, Error>;
