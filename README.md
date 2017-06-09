packet [![Crates.io](https://img.shields.io/crates/v/packet.svg)](https://crates.io/crates/packet) ![packet](https://docs.rs/packet/badge.svg) ![WTFPL](http://img.shields.io/badge/license-WTFPL-blue.svg) [![Build Status](https://travis-ci.org/meh/rust-packet.svg?branch=master)](https://travis-ci.org/meh/rust-packet)
======
This crate allows the parsing and creation of various network packets with an
ergonomic API.

Usage
-----
First, add the following to your `Cargo.toml`:

```toml
[dependencies]
packet = "0.1"
```

Next, add this to your crate root:

```rust
extern crate packet;
```

Examples
========
Creating an ICMP packet echo request packet.

```rust
extern crate packet;
use packet::builder::Builder;
use packet::icmp;

fn main() {
	let packet = icmp::Builder::default()
	  .echo().unwrap().request().unwrap()
	  .identifier(42).unwrap()
			.sequence(2).unwrap()
			.payload(b"test").unwrap()
			.build().unwrap();
}
```
