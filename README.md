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

Packet
======
Packets take any type implementing `AsRef<[u8]>`, this means they can borrow an
`&[u8]` or own a `Vec<u8>` or your own buffer type without needing different
types or annoying lifetime parameters.

If the type also implements `AsMut<[u8]>` some fields are modifiable in place
instead of going through a builder, not all fields are settable this way, for
instance any fields that have a dynamic size.

Fields in any packet are parsed lazily directly from the buffer, the only exception
are fields that are required to verify the packet is correct.

The correctness check doesn't do any checksum validation, this is because some
protocols require additional information to calculate the checksum, for
instance TCP and UDP require the IP packet to validate.

Buffer
======
Buffers are abstractions over growable or static slices, they implement a
layered setup where each builder creates its own layer and any accesses to the
buffer start from where the layer starts.

The buffer can be grown, but the operation may fail if the underlying buffer is
not growable, static buffers will only fail if they can't accomodate the
requested size.

Builder
=======
Builders are structures that take a `Buffer` (or create one internally) and
incrementally define a new packet.

Builders of upper layer protocols usually provide a way to create a specific
sub-protocol, for example `ip::v4::Builder` allows creating an `udp::Builder`
or `tcp::Builder` and deal with checksuming and length delimiting as needed.

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
