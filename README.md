# xmip-core-transport-dhcp

DHCP transport: RFC 2131 over UDP — discover, request, release and inform arrive as Streams of their options, a Send Location offers, acknowledges or refuses a lease. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

The Stream is UTF-8 `name=value` lines, one option each; bytes that are not UTF-8, or a line that is not an option, are refused. An option value that is not text is written as `0x` hex.

A Send Location sends from one socket per address family, bound on its first send and kept by the transport and its clones (`transport::sender::Sender`), so an IPv6 target is reached too; until 2026-09-27 every send bound a new IPv4 socket.

A Receive Location keeps its socket, bound as its transport is opened (`Configured::listening`; on its first receive until 2026-11-16) (`transport::kept::Kept`): a datagram that arrives between two receives waits in its buffer for the next, where until 2026-09-27 each receive bound a socket of its own and a datagram sent between receives was lost.

A send target is read by `net::Target` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net), the one reading of a URI every technology calls, and its query is decoded there. Until 2026-09-28 this technology split the query off itself, without percent-decoding it.

A `0x` number in a target is read by `codec::hex::prefixed_number` in [xmip-core-library-codec](https://github.com/IlleNilsson/xmip-core-library-codec), which refuses a sign; until 2026-09-28 it was read with `from_str_radix`, which took `0x+7e8`.

A Send Location's target is its whole address, `dhcp://host:port?xid=…&mac=…`, which a send reads the transaction it answers from (`Configured::own_target`); until 2026-11-25 it was the address without its scheme, and every send of a node was refused.

## Acknowledgement

Acceptance is at-most-once here. A client message is a datagram, and what
answers it (an offer, an ack, a nak) is a Message's to send through a Send
Location, not this receive's to defer; a release is answered by nobody. A
client that hears nothing sends a discover or a request again on DHCP's own
schedule, which is not a verdict. Each message arrives whole.

## The declaration

What a Location of this technology is configured with is two `const`s in its
`declaration` module, `src/declaration.rs`, beside the code, which
`Configured` reads (ADR-0064, amendment 2026-11-26):
`declaration::SETTINGS`, `timeout`, and `SCHEMES`, `dhcp`. Built with its
`declaration` feature alone (`--no-default-features --features
declaration`), the crate is those and nothing more: its code and every crate
the code is built on are behind the default feature. So the library the
surfaces load can carry it without the code, for the language server and the
desktop to suggest and check a DHCP Location's settings though no node in
their process loaded the technology, once the gathering crate of open
problem 48 links it. `test/Declaration.Test.ps1` in the estate holds that
the declaration builds nothing the transport capability does not.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
