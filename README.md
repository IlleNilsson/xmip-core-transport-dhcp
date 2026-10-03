# xmip-core-transport-dhcp

DHCP transport: RFC 2131 over UDP — discover, request, release and inform arrive as Streams of their options, a Send Location offers, acknowledges or refuses a lease. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

The Stream is UTF-8 `name=value` lines, one option each; bytes that are not UTF-8, or a line that is not an option, are refused. An option value that is not text is written as `0x` hex.

A Send Location sends from one socket per address family, bound on its first send and kept by the transport and its clones (`transport::sender::Sender`), so an IPv6 target is reached too; until 2026-09-27 every send bound a new IPv4 socket.

A Receive Location keeps its socket, bound on the first receive (`transport::kept::Kept`): a datagram that arrives between two receives waits in its buffer for the next, where until 2026-09-27 each receive bound a socket of its own and a datagram sent between receives was lost.

A send target is read by `net::Target` in [xmip-core-library-net](https://github.com/IlleNilsson/xmip-core-library-net), the one reading of a URI every technology calls, and its query is decoded there. Until 2026-09-28 this technology split the query off itself, without percent-decoding it.

A `0x` number in a target is read by `codec::hex::prefixed_number` in [xmip-core-library-codec](https://github.com/IlleNilsson/xmip-core-library-codec), which refuses a sign; until 2026-09-28 it was read with `from_str_radix`, which took `0x+7e8`.

## Acknowledgement

Acceptance is at-most-once here. A client message is a datagram, and what
answers it (an offer, an ack, a nak) is the Journey's to send through a Send
Location, not this receive's to defer; a release is answered by nobody. A
client that hears nothing sends a discover or a request again on DHCP's own
schedule, which is not a verdict. Each message arrives whole.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
