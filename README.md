# xmip-core-transport-dhcp

DHCP transport: RFC 2131 over UDP — discover, request, release and inform arrive as Streams of their options, a Send Location offers, acknowledges or refuses a lease. A technology of [xmip-core-transport](https://github.com/IlleNilsson/xmip-core-transport).

The Stream is UTF-8 `name=value` lines, one option each; bytes that are not UTF-8, or a line that is not an option, are refused. An option value that is not text is written as `0x` hex.

A Send Location sends from one socket per address family, bound on its first send and kept by the transport and its clones (`transport::sender::Sender`), so an IPv6 target is reached too; until 2026-09-27 every send bound a new IPv4 socket.

## Toolchain

`rust-toolchain.toml` pins the toolchain for the whole estate. Do not change it
here.

## Verification

The included workflow is manual-only and calls the versioned shared workflow at
`IlleNilsson/.github@v1`.
