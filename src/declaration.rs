//! This technology's declaration: the transport guide's "The declaration",
//! `module/core/capability/transport/doc/adding-a-transport.md`.

use xcore::settings::{Applies, Settings};

/// Every setting a Location takes beyond its address, which is where a
/// Receive Location listens — `0.0.0.0:67` the server port; a Send Location
/// answers the transaction its target names.
pub const SETTINGS: &Settings = &Settings {
    technology: env!("CARGO_PKG_NAME"),
    settings: &[transport::configured::timeout(
        Applies::Receive,
        None,
        "How long a receive waits for a client's message; unbounded when left out.",
    )],
};

/// This technology's schemes, as [`transport::Configured::SCHEMES`] defines
/// them.
pub const SCHEMES: &[&str] = &["dhcp"];
