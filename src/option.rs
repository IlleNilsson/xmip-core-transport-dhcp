//! RFC 2132 options in their `name=value` line form: the ten names a
//! Stream reads and writes, and the shape each value renders in — a type
//! name, dotted addresses, seconds, text or `0x` hex.

use std::net::Ipv4Addr;

use transport::error::{Result, protocol_error};

use crate::message::{
    Message, MessageType, OPTION_CLIENT_ID, OPTION_DNS, OPTION_HOSTNAME, OPTION_LEASE_TIME,
    OPTION_MESSAGE_TYPE, OPTION_PARAMETER_LIST, OPTION_REQUESTED_ADDRESS, OPTION_ROUTER,
    OPTION_SERVER, OPTION_SUBNET_MASK,
};

/// The named options, in the order a Stream writes them.
const NAMES: [(u8, &str); 10] = [
    (OPTION_MESSAGE_TYPE, "message-type"),
    (OPTION_SERVER, "server"),
    (OPTION_REQUESTED_ADDRESS, "requested-address"),
    (OPTION_LEASE_TIME, "lease-time"),
    (OPTION_SUBNET_MASK, "subnet-mask"),
    (OPTION_ROUTER, "router"),
    (OPTION_DNS, "dns"),
    (OPTION_HOSTNAME, "hostname"),
    (OPTION_CLIENT_ID, "client-id"),
    (OPTION_PARAMETER_LIST, "parameter-list"),
];

pub(crate) fn option_name(code: u8) -> String {
    NAMES
        .iter()
        .find(|(c, _)| *c == code)
        .map_or_else(|| format!("option-{code}"), |(_, name)| (*name).to_string())
}

pub(crate) fn option_code(name: &str) -> Option<u8> {
    NAMES
        .iter()
        .find(|(_, n)| *n == name)
        .map(|(c, _)| *c)
        .or_else(|| name.strip_prefix("option-")?.parse().ok())
}

/// A value as its option's shape writes it: a type name, addresses dotted
/// and comma-separated, a time in seconds, text, or `0x` hex.
pub(crate) fn render_option(code: u8, value: &[u8]) -> String {
    match code {
        OPTION_MESSAGE_TYPE => value
            .first()
            .and_then(|c| MessageType::from_code(*c))
            .map_or_else(|| hex_pairs(value, ""), |t| t.name().to_string()),
        OPTION_SUBNET_MASK
        | OPTION_ROUTER
        | OPTION_DNS
        | OPTION_REQUESTED_ADDRESS
        | OPTION_SERVER
            if value.len().is_multiple_of(4) && !value.is_empty() =>
        {
            value
                .chunks(4)
                .map(|c| Ipv4Addr::new(c[0], c[1], c[2], c[3]).to_string())
                .collect::<Vec<_>>()
                .join(",")
        }
        OPTION_LEASE_TIME if value.len() == 4 => {
            u32::from_be_bytes([value[0], value[1], value[2], value[3]]).to_string()
        }
        OPTION_HOSTNAME => String::from_utf8_lossy(value).into_owned(),
        OPTION_CLIENT_ID | OPTION_PARAMETER_LIST => hex_pairs(value, ":"),
        _ => format!("0x{}", hex_pairs(value, "")),
    }
}

pub(crate) fn parse_option(code: u8, text: &str) -> Result<Vec<u8>> {
    let addresses = || -> Result<Vec<u8>> {
        let mut out = Vec::new();
        for part in text.split(',') {
            let address: Ipv4Addr = part
                .trim()
                .parse()
                .map_err(|_| protocol_error(format!("not an address: {part:?}")))?;
            out.extend_from_slice(&address.octets());
        }
        Ok(out)
    };
    Ok(match code {
        OPTION_MESSAGE_TYPE => vec![
            MessageType::parse(text)
                .ok_or_else(|| protocol_error(format!("not a message type: {text:?}")))?
                as u8,
        ],
        OPTION_SUBNET_MASK
        | OPTION_ROUTER
        | OPTION_DNS
        | OPTION_REQUESTED_ADDRESS
        | OPTION_SERVER => addresses()?,
        OPTION_LEASE_TIME => text
            .parse::<u32>()
            .map_err(|_| protocol_error(format!("not seconds: {text:?}")))?
            .to_be_bytes()
            .to_vec(),
        OPTION_HOSTNAME => text.as_bytes().to_vec(),
        OPTION_CLIENT_ID | OPTION_PARAMETER_LIST => Message::parse_mac(text)
            .ok_or_else(|| protocol_error(format!("not colon-separated hex: {text:?}")))?,
        _ => text
            .strip_prefix("0x")
            .and_then(unhex)
            .ok_or_else(|| protocol_error(format!("option {code} takes 0x hex: {text:?}")))?,
    })
}

pub(crate) fn hex_pairs(bytes: &[u8], between: &str) -> String {
    bytes
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(between)
}

pub(crate) fn unhex(digits: &str) -> Option<Vec<u8>> {
    if !digits.len().is_multiple_of(2) {
        return None;
    }
    (0..digits.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(digits.get(at..at + 2)?, 16).ok())
        .collect()
}
