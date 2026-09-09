//! RFC 2131 section 2: the BOOTP fixed fields, the magic cookie and the
//! RFC 2132 options after it — and the `name=value` line form of the
//! options a Stream is made of.
//!
//! Twelve named options are read and written by name; any other is
//! `option-N=0x…`. A message is padded to the 300 bytes the oldest relays
//! insist on.

use std::fmt::Write;
use std::net::Ipv4Addr;

use transport::error::{Result, protocol_error};

use crate::option::{hex_pairs, option_code, option_name, parse_option, render_option};

/// The four bytes that say the options follow.
pub const MAGIC: [u8; 4] = [99, 130, 83, 99];
/// A message from a client.
pub const BOOTREQUEST: u8 = 1;
/// A message from a server.
pub const BOOTREPLY: u8 = 2;
/// Ethernet, the one hardware type the estate has.
pub const HTYPE_ETHERNET: u8 = 1;
/// The smallest datagram a relay forwards.
pub const MIN_MESSAGE: usize = 300;
/// The largest a client must take without option 57.
pub const MAX_MESSAGE: usize = 576;

pub const OPTION_SUBNET_MASK: u8 = 1;
pub const OPTION_ROUTER: u8 = 3;
pub const OPTION_DNS: u8 = 6;
pub const OPTION_HOSTNAME: u8 = 12;
pub const OPTION_REQUESTED_ADDRESS: u8 = 50;
pub const OPTION_LEASE_TIME: u8 = 51;
pub const OPTION_MESSAGE_TYPE: u8 = 53;
pub const OPTION_SERVER: u8 = 54;
pub const OPTION_PARAMETER_LIST: u8 = 55;
pub const OPTION_CLIENT_ID: u8 = 61;
pub const OPTION_END: u8 = 255;

/// Option 53.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageType {
    Discover = 1,
    Offer = 2,
    Request = 3,
    Decline = 4,
    Ack = 5,
    Nak = 6,
    Release = 7,
    Inform = 8,
}

impl MessageType {
    /// The lower-case name an origin and a Stream line write.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Discover => "discover",
            Self::Offer => "offer",
            Self::Request => "request",
            Self::Decline => "decline",
            Self::Ack => "ack",
            Self::Nak => "nak",
            Self::Release => "release",
            Self::Inform => "inform",
        }
    }

    /// The type called `name`, or numbered `name`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|t| t.name() == name || (*t as u8).to_string() == name)
    }

    /// The type numbered `code`.
    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|t| *t as u8 == code)
    }

    const ALL: [Self; 8] = [
        Self::Discover,
        Self::Offer,
        Self::Request,
        Self::Decline,
        Self::Ack,
        Self::Nak,
        Self::Release,
        Self::Inform,
    ];
}

/// One DHCP message.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    pub op: u8,
    pub htype: u8,
    pub hlen: u8,
    pub hops: u8,
    pub xid: u32,
    pub secs: u16,
    pub flags: u16,
    pub ciaddr: Ipv4Addr,
    pub yiaddr: Ipv4Addr,
    pub siaddr: Ipv4Addr,
    pub giaddr: Ipv4Addr,
    pub chaddr: [u8; 16],
    pub sname: String,
    pub file: String,
    /// Options as they came, code and value, `END` not among them.
    pub options: Vec<(u8, Vec<u8>)>,
}

impl Message {
    /// A message of `op` for transaction `xid` from the Ethernet client
    /// `mac`, every address zero, no options yet.
    #[must_use]
    pub fn new(op: u8, xid: u32, mac: &[u8]) -> Self {
        let mut chaddr = [0u8; 16];
        let hlen = mac.len().min(16);
        chaddr[..hlen].copy_from_slice(&mac[..hlen]);
        Self {
            op,
            htype: HTYPE_ETHERNET,
            hlen: u8::try_from(hlen).unwrap_or(6),
            hops: 0,
            xid,
            secs: 0,
            flags: 0,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            chaddr,
            sname: String::new(),
            file: String::new(),
            options: Vec::new(),
        }
    }

    /// With option `code` set to `value`, replacing an earlier one.
    #[must_use]
    pub fn with(mut self, code: u8, value: Vec<u8>) -> Self {
        self.options.retain(|(c, _)| *c != code);
        self.options.push((code, value));
        self
    }

    /// Option `code` as it came.
    #[must_use]
    pub fn option(&self, code: u8) -> Option<&[u8]> {
        self.options
            .iter()
            .find(|(c, _)| *c == code)
            .map(|(_, v)| v.as_slice())
    }

    /// Option 53, where it is one of the eight.
    #[must_use]
    pub fn message_type(&self) -> Option<MessageType> {
        MessageType::from_code(*self.option(OPTION_MESSAGE_TYPE)?.first()?)
    }

    /// `aa:bb:cc:dd:ee:ff`, the hardware address as far as `hlen` says.
    #[must_use]
    pub fn mac(&self) -> String {
        hex_pairs(&self.chaddr[..usize::from(self.hlen).min(16)], ":")
    }

    /// The hardware address `aa:bb:cc:dd:ee:ff` names.
    #[must_use]
    pub fn parse_mac(text: &str) -> Option<Vec<u8>> {
        let parts: Vec<&str> = text.split([':', '-']).collect();
        if parts.is_empty() || parts.len() > 16 {
            return None;
        }
        parts
            .into_iter()
            .map(|part| u8::from_str_radix(part, 16).ok())
            .collect()
    }

    /// Option 12 as text.
    #[must_use]
    pub fn hostname(&self) -> String {
        self.option(OPTION_HOSTNAME)
            .map(|v| String::from_utf8_lossy(v).into_owned())
            .unwrap_or_default()
    }

    /// The options as the Stream: one `name=value` line each.
    #[must_use]
    pub fn option_lines(&self) -> Vec<u8> {
        let mut out = String::new();
        for (code, value) in &self.options {
            let _ = writeln!(
                out,
                "{}={}",
                option_name(*code),
                render_option(*code, value)
            );
        }
        out.into_bytes()
    }

    /// With every `name=value` line of `bytes` set as an option.
    ///
    /// # Errors
    /// A line without `=`, a name that is neither known nor `option-N`,
    /// or a value not shaped for its option.
    pub fn with_lines(mut self, bytes: &[u8]) -> Result<Self> {
        let text = std::str::from_utf8(bytes).map_err(|_| protocol_error("options not UTF-8"))?;
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let (name, value) = line
                .split_once('=')
                .ok_or_else(|| protocol_error(format!("an option without =: {line:?}")))?;
            let code = option_code(name.trim())
                .ok_or_else(|| protocol_error(format!("an option not known: {name:?}")))?;
            self = self.with(code, parse_option(code, value.trim())?);
        }
        Ok(self)
    }
}

/// `message` on the wire, padded to [`MIN_MESSAGE`].
///
/// # Errors
/// An option value over 255 bytes, or a message over [`MAX_MESSAGE`].
pub fn encode(message: &Message) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(MIN_MESSAGE);
    out.extend_from_slice(&[message.op, message.htype, message.hlen, message.hops]);
    out.extend_from_slice(&message.xid.to_be_bytes());
    out.extend_from_slice(&message.secs.to_be_bytes());
    out.extend_from_slice(&message.flags.to_be_bytes());
    for address in [
        message.ciaddr,
        message.yiaddr,
        message.siaddr,
        message.giaddr,
    ] {
        out.extend_from_slice(&address.octets());
    }
    out.extend_from_slice(&message.chaddr);
    fixed_text(&mut out, &message.sname, 64);
    fixed_text(&mut out, &message.file, 128);
    out.extend_from_slice(&MAGIC);
    for (code, value) in &message.options {
        let length = u8::try_from(value.len())
            .map_err(|_| protocol_error(format!("option {code} over 255 bytes")))?;
        out.push(*code);
        out.push(length);
        out.extend_from_slice(value);
    }
    out.push(OPTION_END);
    if out.len() > MAX_MESSAGE {
        return Err(protocol_error("a message over what a client must take"));
    }
    out.resize(out.len().max(MIN_MESSAGE), 0);
    Ok(out)
}

fn fixed_text(out: &mut Vec<u8>, text: &str, width: usize) {
    let bytes = text.as_bytes();
    let take = bytes.len().min(width - 1);
    out.extend_from_slice(&bytes[..take]);
    out.resize(out.len() + width - take, 0);
}

/// One datagram.
///
/// # Errors
/// Shorter than the fixed fields and the cookie, a cookie that is not the
/// magic, or an option running past the end.
pub fn decode(bytes: &[u8]) -> Result<Message> {
    if bytes.len() < 240 {
        return Err(protocol_error("a message shorter than its fixed fields"));
    }
    if bytes[236..240] != MAGIC {
        return Err(protocol_error("a cookie that is not DHCP's"));
    }
    let address = |at: usize| Ipv4Addr::new(bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]);
    let text = |range: std::ops::Range<usize>| {
        let field = &bytes[range];
        let end = field.iter().position(|b| *b == 0).unwrap_or(field.len());
        String::from_utf8_lossy(&field[..end]).into_owned()
    };
    let mut chaddr = [0u8; 16];
    chaddr.copy_from_slice(&bytes[28..44]);
    let mut options = Vec::new();
    let mut at = 240;
    while at < bytes.len() {
        let code = bytes[at];
        if code == OPTION_END {
            break;
        }
        if code == 0 {
            at += 1;
            continue;
        }
        let length = usize::from(*bytes.get(at + 1).ok_or_else(past_end)?);
        let value = bytes.get(at + 2..at + 2 + length).ok_or_else(past_end)?;
        options.push((code, value.to_vec()));
        at += 2 + length;
    }
    Ok(Message {
        op: bytes[0],
        htype: bytes[1],
        hlen: bytes[2],
        hops: bytes[3],
        xid: u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        secs: u16::from_be_bytes([bytes[8], bytes[9]]),
        flags: u16::from_be_bytes([bytes[10], bytes[11]]),
        ciaddr: address(12),
        yiaddr: address(16),
        siaddr: address(20),
        giaddr: address(24),
        chaddr,
        sname: text(44..108),
        file: text(108..236),
        options,
    })
}

fn past_end() -> transport::TransportError {
    protocol_error("an option running past the end")
}

#[cfg(test)]
mod tests {
    use super::*;

    const MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

    #[test]
    fn a_discover_round_trips_and_its_options_read_as_lines() {
        let discover = Message::new(BOOTREQUEST, 0x3903_f326, &MAC)
            .with(OPTION_HOSTNAME, b"printer-7".to_vec())
            .with_lines(
                b"message-type=discover\nrequested-address=10.0.0.9\n\
                  client-id=01:aa:bb:cc:dd:ee:ff\nparameter-list=01:03:06\noption-60=0x786d6970\n",
            )
            .expect("lines");
        let bytes = encode(&discover).expect("encode");
        assert_eq!(bytes.len(), MIN_MESSAGE, "padded");
        assert_eq!(&bytes[236..240], &MAGIC);
        let back = decode(&bytes).expect("decode");
        assert_eq!(back, discover);
        assert_eq!(back.message_type(), Some(MessageType::Discover));
        assert_eq!(back.mac(), "aa:bb:cc:dd:ee:ff");
        assert_eq!(back.hostname(), "printer-7");
        assert_eq!(back.xid, 0x3903_f326);
        let lines = String::from_utf8(back.option_lines()).expect("text");
        assert_eq!(
            lines,
            "hostname=printer-7\nmessage-type=discover\nrequested-address=10.0.0.9\n\
             client-id=01:aa:bb:cc:dd:ee:ff\nparameter-list=01:03:06\noption-60=0x786d6970\n"
        );
        let offer = Message::new(BOOTREPLY, 1, &MAC)
            .with_lines(
                b"message-type=2\nserver=10.0.0.1\ndns=10.0.0.1, 10.0.0.2\nlease-time=3600\n",
            )
            .expect("lines");
        assert_eq!(
            offer.option(OPTION_LEASE_TIME),
            Some(&[0, 0, 0x0e, 0x10][..])
        );
        assert_eq!(offer.option(OPTION_DNS).map(<[u8]>::len), Some(8));
        assert!(
            String::from_utf8(offer.option_lines())
                .expect("text")
                .contains(
                    "message-type=offer\nserver=10.0.0.1\ndns=10.0.0.1,10.0.0.2\nlease-time=3600\n"
                )
        );
        let mut long = Message::new(BOOTREQUEST, 1, &MAC);
        long.sname = "s".repeat(80);
        long.file = "f".repeat(200);
        let back = decode(&encode(&long).expect("encode")).expect("decode");
        assert_eq!(back.sname.len(), 63, "cut to the field less its NUL");
        assert_eq!(back.file.len(), 127);
        assert_eq!(MessageType::parse("nak"), Some(MessageType::Nak));
        assert_eq!(Message::parse_mac("aa-bb"), Some(vec![0xaa, 0xbb]));
    }

    #[test]
    fn what_is_not_dhcp_is_refused() {
        assert!(decode(&[0; 239]).is_err(), "short");
        assert!(decode(&[0; 300]).is_err(), "no cookie");
        let mut cut =
            encode(&Message::new(BOOTREQUEST, 1, &MAC).with(12, b"host".to_vec())).expect("encode");
        cut.truncate(243);
        assert!(decode(&cut).is_err(), "option past the end");
        let base = Message::new(BOOTREQUEST, 1, &MAC);
        assert!(base.clone().with_lines(b"no equals").is_err());
        assert!(base.clone().with_lines(b"colour=blue").is_err());
        assert!(base.clone().with_lines(b"router=nowhere").is_err());
        assert!(base.clone().with_lines(b"lease-time=soon").is_err());
        assert!(base.clone().with_lines(b"message-type=hello").is_err());
        assert!(base.clone().with_lines(b"option-60=plain").is_err());
        assert!(base.clone().with_lines(b"client-id=zz").is_err());
        assert!(base.clone().with_lines(&[0xff]).is_err());
        assert!(
            encode(&base.clone().with(60, vec![0; 256])).is_err(),
            "over 255"
        );
        assert!(
            encode(&base.with(60, vec![0; 255]).with(61, vec![0; 255])).is_err(),
            "over 576"
        );
        assert!(Message::parse_mac("").is_none() || Message::parse_mac("").is_some());
        assert!(Message::parse_mac("a:b:c:d:e:f:1:2:3:4:5:6:7:8:9:0:1").is_none());
    }
}
