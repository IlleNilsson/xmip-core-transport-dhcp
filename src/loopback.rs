//! Both ends of one DHCP exchange on this machine (ADR-0051): a server at
//! an ephemeral local port takes the Stream a client sends as informs of
//! one site-specific option each — [`OPTION`] bytes, what an option holds —
//! acknowledging every one before the next goes, as RFC 2131 answers a
//! DHCPINFORM with a DHCPACK, then an inform with none to close. The client
//! is a socket and the transport's own message, because what the transport
//! sends is a reply and what its server takes is a request.
//!
//! The ceiling is a fact about the protocol: option 57, Maximum DHCP
//! Message Size, is sixteen bits (RFC 2132 section 9.10), so a Stream
//! larger than the largest possible message less its fixed header and magic
//! cookie is not a DHCP conversation, however many informs it were cut into.

use std::fmt::Write;
use std::net::UdpSocket;

use transport::Arrived;
use transport::error::{Result, classify, protocol_error};
use transport::loopback::{FarEnd, LOOPBACK_TIMEOUT, Loopback};
use transport::socket;

use crate::DhcpTransport;
use crate::message::{self, BOOTREPLY, BOOTREQUEST, MAX_MESSAGE, Message, MessageType};

/// The most a DHCP conversation carries: the largest message option 57 can
/// name, less the 236 fixed bytes and the 4 of the magic cookie.
pub const MAX_STREAM: usize = u16::MAX as usize - 240 - 4;

/// What one option holds, and so what one inform carries.
const OPTION: usize = 255;
/// The site-specific option the Stream rides in, as a line names it.
const LINE: &str = "option-224=0x";
/// A locally administered hardware address, so no vendor's is borrowed.
const MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x78, 0x6d, 0x69];
/// The transaction every inform is part of: `xmip`.
const XID: u32 = 0x786d_6970;

impl DhcpTransport {
    /// Both ends on this machine: a server at an ephemeral local port, the
    /// loopback timeout on both.
    #[must_use]
    pub fn loopback() -> Self {
        Self::new("127.0.0.1:0").timing_out_after(LOOPBACK_TIMEOUT)
    }
}

/// A bound server waiting for its informs.
struct Serving {
    transport: DhcpTransport,
    socket: UdpSocket,
    address: String,
}

impl FarEnd for Serving {
    fn address(&self) -> &str {
        &self.address
    }

    fn take_one(self: Box<Self>) -> Result<Arrived> {
        let mut bytes = Vec::new();
        let mut origin = None;
        loop {
            let arrived = self.transport.receive_datagram(&self.socket)?;
            acknowledge(&self.socket, &arrived.origin_uri)?;
            let text = std::str::from_utf8(&arrived.bytes)
                .map_err(|_| protocol_error("option lines that are not text"))?;
            let mut carried = false;
            for digits in text.lines().filter_map(|line| line.strip_prefix(LINE)) {
                bytes.extend(unhex(digits)?);
                carried = true;
            }
            let origin = origin.get_or_insert(arrived.origin_uri);
            if !carried {
                return Ok(Arrived::new(origin.as_str(), bytes));
            }
        }
    }
}

impl Loopback for DhcpTransport {
    fn ceiling(&self) -> Option<usize> {
        Some(MAX_STREAM)
    }

    fn far_end(&self) -> Result<Box<dyn FarEnd>> {
        let (socket, address) = self.bind_udp()?;
        Ok(Box::new(Serving {
            transport: self.clone(),
            socket,
            address,
        }))
    }

    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        if payload.len() > MAX_STREAM {
            return Err(protocol_error(format!(
                "{} bytes is over the {MAX_STREAM} the largest DHCP message holds",
                payload.len()
            )));
        }
        let (client, _) = socket::bind_udp("127.0.0.1:0", self.timeout)?;
        let mut informs: Vec<String> = payload
            .chunks(OPTION)
            .map(|chunk| format!("message-type=inform\n{LINE}{}\n", hex(chunk)))
            .collect();
        informs.push("message-type=inform\n".to_string());
        for lines in informs {
            client
                .send_to(&inform(&lines)?, address)
                .map_err(|e| classify("sending an inform", &e))?;
            acknowledged(&client)?;
        }
        Ok(())
    }

    fn unblock(&self, _address: &str) {
        // The receive has its own timeout; there is no listener to poke.
    }
}

/// The DHCPINFORM carrying `lines`.
fn inform(lines: &str) -> Result<Vec<u8>> {
    let inform = Message::new(BOOTREQUEST, XID, &MAC).with_lines(lines.as_bytes())?;
    message::encode(&inform)
}

/// The DHCPACK answering the inform `origin` names, back to its client.
fn acknowledge(socket: &UdpSocket, origin: &str) -> Result<()> {
    let target = origin.replace("type=inform", "type=ack");
    let (client, ack) = DhcpTransport::reply_for(&target, &[])?;
    socket
        .send_to(&message::encode(&ack)?, client)
        .map_err(|e| classify("acknowledging an inform", &e))?;
    Ok(())
}

/// The DHCPACK a client waits for after each inform.
fn acknowledged(client: &UdpSocket) -> Result<()> {
    let mut buffer = vec![0u8; MAX_MESSAGE * 2];
    let (read, _) = client
        .recv_from(&mut buffer)
        .map_err(|e| classify("awaiting the acknowledgement", &e))?;
    let reply = message::decode(&buffer[..read])?;
    if reply.op == BOOTREPLY && reply.message_type() == Some(MessageType::Ack) {
        Ok(())
    } else {
        Err(protocol_error("an answer that is not a DHCPACK"))
    }
}

/// `bytes` as lower-case hex pairs, the form an option line takes.
fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// The bytes `digits` spell, refused where they do not.
fn unhex(digits: &str) -> Result<Vec<u8>> {
    if !digits.len().is_multiple_of(2) {
        return Err(protocol_error(format!(
            "an odd number of hex digits: {digits:?}"
        )));
    }
    (0..digits.len())
        .step_by(2)
        .map(|at| {
            digits
                .get(at..at + 2)
                .and_then(|pair| u8::from_str_radix(pair, 16).ok())
                .ok_or_else(|| protocol_error(format!("not hex: {digits:?}")))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_reads_back_and_refuses_what_is_not_hex() {
        assert_eq!(hex(&[0, 0x7f, 0xff]), "007fff");
        assert_eq!(unhex("007fff").expect("hex"), [0, 0x7f, 0xff]);
        assert!(unhex("").expect("nothing").is_empty());
        assert!(unhex("abc").is_err(), "odd");
        assert!(unhex("zz").is_err(), "not hex");
    }
}
