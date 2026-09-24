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

use std::net::UdpSocket;

use codec::hex;
use transport::Arrived;
use transport::bound::{Bound, Reading};
use transport::ceiling;
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

impl Reading for DhcpTransport {
    /// A bound server waiting for its informs.
    fn take_one(self, socket: &UdpSocket) -> Result<Arrived> {
        let mut bytes = Vec::new();
        let mut origin = None;
        loop {
            let arrived = self.receive_datagram(socket)?;
            acknowledge(socket, &arrived.origin_uri)?;
            let text = std::str::from_utf8(&arrived.bytes)
                .map_err(|_| protocol_error("option lines that are not text"))?;
            let mut carried = false;
            for digits in text.lines().filter_map(|line| line.strip_prefix(LINE)) {
                bytes.extend(hex::decode(digits)?);
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
        Ok(Box::new(Bound::new(self.clone(), self.bind_udp()?)))
    }

    fn send_to(&self, address: &str, payload: &[u8]) -> Result<()> {
        ceiling::within(payload.len(), MAX_STREAM, "the largest DHCP message holds")?;
        let (client, _) = socket::bind_udp("127.0.0.1:0", self.timeout)?;
        let mut informs: Vec<String> = payload
            .chunks(OPTION)
            .map(|chunk| format!("message-type=inform\n{LINE}{}\n", hex::encode(chunk)))
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
