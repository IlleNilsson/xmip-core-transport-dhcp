#![forbid(unsafe_code)]

//! Streams that arrive as DHCP client messages. One message is one
//! Stream: its options, one `name=value` line each, with the transaction,
//! type, hardware address and hostname in the origin.
//!
//! DHCP (RFC 2131) is the first thing a device says on a network, which
//! makes a Receive Location on port 67 the earliest possible sight of one:
//! a discover names the device, a request names the address it wants, a
//! release says it has gone, an inform asks for configuration. A Send
//! Location is how an Xmip Journey answers — offers, acknowledges or
//! refuses a lease from whatever authoritative source it consulted: the
//! asset register, the network team's allocation, a policy. The transport
//! carries the conversation; the Journey decides.
//!
//! The origin URI carries what the fixed fields and option 53 knew:
//! `dhcp://peer?xid=0x3903f326&type=discover&mac=aa:bb:cc:dd:ee:ff&hostname=printer-7`.
//!
//! A send goes to `dhcp://host:port?xid=0x3903f326&mac=aa:bb:cc:dd:ee:ff`
//! `&type=offer&yiaddr=10.0.0.9&server=10.0.0.1` — the port being 68 at
//! the client or 67 at a relay — and the bytes' `name=value` lines are the
//! options. `xid` and `mac` name the transaction being answered and are
//! required; `type` defaults to `ack`, `server` sets both `siaddr` and
//! option 54, and a bare `host:port` answers nothing and is refused.

pub mod loopback;
pub mod message;
mod option;

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

pub use loopback::MAX_STREAM;
pub use message::{BOOTREPLY, BOOTREQUEST, MAX_MESSAGE, Message, MessageType};
use transport::error::{Result, classify, protocol_error};
use transport::socket;
use transport::{Arrived, Directions, Transport};

#[derive(Clone)]
pub struct DhcpTransport {
    bind: String,
    timeout: Option<Duration>,
}

impl DhcpTransport {
    /// Listen at `bind`, `0.0.0.0:67` being the server port.
    #[must_use]
    pub fn new(bind: impl Into<String>) -> Self {
        Self {
            bind: bind.into(),
            timeout: None,
        }
    }

    /// Give up waiting for a message after `timeout`.
    #[must_use]
    pub const fn timing_out_after(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Bind the UDP socket and report the address actually assigned.
    ///
    /// # Errors
    /// Where the address is taken, malformed, or not permitted.
    pub fn bind_udp(&self) -> Result<(UdpSocket, String)> {
        socket::bind_udp(&self.bind, self.timeout)
    }

    /// Take one client message from an already-bound socket. A reply
    /// arriving — another server's — is skipped.
    ///
    /// # Errors
    /// Where nothing arrived in time, or what arrived is not DHCP.
    pub fn receive_datagram(&self, socket: &UdpSocket) -> Result<Arrived> {
        let mut buffer = vec![0u8; MAX_MESSAGE * 2];
        loop {
            let (read, peer) = socket
                .recv_from(&mut buffer)
                .map_err(|e| classify("receiving a datagram", &e))?;
            let message = message::decode(&buffer[..read])?;
            if message.op == BOOTREQUEST {
                return Ok(arrived(peer, &message));
            }
        }
    }

    /// The reply `target` describes, its options being `bytes`' lines.
    ///
    /// # Errors
    /// A target that is not `dhcp://host:port?xid=…&mac=…`, or lines that
    /// are not options.
    pub fn reply_for(target: &str, bytes: &[u8]) -> Result<(String, Message)> {
        let Some((address, rest)) = socket::target("dhcp", target) else {
            return Err(protocol_error(format!(
                "a dhcp target answers a transaction: dhcp://host:port?xid=…&mac=…, got {target}"
            )));
        };
        let query = rest
            .strip_prefix('?')
            .or_else(|| address.split_once('?').map(|(_, q)| q));
        let address = address.split_once('?').map_or(address, |(a, _)| a);
        let value = |key: &str| {
            query?
                .split('&')
                .find_map(|pair| pair.strip_prefix(key)?.strip_prefix('='))
        };
        let xid = value("xid")
            .and_then(parse_xid)
            .ok_or_else(|| protocol_error(format!("a reply without ?xid=: {target}")))?;
        let mac = value("mac")
            .and_then(Message::parse_mac)
            .ok_or_else(|| protocol_error(format!("a reply without &mac=: {target}")))?;
        let kind = match value("type") {
            None => MessageType::Ack,
            Some(name) => MessageType::parse(name)
                .ok_or_else(|| protocol_error(format!("not a message type: {name}")))?,
        };
        let address_of = |key: &str| -> Result<Ipv4Addr> {
            value(key).map_or(Ok(Ipv4Addr::UNSPECIFIED), |text| {
                text.parse()
                    .map_err(|_| protocol_error(format!("&{key}= is not an address: {text}")))
            })
        };
        let mut reply = Message::new(BOOTREPLY, xid, &mac);
        reply.yiaddr = address_of("yiaddr")?;
        reply.siaddr = address_of("server")?;
        reply = reply.with(message::OPTION_MESSAGE_TYPE, vec![kind as u8]);
        let server = reply.siaddr;
        if !server.is_unspecified() {
            reply = reply.with(message::OPTION_SERVER, server.octets().to_vec());
        }
        Ok((address.to_string(), reply.with_lines(bytes)?))
    }
}

/// `0x3903f326` or `956363558`.
fn parse_xid(text: &str) -> Option<u32> {
    match text.strip_prefix("0x") {
        Some(hex) => u32::from_str_radix(hex, 16).ok(),
        None => text.parse().ok(),
    }
}

fn arrived(peer: SocketAddr, message: &Message) -> Arrived {
    Arrived::new(
        format!(
            "dhcp://{peer}?xid={:#010x}&type={}&mac={}&hostname={}",
            message.xid,
            message.message_type().map_or("bootp", MessageType::name),
            message.mac(),
            message.hostname()
        ),
        message.option_lines(),
    )
}

impl Transport for DhcpTransport {
    fn name(&self) -> &'static str {
        "dhcp"
    }

    fn directions(&self) -> Directions {
        Directions::BOTH
    }

    fn receive(&self) -> Result<Vec<Arrived>> {
        let (socket, _) = self.bind_udp()?;
        Ok(vec![self.receive_datagram(&socket)?])
    }

    fn send(&self, target: &str, bytes: &[u8]) -> Result<()> {
        let (address, reply) = Self::reply_for(target, bytes)?;
        let sender =
            UdpSocket::bind("0.0.0.0:0").map_err(|e| classify("binding the sending socket", &e))?;
        sender
            .send_to(&message::encode(&reply)?, address)
            .map_err(|e| classify("sending the reply", &e))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use transport::loopback::Loopback;

    const MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

    fn node() -> DhcpTransport {
        DhcpTransport::new("127.0.0.1:0").timing_out_after(Duration::from_secs(2))
    }

    /// `len` bytes that a truncation, a reorder or a duplicate would change.
    fn patterned(len: usize) -> Vec<u8> {
        (0..len)
            .map(|at| u8::try_from((at * 31 + at / 251) % 256).unwrap_or(0))
            .collect()
    }

    #[test]
    fn a_stream_rounds_as_informs_each_acknowledged() {
        let loopback = DhcpTransport::loopback();
        let opaque: &[u8] = b"\x00line\r\nbreak \xff";
        let arrived = loopback.round(opaque).expect("opaque");
        assert_eq!(arrived.bytes, opaque);
        assert!(
            arrived.origin_uri.starts_with("dhcp://127.0.0.1:"),
            "{}",
            arrived.origin_uri
        );
        assert!(
            arrived
                .origin_uri
                .contains("?xid=0x786d6970&type=inform&mac=02:00:00:78:6d:69")
        );
        let long = vec![0x2a; 3000];
        assert_eq!(loopback.round(&long).expect("long").bytes, long);
        assert!(loopback.round(b"").expect("empty").bytes.is_empty());
        assert_eq!(loopback.ceiling(), Some(MAX_STREAM));
        assert!(loopback.refuses(opaque).is_none());
    }

    #[test]
    fn the_loopback_returns_the_edges_whole_and_refuses_over_the_ceiling() {
        let loopback = DhcpTransport::loopback();
        let edges: [(&str, Vec<u8>); 7] = [
            ("empty", Vec::new()),
            ("one byte", vec![0x2a]),
            ("every byte", (0..=255).collect()),
            ("nul run", vec![0; 512]),
            ("high bytes", vec![0xff; 512]),
            ("crlf storm", b"\r\n".repeat(400)),
            ("brim", patterned(MAX_STREAM)),
        ];
        for (name, payload) in edges {
            assert_eq!(
                loopback.round(&payload).expect(name).bytes,
                payload,
                "{name}"
            );
        }
        let over = loopback.round(&vec![0; MAX_STREAM + 1]).expect_err("over");
        assert!(over.message.starts_with("send failed:"), "{over}");
        assert!(over.message.contains("65291"), "{over}");
    }

    #[test]
    fn a_discover_arrives_as_its_options_with_the_client_in_the_origin() {
        let far_end = node();
        let (socket, address) = far_end.bind_udp().expect("binding");
        let client = UdpSocket::bind("127.0.0.1:0").expect("client");
        let discover = Message::new(BOOTREQUEST, 0x3903_f326, &MAC)
            .with_lines(b"message-type=discover\nhostname=printer-7\nrequested-address=10.0.0.9\n")
            .expect("lines");
        client
            .send_to(&message::encode(&discover).expect("encode"), &address)
            .expect("discover");
        let arrived = far_end.receive_datagram(&socket).expect("receiving");
        assert!(
            arrived.origin_uri.ends_with(
                "?xid=0x3903f326&type=discover&mac=aa:bb:cc:dd:ee:ff&hostname=printer-7"
            ),
            "{}",
            arrived.origin_uri
        );
        assert_eq!(
            arrived.bytes,
            b"message-type=discover\nhostname=printer-7\nrequested-address=10.0.0.9\n"
        );
        let bootp = Message::new(BOOTREQUEST, 7, &MAC[..4]);
        client
            .send_to(&message::encode(&bootp).expect("encode"), &address)
            .expect("bootp");
        let plain = far_end.receive_datagram(&socket).expect("receiving");
        assert!(
            plain
                .origin_uri
                .ends_with("?xid=0x00000007&type=bootp&mac=aa:bb:cc:dd&hostname=")
        );
        assert!(plain.bytes.is_empty());
    }

    #[test]
    fn an_offer_reaches_the_client_with_its_lease() {
        let client = UdpSocket::bind("127.0.0.1:0").expect("client");
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("timeout");
        let address = client.local_addr().expect("address");
        node()
            .send(
                &format!(
                    "dhcp://{address}?xid=0x3903f326&mac=aa:bb:cc:dd:ee:ff&type=offer\
                     &yiaddr=10.0.0.9&server=10.0.0.1"
                ),
                b"subnet-mask=255.255.255.0\nrouter=10.0.0.1\ndns=10.0.0.1,10.0.0.2\nlease-time=3600\n",
            )
            .expect("offering");
        let mut buffer = [0u8; MAX_MESSAGE];
        let read = client.recv(&mut buffer).expect("the offer");
        let offer = message::decode(&buffer[..read]).expect("decode");
        assert_eq!(offer.op, BOOTREPLY);
        assert_eq!(offer.xid, 0x3903_f326);
        assert_eq!(offer.mac(), "aa:bb:cc:dd:ee:ff");
        assert_eq!(offer.yiaddr, Ipv4Addr::new(10, 0, 0, 9));
        assert_eq!(offer.siaddr, Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(offer.message_type(), Some(MessageType::Offer));
        assert_eq!(
            offer.option(message::OPTION_SERVER),
            Some(&[10, 0, 0, 1][..])
        );
        assert_eq!(
            offer.option(message::OPTION_SUBNET_MASK),
            Some(&[255, 255, 255, 0][..])
        );
        assert_eq!(offer.option(message::OPTION_DNS).map(<[u8]>::len), Some(8));
        assert_eq!(
            offer.option(message::OPTION_LEASE_TIME),
            Some(&[0, 0, 0x0e, 0x10][..])
        );
        node()
            .send(
                &format!("dhcp://{address}?xid=99&mac=aa:bb:cc:dd:ee:ff&type=nak"),
                b"",
            )
            .expect("refusing");
        let read = client.recv(&mut buffer).expect("the nak");
        let nak = message::decode(&buffer[..read]).expect("decode");
        assert_eq!(nak.message_type(), Some(MessageType::Nak));
        assert_eq!(nak.xid, 99);
        assert!(nak.option(message::OPTION_SERVER).is_none());
    }

    #[test]
    fn what_is_not_dhcp_is_refused_and_a_reply_arriving_is_skipped() {
        let far_end = node().timing_out_after(Duration::from_millis(300));
        let (socket, address) = far_end.bind_udp().expect("binding");
        let other = UdpSocket::bind("127.0.0.1:0").expect("sender");
        other.send_to(&[0; 100], &address).expect("junk");
        assert!(
            !far_end
                .receive_datagram(&socket)
                .expect_err("junk")
                .retryable
        );
        let reply = Message::new(BOOTREPLY, 1, &MAC);
        other
            .send_to(&message::encode(&reply).expect("encode"), &address)
            .expect("reply");
        assert!(
            far_end
                .receive_datagram(&socket)
                .expect_err("skipped")
                .retryable
        );
        for target in [
            address.as_str(),
            "dhcp://127.0.0.1:68",
            "dhcp://127.0.0.1:68?xid=1",
            "dhcp://127.0.0.1:68?xid=x&mac=aa",
            "dhcp://127.0.0.1:68?xid=1&mac=aa&type=lease",
            "dhcp://127.0.0.1:68?xid=1&mac=aa&yiaddr=here",
            "http://127.0.0.1:68?xid=1&mac=aa",
        ] {
            let error = node().send(target, b"").expect_err(target);
            assert!(!error.retryable, "{target}");
        }
        let bad_lines = node().send("dhcp://127.0.0.1:68?xid=1&mac=aa", b"router=nowhere");
        assert!(bad_lines.is_err());
        assert!(node().claims().is_none());
        assert_eq!(node().name(), "dhcp");
    }
}
