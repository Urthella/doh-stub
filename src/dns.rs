//! The few parts of the DNS wire format (RFC 1035) a forwarder has to touch: the ID, the largest
//! UDP reply a client accepts (RFC 6891), and the short replies it sends on its own.

pub const HEADER_LEN: usize = 12;
const TYPE_OPT: u16 = 41;

pub fn id(msg: &[u8]) -> u16 {
    u16::from_be_bytes([msg[0], msg[1]])
}

pub fn set_id(msg: &mut [u8], id: u16) {
    msg[..2].copy_from_slice(&id.to_be_bytes());
}

/// QR is set, so the message is a response, not a query.
pub fn is_response(msg: &[u8]) -> bool {
    msg[2] & 0x80 != 0
}

fn u16_at(msg: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_be_bytes([*msg.get(at)?, *msg.get(at + 1)?]))
}

/// Steps over a domain name, which ends with a zero-length label or a compression pointer.
fn skip_name(msg: &[u8], mut at: usize) -> Option<usize> {
    loop {
        let len = *msg.get(at)?;
        match len >> 6 {
            0 if len == 0 => return Some(at + 1),
            0 => at += 1 + len as usize,
            0b11 => return Some(at + 2),
            _ => return None, // label types 01 and 10 were never deployed
        }
    }
}

/// Where the question section ends.
fn question_end(msg: &[u8]) -> Option<usize> {
    let mut at = HEADER_LEN;
    for _ in 0..u16_at(msg, 4)? {
        at = skip_name(msg, at)? + 4;
    }
    (at <= msg.len()).then_some(at)
}

/// The largest UDP reply the client accepts: the payload size in its EDNS(0) OPT record, or 512
/// bytes if it has none. Sizes below 512 count as 512 (RFC 6891 section 6.2.3).
pub fn udp_limit(query: &[u8]) -> usize {
    let advertised = || {
        let mut at = question_end(query)?;
        let records = (6..12)
            .step_by(2)
            .map(|i| u16_at(query, i).map(usize::from));
        for _ in 0..records.sum::<Option<usize>>()? {
            at = skip_name(query, at)?;
            if u16_at(query, at)? == TYPE_OPT {
                return u16_at(query, at + 2); // an OPT record's CLASS field holds the size
            }
            at += 10 + usize::from(u16_at(query, at + 8)?);
        }
        None
    };
    advertised().map_or(512, |size| usize::from(size).max(512))
}

/// The header and the question, with every other section dropped.
fn header_and_question(msg: &[u8]) -> Vec<u8> {
    let Some(end) = question_end(msg) else {
        let mut out = msg[..HEADER_LEN].to_vec();
        out[4..].fill(0);
        return out;
    };
    let mut out = msg[..end].to_vec();
    out[6..HEADER_LEN].fill(0);
    out
}

/// A response cut down to fit UDP, with TC set so the client asks again over TCP.
pub fn truncated(response: &[u8]) -> Vec<u8> {
    let mut out = header_and_question(response);
    out[2] |= 0x02;
    out
}

/// A SERVFAIL reply to a query, so the client gives up at once instead of waiting.
pub fn servfail(query: &[u8]) -> Vec<u8> {
    let mut out = header_and_question(query);
    out[2] = 0x80 | (out[2] & 0x79); // QR, keeping the opcode and RD
    out[3] = 0x80 | 2; // RA, RCODE 2
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query};
    use hickory_proto::rr::rdata::{A, NS};
    use hickory_proto::rr::{Name, RData, Record, RecordType};

    /// A message with answers and authorities ahead of the OPT record, whose names hickory
    /// compresses into pointers back to the question.
    fn message(udp_size: Option<u16>) -> Vec<u8> {
        let name = Name::from_ascii("www.example.com.").unwrap();
        let zone = Name::from_ascii("example.com.").unwrap();
        let mut m = Message::new(42, MessageType::Response, OpCode::Query);
        m.add_query(Query::query(name.clone(), RecordType::A));
        m.add_answer(Record::from_rdata(
            name,
            60,
            RData::A(A([192, 0, 2, 9].into())),
        ));
        let ns = Name::from_ascii("ns1.example.com.").unwrap();
        m.authorities
            .push(Record::from_rdata(zone, 60, RData::NS(NS(ns))));
        if let Some(size) = udp_size {
            let mut edns = Edns::new();
            edns.set_max_payload(size);
            m.set_edns(edns);
        }
        m.to_vec().unwrap()
    }

    #[test]
    fn finds_the_edns_size_past_compressed_records() {
        assert!(
            message(None).windows(2).any(|w| w[0] >= 0xc0),
            "the names are compressed"
        );
        assert_eq!(udp_limit(&message(None)), 512);
        assert_eq!(udp_limit(&message(Some(1232))), 1232);
        assert_eq!(udp_limit(&message(Some(65535))), 65535);
        assert_eq!(
            udp_limit(&message(Some(100))),
            512,
            "below 512 counts as 512"
        );
    }

    #[test]
    fn short_replies_keep_the_id_and_question() {
        let original = Message::from_vec(&message(Some(1232))).unwrap();
        for (bytes, servfail) in [
            (truncated(&message(Some(1232))), false),
            (servfail(&message(None)), true),
        ] {
            let reply = Message::from_vec(&bytes).unwrap();
            assert_eq!(reply.metadata.id, 42);
            assert_eq!(reply.queries, original.queries);
            assert!(
                reply.answers.is_empty() && reply.authorities.is_empty() && reply.edns.is_none()
            );
            assert_eq!(reply.metadata.truncation, !servfail);
            assert_eq!(reply.metadata.message_type, MessageType::Response);
        }
    }

    #[test]
    fn never_panics_on_damaged_messages() {
        let mut seed = 0x9e3779b97f4a7c15u64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let good = message(Some(1232));
        for _ in 0..20_000 {
            let mut m =
                good[..HEADER_LEN + next() as usize % (good.len() - HEADER_LEN + 1)].to_vec();
            for _ in 0..next() % 4 {
                let at = next() as usize % m.len();
                m[at] = next() as u8;
            }
            assert!(udp_limit(&m) >= 512);
            let cut = truncated(&m);
            assert!(cut.len() >= HEADER_LEN && cut[2] & 0x02 != 0);
            assert_eq!(servfail(&m)[3] & 0x0f, 2);
        }
    }
}
