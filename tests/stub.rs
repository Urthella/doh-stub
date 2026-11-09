//! Runs the real binary against a fake DoH server and checks what crosses the wire both ways.
//! Every message is built and read with hickory-proto, an independent DNS implementation.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, TXT};
use hickory_proto::rr::{Name, RData, Record, RecordType};

/// A request the fake DoH server received.
struct Seen {
    request_line: String,
    content_type: String,
    body: Vec<u8>,
}

type Log = Arc<Mutex<Vec<Seen>>>;

/// A fake DoH server on 127.0.0.1, over plain HTTP. `reply` turns a query into (status, body).
fn fake_doh(reply: impl Fn(&[u8]) -> (u16, Vec<u8>) + Send + 'static) -> (String, Log) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/dns-query", listener.local_addr().unwrap());
    let log = Log::default();
    let seen = log.clone();
    thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            handle(stream, &reply, &seen);
        }
    });
    (url, log)
}

fn handle(
    mut stream: TcpStream,
    reply: &impl Fn(&[u8]) -> (u16, Vec<u8>),
    log: &Log,
) -> Option<()> {
    let mut reader = BufReader::new(stream.try_clone().ok()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line).ok()?;
    let (mut length, mut content_type) = (0, String::new());
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).ok()?;
        let Some((name, value)) = line.trim_end().split_once(':') else {
            break;
        };
        match name.to_ascii_lowercase().as_str() {
            "content-length" => length = value.trim().parse().ok()?,
            "content-type" => content_type = value.trim().to_string(),
            _ => {}
        }
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).ok()?;
    let (status, answer) = reply(&body);
    let request_line = request_line.trim_end().to_string();
    log.lock().unwrap().push(Seen {
        request_line,
        content_type,
        body,
    });
    let head = format!(
        "HTTP/1.1 {status} Fake\r\ncontent-type: application/dns-message\r\n\
         content-length: {}\r\nconnection: close\r\n\r\n",
        answer.len()
    );
    stream.write_all(head.as_bytes()).ok()?;
    stream.write_all(&answer).ok()
}

/// The stub, started with --port 0 so the system picks a free port; killed when dropped.
struct Stub {
    child: Child,
    addr: String,
}

impl Drop for Stub {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn start_stub(upstreams: &[&str]) -> Stub {
    let mut command = Command::new(env!("CARGO_BIN_EXE_doh-stub"));
    command.args(["--port", "0"]);
    for upstream in upstreams {
        command.args(["--upstream", upstream]);
    }
    let mut child = command
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut line = String::new();
    BufReader::new(child.stdout.take().unwrap())
        .read_line(&mut line)
        .unwrap();
    let addr = line
        .trim()
        .strip_prefix("doh-stub: listening on udp://")
        .unwrap()
        .to_string();
    Stub { child, addr }
}

fn client(timeout: Duration) -> UdpSocket {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_read_timeout(Some(timeout)).unwrap();
    socket
}

/// Sends a query to the stub and returns its reply and the reply's size in bytes.
fn ask(stub: &Stub, query: &Message) -> (Message, usize) {
    let socket = client(Duration::from_secs(20));
    socket
        .send_to(&query.to_vec().unwrap(), &stub.addr)
        .unwrap();
    let mut buf = [0u8; 65535];
    let len = socket.recv(&mut buf).unwrap();
    (Message::from_vec(&buf[..len]).unwrap(), len)
}

fn query(id: u16, name: &str, record_type: RecordType, udp_size: Option<u16>) -> Message {
    let mut message = Message::new(id, MessageType::Query, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.add_query(Query::query(Name::from_ascii(name).unwrap(), record_type));
    if let Some(size) = udp_size {
        let mut edns = Edns::new();
        edns.set_max_payload(size);
        message.set_edns(edns);
    }
    message
}

/// What a DoH server would send back: the query's own question, with these records.
fn answer_with(query: &[u8], records: Vec<Record>) -> Vec<u8> {
    let asked = Message::from_vec(query).unwrap();
    let mut message = Message::new(asked.metadata.id, MessageType::Response, OpCode::Query);
    message.metadata.recursion_desired = true;
    message.metadata.recursion_available = true;
    message.add_query(asked.queries[0].clone());
    message.add_answers(records);
    message.edns = asked.edns;
    message.to_vec().unwrap()
}

fn a_record(name: &str, ip: [u8; 4]) -> Record {
    Record::from_rdata(Name::from_ascii(name).unwrap(), 300, RData::A(A(ip.into())))
}

#[test]
fn forwards_a_query_the_way_rfc_8484_says_and_restores_its_id() {
    let (url, seen) = fake_doh(|q| {
        (
            200,
            answer_with(q, vec![a_record("example.com.", [192, 0, 2, 1])]),
        )
    });
    let stub = start_stub(&[&url]);

    let asked = query(0xbeef, "example.com.", RecordType::A, None);
    let (reply, _) = ask(&stub, &asked);
    assert_eq!(reply.metadata.id, 0xbeef);
    assert_eq!(reply.metadata.message_type, MessageType::Response);
    assert_eq!(reply.answers.len(), 1);
    assert_eq!(reply.answers[0].data, RData::A(A([192, 0, 2, 1].into())));

    let seen = seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].request_line, "POST /dns-query HTTP/1.1");
    assert_eq!(seen[0].content_type, "application/dns-message");
    let sent = Message::from_vec(&seen[0].body).unwrap();
    assert_eq!(sent.metadata.id, 0, "RFC 8484 section 4.1 asks for ID 0");
    assert_eq!(sent.queries, asked.queries);
}

#[test]
fn tries_the_next_upstream_when_one_fails() {
    let (failing, failed) = fake_doh(|_| (500, vec![]));
    let (garbled, garbled_seen) = fake_doh(|_| (200, b"not dns".to_vec()));
    let (working, worked) = fake_doh(|q| {
        (
            200,
            answer_with(q, vec![a_record("example.org.", [192, 0, 2, 7])]),
        )
    });
    let stub = start_stub(&[&failing, &garbled, &working]);

    let (reply, _) = ask(&stub, &query(7, "example.org.", RecordType::A, None));
    assert_eq!(reply.answers.len(), 1);
    assert_eq!(reply.metadata.id, 7);
    for (log, name) in [
        (failed, "the failing upstream"),
        (garbled_seen, "the garbled one"),
        (worked, "the working one"),
    ] {
        assert_eq!(log.lock().unwrap().len(), 1, "{name} was asked once");
    }
}

#[test]
fn answers_servfail_when_no_upstream_answers() {
    let (url, _) = fake_doh(|_| (500, vec![]));
    let stub = start_stub(&[&url]);

    let asked = query(0x1234, "example.net.", RecordType::AAAA, None);
    let (reply, _) = ask(&stub, &asked);
    assert_eq!(reply.metadata.id, 0x1234);
    assert_eq!(reply.metadata.message_type, MessageType::Response);
    assert_eq!(reply.metadata.response_code, ResponseCode::ServFail);
    assert!(reply.metadata.recursion_desired);
    assert_eq!(reply.queries, asked.queries);
    assert!(reply.answers.is_empty());
}

#[test]
fn cuts_an_answer_too_big_for_the_clients_udp_size() {
    // Twenty 200-byte TXT records: a reply of a little over 4 kB.
    let txt = |_| {
        let rdata = RData::TXT(TXT::new(vec!["x".repeat(200)]));
        Record::from_rdata(Name::from_ascii("big.example.").unwrap(), 60, rdata)
    };
    let (url, _) = fake_doh(move |q| (200, answer_with(q, (0..20).map(txt).collect())));
    let stub = start_stub(&[&url]);

    for (udp_size, fits) in [
        (None, false),
        (Some(1232), false),
        (Some(100), false),
        (Some(8192), true),
    ] {
        let asked = query(99, "big.example.", RecordType::TXT, udp_size);
        let (reply, len) = ask(&stub, &asked);
        assert_eq!(reply.metadata.id, 99);
        assert_eq!(reply.queries, asked.queries);
        if fits {
            assert!(!reply.metadata.truncation, "{udp_size:?}");
            assert_eq!(reply.answers.len(), 20, "{udp_size:?}");
        } else {
            assert!(
                reply.metadata.truncation,
                "{udp_size:?} should be cut, so the client uses TCP"
            );
            assert!(reply.answers.is_empty(), "{udp_size:?}");
            assert!(len <= 512, "{udp_size:?}: {len} bytes");
        }
    }
}

#[test]
fn ignores_packets_that_are_not_queries() {
    let (url, seen) = fake_doh(|q| (200, answer_with(q, vec![])));
    let stub = start_stub(&[&url]);

    let socket = client(Duration::from_millis(500));
    let mut response = query(5, "example.com.", RecordType::A, None);
    response.metadata.message_type = MessageType::Response;
    socket
        .send_to(&response.to_vec().unwrap(), &stub.addr)
        .unwrap();
    socket.send_to(b"short", &stub.addr).unwrap();
    assert!(
        socket.recv(&mut [0u8; 512]).is_err(),
        "neither should get a reply"
    );

    ask(&stub, &query(6, "example.com.", RecordType::A, None));
    assert_eq!(
        seen.lock().unwrap().len(),
        1,
        "only the real query went upstream"
    );
}
