//! A DNS-over-HTTPS stub: it takes plain DNS queries on a local port and forwards each one to a
//! DoH server (RFC 8484), as `cloudflared proxy-dns` did before Cloudflare removed it.

mod dns;

use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream, UdpSocket};
use std::sync::Arc;
use std::time::Duration;
use std::{env, process, thread};

use ureq::Agent;
use ureq::tls::{TlsConfig, TlsProvider};

/// The defaults `cloudflared proxy-dns` used. IP addresses, so no DNS is needed to reach them.
const DEFAULT_UPSTREAMS: [&str; 2] = ["https://1.1.1.1/dns-query", "https://1.0.0.1/dns-query"];
/// ponytail: fixed pools of blocking workers cap it at 16 UDP queries and 16 TCP connections at
/// once; plenty for a home network or a Pi-hole, move to async if one stub has to serve thousands.
const WORKERS: usize = 16;
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(4);
/// How long a TCP connection may sit idle before it's closed (RFC 7766 section 6.2.3).
const TCP_IDLE: Duration = Duration::from_secs(10);
const USAGE: &str = "usage: doh-stub [--address 127.0.0.1] [--port 53] [--upstream URL]...";

struct Config {
    address: String,
    port: u16,
    upstreams: Vec<String>,
}

fn parse_args(mut args: impl Iterator<Item = String>) -> Result<Config, String> {
    let mut config = Config {
        address: "127.0.0.1".into(),
        port: 53,
        upstreams: vec![],
    };
    while let Some(flag) = args.next() {
        let mut value = || args.next().ok_or(format!("{flag} needs a value\n{USAGE}"));
        match flag.as_str() {
            "--address" => config.address = value()?,
            "--port" => config.port = value()?.parse().map_err(|_| "--port takes 0 to 65535")?,
            "--upstream" => config.upstreams.push(value()?),
            "-h" | "--help" => return Err(USAGE.into()),
            other => return Err(format!("unknown flag {other}\n{USAGE}")),
        }
    }
    if config.upstreams.is_empty() {
        config.upstreams = DEFAULT_UPSTREAMS.map(String::from).to_vec();
    }
    Ok(config)
}

/// POSTs the query to one DoH server and returns the DNS message it sends back.
fn ask(agent: &Agent, url: &str, query: &[u8]) -> Result<Vec<u8>, ureq::Error> {
    let reply = agent
        .post(url)
        .header("content-type", "application/dns-message")
        .header("accept", "application/dns-message")
        .send(query)?
        .body_mut()
        .with_config()
        .limit(65535)
        .read_to_vec()?;
    if reply.len() < dns::HEADER_LEN {
        return Err(ureq::Error::Other(
            "the reply is too short to be DNS".into(),
        ));
    }
    Ok(reply)
}

/// The answer to a query: from the first upstream that gives one, or SERVFAIL if none does.
fn answer(agent: &Agent, upstreams: &[String], query: &[u8]) -> Vec<u8> {
    // RFC 8484 section 4.1: use ID 0, so the same question always makes the same HTTP request.
    let mut asked = query.to_vec();
    dns::set_id(&mut asked, 0);
    let mut reply = upstreams
        .iter()
        .find_map(|url| {
            ask(agent, url, &asked)
                .inspect_err(|e| eprintln!("doh-stub: {url}: {e}"))
                .ok()
        })
        .unwrap_or_else(|| dns::servfail(query));
    dns::set_id(&mut reply, dns::id(query));
    reply
}

fn serve_udp(socket: UdpSocket, agent: Agent, upstreams: Arc<[String]>) {
    let mut buf = [0u8; 65535];
    loop {
        // On Windows a send to a client that has gone away makes the next receive fail; skip it.
        let Ok((len, client)) = socket.recv_from(&mut buf) else {
            continue;
        };
        let query = &buf[..len];
        if len < dns::HEADER_LEN || dns::is_response(query) {
            continue;
        }
        let mut reply = answer(&agent, &upstreams, query);
        if reply.len() > dns::udp_limit(query) {
            reply = dns::truncated(&reply);
        }
        let _ = socket.send_to(&reply, client);
    }
}

fn serve_tcp(listener: TcpListener, agent: Agent, upstreams: Arc<[String]>) {
    for stream in listener.incoming().flatten() {
        let _ = answer_tcp(stream, &agent, &upstreams);
    }
}

/// DNS over TCP (RFC 7766), where clients come after a UDP answer was cut: each message has its
/// length in front, as two bytes, and one connection can carry several queries.
fn answer_tcp(mut stream: TcpStream, agent: &Agent, upstreams: &[String]) -> io::Result<()> {
    stream.set_read_timeout(Some(TCP_IDLE))?;
    loop {
        let mut len = [0u8; 2];
        stream.read_exact(&mut len)?; // the client closing, or going idle, ends the connection
        let mut query = vec![0u8; usize::from(u16::from_be_bytes(len))];
        stream.read_exact(&mut query)?;
        if query.len() < dns::HEADER_LEN || dns::is_response(&query) {
            return Ok(());
        }
        let reply = answer(agent, upstreams, &query);
        // Upstream bodies are capped at 65535 bytes, so the length always fits.
        let mut framed = (reply.len() as u16).to_be_bytes().to_vec();
        framed.extend(reply);
        stream.write_all(&framed)?;
    }
}

fn main() {
    let config = parse_args(env::args().skip(1)).unwrap_or_else(|message| {
        eprintln!("{message}");
        process::exit(2)
    });
    let socket = UdpSocket::bind((config.address.as_str(), config.port)).unwrap_or_else(|e| {
        eprintln!(
            "doh-stub: can't listen on {}:{}: {e}",
            config.address, config.port
        );
        process::exit(1)
    });
    // TCP on the address UDP got, so `--port 0` gives both the same port.
    let address = socket.local_addr().unwrap();
    let listener = TcpListener::bind(address).unwrap_or_else(|e| {
        eprintln!("doh-stub: can't listen on tcp://{address}: {e}");
        process::exit(1)
    });
    println!("doh-stub: listening on udp://{address} and tcp://{address}");

    let agent: Agent = Agent::config_builder()
        .tls_config(
            TlsConfig::builder()
                .provider(TlsProvider::NativeTls)
                .build(),
        )
        .timeout_global(Some(UPSTREAM_TIMEOUT))
        .max_idle_connections_per_host(WORKERS)
        .build()
        .into();
    let upstreams: Arc<[String]> = config.upstreams.into();
    let mut workers = Vec::new();
    for _ in 0..WORKERS {
        let socket = socket.try_clone().expect("a UDP socket can be shared");
        let (a, u) = (agent.clone(), upstreams.clone());
        workers.push(thread::spawn(move || serve_udp(socket, a, u)));
        let listener = listener.try_clone().expect("a TCP listener can be shared");
        let (a, u) = (agent.clone(), upstreams.clone());
        workers.push(thread::spawn(move || serve_tcp(listener, a, u)));
    }
    for worker in workers {
        let _ = worker.join();
    }
}
