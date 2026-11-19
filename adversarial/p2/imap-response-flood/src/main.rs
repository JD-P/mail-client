use futures_util::TryStreamExt;
use std::{env, fs, panic};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream};

fn command_tag(line: &str) -> Result<&str, String> {
    line.split_ascii_whitespace()
        .next()
        .ok_or_else(|| "client sent an empty command".to_owned())
}

async fn read_command(
    reader: &mut BufReader<tokio::io::ReadHalf<DuplexStream>>,
) -> Result<String, String> {
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .await
        .map_err(|error| format!("reading client command: {error}"))?;
    if !line.ends_with("\r\n") {
        return Err("client command did not end in CRLF".to_owned());
    }
    Ok(line)
}

async fn malicious_list_server(
    stream: DuplexStream,
    count: usize,
) -> Result<(usize, usize), String> {
    let (read, mut write) = tokio::io::split(stream);
    let mut read = BufReader::new(read);
    write
        .write_all(b"* OK local malicious-server harness ready\r\n")
        .await
        .map_err(|error| format!("writing greeting: {error}"))?;

    let login = read_command(&mut read).await?;
    let login_tag = command_tag(&login)?;
    write
        .write_all(format!("{login_tag} OK LOGIN complete\r\n").as_bytes())
        .await
        .map_err(|error| format!("writing LOGIN completion: {error}"))?;

    let list = read_command(&mut read).await?;
    let list_tag = command_tag(&list)?;
    let mut emitted = 0usize;
    let mut wire_bytes = 0usize;
    let mut block = String::with_capacity(64 * 1024);
    for index in 0..count {
        let response = format!("* LIST () \"/\" \"mailbox-{index:08}\"\r\n");
        wire_bytes += response.len();
        block.push_str(&response);
        if block.len() >= 60 * 1024 {
            write
                .write_all(block.as_bytes())
                .await
                .map_err(|error| format!("writing LIST responses: {error}"))?;
            block.clear();
        }
        emitted += 1;
    }
    if !block.is_empty() {
        write
            .write_all(block.as_bytes())
            .await
            .map_err(|error| format!("writing final LIST response block: {error}"))?;
    }
    let completion = format!("{list_tag} OK LIST complete\r\n");
    wire_bytes += completion.len();
    write
        .write_all(completion.as_bytes())
        .await
        .map_err(|error| format!("writing LIST completion: {error}"))?;
    write
        .shutdown()
        .await
        .map_err(|error| format!("closing server stream: {error}"))?;
    Ok((emitted, wire_bytes))
}

async fn list_flood(count: usize) -> Result<(), String> {
    let (client_stream, server_stream) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(malicious_list_server(server_stream, count));
    let mut client = async_imap::Client::new(client_stream);
    let greeting = client
        .read_response()
        .await
        .map_err(|error| format!("reading greeting: {error}"))?;
    if greeting.is_none() {
        return Err("server closed before greeting".to_owned());
    }
    let mut session = client
        .login("local-user", "local-password")
        .await
        .map_err(|(error, _)| format!("logging in: {error}"))?;
    let names = session
        .list(None, Some("\"*\""))
        .await
        .map_err(|error| format!("starting LIST: {error}"))?
        .try_collect::<Vec<_>>()
        .await;
    match names {
        Ok(names) => {
            let (emitted, wire_bytes) = server
                .await
                .map_err(|error| format!("server task failed: {error}"))??;
            println!(
                "requested={count} emitted={emitted} collected={} wire_bytes={wire_bytes} rejected=false peak_rss_kib={}",
                names.len(),
                peak_rss_kib()
            );
        }
        Err(error) => {
            drop(session);
            let _ = server.await;
            println!(
                "requested={count} rejected=true error={error:?} peak_rss_kib={}",
                peak_rss_kib()
            );
        }
    }
    Ok(())
}

fn peak_rss_kib() -> String {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("VmHWM:"))
                .and_then(|value| value.split_ascii_whitespace().next())
                .and_then(|value| value.parse::<usize>().ok())
        })
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unavailable".to_owned())
}

fn xorshift(state: &mut u64) -> u64 {
    *state ^= *state << 13;
    *state ^= *state >> 7;
    *state ^= *state << 17;
    *state
}

fn parser_fuzz(iterations: usize) -> Result<(), String> {
    let seeds: [&[u8]; 12] = [
        b"* OK ready\r\n",
        b"* LIST () \"/\" \"INBOX\"\r\n",
        b"* 1 FETCH (UID 1 FLAGS (\\Seen) RFC822.SIZE 42)\r\n",
        b"* SEARCH 1 2 3\r\n",
        b"* STATUS INBOX (MESSAGES 1 UIDNEXT 2)\r\n",
        b"* 1 FETCH (BODY[] {4}\r\ntest)\r\n",
        b"+ Y2hhbGxlbmdl\r\n",
        b"A0001 OK complete\r\n",
        b"* METADATA INBOX (/shared/comment \"x\")\r\n",
        b"* VANISHED (EARLIER) 1:42\r\n",
        b"* ESEARCH (TAG \"A0001\") UID ALL 1:9 COUNT 9\r\n",
        b"* NAMESPACE ((\"\" \"/\")) NIL NIL\r\n",
    ];
    let mut state = 0x5eed_15ea_5e00_0001u64;
    for iteration in 0..iterations {
        let seed = seeds[(xorshift(&mut state) as usize) % seeds.len()];
        let mut candidate = seed.to_vec();
        let changes = 1 + (xorshift(&mut state) as usize % 12);
        for _ in 0..changes {
            match xorshift(&mut state) % 4 {
                0 if !candidate.is_empty() => {
                    let at = xorshift(&mut state) as usize % candidate.len();
                    candidate[at] = xorshift(&mut state) as u8;
                }
                1 if candidate.len() < 4096 => {
                    let at = xorshift(&mut state) as usize % (candidate.len() + 1);
                    candidate.insert(at, xorshift(&mut state) as u8);
                }
                2 if !candidate.is_empty() => {
                    let at = xorshift(&mut state) as usize % candidate.len();
                    candidate.remove(at);
                }
                _ if candidate.len() < 4096 => {
                    let repeats = 1 + xorshift(&mut state) as usize % 64;
                    let byte = xorshift(&mut state) as u8;
                    candidate.extend(std::iter::repeat_n(byte, repeats));
                }
                _ => {}
            }
        }
        let parsed = panic::catch_unwind(|| imap_proto::Response::parse(&candidate));
        if parsed.is_err() {
            return Err(format!(
                "imap-proto panicked at iteration {iteration} on {:02x?}",
                candidate
            ));
        }
    }
    println!("parser_iterations={iterations} panics=0 max_input_bytes=4096");
    Ok(())
}

fn exercise_mail(candidate: &[u8]) {
    let Some(message) = mail_parser::MessageParser::new()
        .max_depth(32)
        .max_parts(1024)
        .max_encoded_nesting(4)
        .parse(candidate)
    else {
        return;
    };
    std::hint::black_box(message.subject());
    std::hint::black_box(message.from());
    std::hint::black_box(message.to());
    for header in message.headers() {
        std::hint::black_box(header.raw_name());
        std::hint::black_box(header.value());
    }
    for part in message.parts() {
        std::hint::black_box(part.content_type());
        std::hint::black_box(part.attachment_name());
        std::hint::black_box(part.decoded_checked());
    }
    for body in message.text_bodies() {
        std::hint::black_box(body);
    }
    for body in message.html_bodies() {
        std::hint::black_box(body);
    }
}

fn mime_fuzz(iterations: usize) -> Result<(), String> {
    let seeds: [&[u8]; 8] = [
        b"From: Sender <sender@example.test>\r\nTo: Recipient <recipient@example.test>\r\nSubject: ordinary\r\n\r\nHello.\r\n",
        b"From: =?UTF-8?Q?Abigail_Marie?= <a@example.test>\r\nSubject: =?UTF-8?B?8J+UkQ==?=\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nline=3Done\r\n",
        b"Content-Type: multipart/mixed; boundary=outer\r\n\r\n--outer\r\nContent-Type: text/html\r\n\r\n<p>Hello <a href=\"https://example.test/\">world</a></p>\r\n--outer\r\nContent-Disposition: attachment; filename*=utf-8''report%20one.txt\r\nContent-Transfer-Encoding: base64\r\n\r\ndGVzdA==\r\n--outer--\r\n",
        b"Content-Type: message/rfc822\r\n\r\nFrom: nested@example.test\r\nSubject: nested\r\n\r\nbody\r\n",
        b"Received: from mx.example.test ([192.0.2.1]) by local.test with ESMTPS id 42; Thu, 19 Nov 2026 12:00:00 +0000\r\nAuthentication-Results: local.test; dkim=pass header.d=example.test\r\nDKIM-Signature: v=1; a=rsa-sha256; d=example.test; s=mail; bh=x; b=y\r\n\r\nbody\r\n",
        b"From: Group: one@example.test, two@example.test;\r\nTo: undisclosed-recipients:;\r\nReferences: <one@example.test> <two@example.test>\r\nIn-Reply-To: <two@example.test>\r\n\r\nthread\r\n",
        b"Content-Type: multipart/alternative; boundary=\"a b\"\r\n\r\n--a b\r\nContent-Type: text/plain; charset=utf-16\r\nContent-Transfer-Encoding: base64\r\n\r\n//5oAGkA\r\n--a b\r\nContent-Type: text/html\r\n\r\n<b>hi</b>\r\n--a b--\r\n",
        b"Content-Type: application/octet-stream; name=blob.bin\r\nContent-Disposition: attachment; filename=blob.bin\r\nContent-Transfer-Encoding: base64\r\n\r\nAAECAwQFBgcICQ==\r\n",
    ];
    let mut state = 0x6d69_6d65_5eed_0002u64;
    for iteration in 0..iterations {
        let seed = seeds[(xorshift(&mut state) as usize) % seeds.len()];
        let mut candidate = seed.to_vec();
        let changes = 1 + xorshift(&mut state) as usize % 24;
        for _ in 0..changes {
            match xorshift(&mut state) % 5 {
                0 if !candidate.is_empty() => {
                    let at = xorshift(&mut state) as usize % candidate.len();
                    candidate[at] = xorshift(&mut state) as u8;
                }
                1 if candidate.len() < 65_536 => {
                    let at = xorshift(&mut state) as usize % (candidate.len() + 1);
                    candidate.insert(at, xorshift(&mut state) as u8);
                }
                2 if !candidate.is_empty() => {
                    let at = xorshift(&mut state) as usize % candidate.len();
                    candidate.remove(at);
                }
                3 if candidate.len() < 65_536 => {
                    let repeats = 1 + xorshift(&mut state) as usize % 512;
                    let byte = xorshift(&mut state) as u8;
                    candidate.extend(std::iter::repeat_n(byte, repeats));
                }
                _ if candidate.len() < 65_536 => {
                    let fragment = seeds[(xorshift(&mut state) as usize) % seeds.len()];
                    let count = fragment.len().min(65_536 - candidate.len());
                    candidate.extend_from_slice(&fragment[..count]);
                }
                _ => {}
            }
        }
        let parsed = panic::catch_unwind(|| exercise_mail(&candidate));
        if parsed.is_err() {
            return Err(format!(
                "mail-parser panicked at iteration {iteration} on {} bytes",
                candidate.len()
            ));
        }
    }
    println!("mime_iterations={iterations} panics=0 max_input_bytes=65536");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), String> {
    let mut args = env::args().skip(1);
    match args.next().as_deref() {
        Some("list-flood") => {
            let count = args
                .next()
                .as_deref()
                .unwrap_or("20000")
                .parse::<usize>()
                .map_err(|error| format!("invalid LIST count: {error}"))?;
            list_flood(count).await
        }
        Some("parser-fuzz") => {
            let iterations = args
                .next()
                .as_deref()
                .unwrap_or("1000000")
                .parse::<usize>()
                .map_err(|error| format!("invalid iteration count: {error}"))?;
            parser_fuzz(iterations)
        }
        Some("mime-fuzz") => {
            let iterations = args
                .next()
                .as_deref()
                .unwrap_or("1000000")
                .parse::<usize>()
                .map_err(|error| format!("invalid iteration count: {error}"))?;
            mime_fuzz(iterations)
        }
        _ => Err("usage: p2-imap-response-flood list-flood [count] | parser-fuzz [iterations] | mime-fuzz [iterations]".to_owned()),
    }
}
