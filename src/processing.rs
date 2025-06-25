use std::collections::HashMap;
use std::io::{self, BufRead, BufReader};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::process;
use std::sync::mpsc;
use std::thread;
use std::time::SystemTime;

use regex::Regex;
use serde_json;

use errors::{Error, Result};

use config::Config;
use gelf::{ChunkSize, ChunkedMessage, Message, OptFieldsIterator, WireMessage};
use gelf::{LevelMsg, LevelSystem};

const IGNORED_FIELDS: [&str; 9] = [
    "MESSAGE",
    "_HOSTNAME",
    "__REALTIME_TIMESTAMP",
    "PRIORITY",
    "__CURSOR",
    "_BOOT_ID",
    "_MACHINE_ID",
    "_SYSTEMD_CGROUP",
    "_SYSTEMD_SLICE",
];

type LogRecord = HashMap<String, serde_json::Value>;

pub fn process_journalctl(config: Config) -> Result<()> {
    // check OS
    if !is_platform_supported() {
        return Err(Error::InternalError(
            "operating system currently unsupported".to_string(),
        ));
    }

    let mut process_args = Vec::new();
    let slice = &["-o", "json", "-f", "--merge"];
    process_args.extend_from_slice(slice);

    if config.journal_dir.len() > 0 {
        process_args.push("--directory");
        process_args.push(&config.journal_dir);
    }

    let mut subprocess = process::Command::new("journalctl")
        .args(&process_args)
        .stdout(process::Stdio::piped())
        .stderr(process::Stdio::piped())
        .spawn()?;

    // Take ownership of stdout and stderr for threading
    let subprocess_stdout = subprocess.stdout.take().unwrap();
    let subprocess_stderr = subprocess.stderr.take().unwrap();

    // Create channels for communication between threads
    let (stdout_tx, stdout_rx) = mpsc::channel::<String>();
    let (stderr_tx, stderr_rx) = mpsc::channel::<String>();

    // Thread for handling stdout
    let stdout_handle = thread::spawn(move || {
        let mut reader = BufReader::new(subprocess_stdout);
        let mut line = String::new();
        loop {
            match reader.read_line(&mut line) {
                Ok(0) => {
                    debug!("journalctl stdout closed");
                    break; // EOF
                }
                Ok(_) => {
                    if stdout_tx.send(line.clone()).is_err() {
                        debug!("stdout receiver dropped, stopping stdout thread");
                        break;
                    }
                    line.clear();
                }
                Err(e) => {
                    error!("error reading journalctl stdout: {}", e);
                    break;
                }
            }
        }
    });

    // Thread for handling stderr
    let stderr_handle = thread::spawn(move || {
        let mut reader = BufReader::new(subprocess_stderr);
        let mut line = String::new();
        loop {
            match reader.read_line(&mut line) {
                Ok(0) => {
                    debug!("journalctl stderr closed");
                    break; // EOF
                }
                Ok(_) => {
                    if stderr_tx.send(line.clone()).is_err() {
                        debug!("stderr receiver dropped, stopping stderr thread");
                        break;
                    }
                    line.clear();
                }
                Err(e) => {
                    error!("error reading journalctl stderr: {}", e);
                    break;
                }
            }
        }
    });

    // bind to socket
    let sender = create_sender_udp(config.sender_port)?;

    // obtain target address (first resolve may fail)
    let (mut target_addr, mut target_addr_updated_at) = get_target_addr(&config.graylog_addr)?;

    debug!("start reading from journalctl");

    // Message counting for diagnostics
    let mut messages_received = 0u64;
    let mut messages_processed = 0u64;

    // Main loop - process stdout messages and log stderr messages
    loop {
        // Check for stderr messages (non-blocking)
        while let Ok(stderr_line) = stderr_rx.try_recv() {
            warn!("journalctl stderr: {}", stderr_line.trim());
        }

        // Wait for stdout messages (blocking)
        match stdout_rx.recv() {
            Ok(line) => {
                messages_received += 1;
                let msg = line.trim();

                // verify if stdout was closed (empty line could be valid JSON)
                if msg.is_empty() {
                    error!("Message dropped: Empty line received (message #{})", messages_received);
                    continue;
                }

                // renew outdated target address
                if target_addr_updated_at
                    .elapsed()
                    .unwrap_or_default()
                    .as_secs()
                    > config.graylog_addr_ttl
                {
                    match get_target_addr(&config.graylog_addr) {
                        Ok((addr, updated_at)) => {
                            target_addr = addr;
                            target_addr_updated_at = updated_at;
                            debug!("target address updated");
                        }

                        // use outdated address
                        Err(e) => warn!("cannot resolve graylog address: {}", e),
                    }
                }

                process_log_record(msg, &config, &sender, &target_addr);
                messages_processed += 1;
                
                // Log progress every 1000 messages
                if messages_processed % 1000 == 0 {
                    info!("Progress: Processed {}/{} messages ({:.1}% success rate)", 
                          messages_processed, messages_received, 
                          (messages_processed as f64 / messages_received as f64) * 100.0);
                }
            }
            Err(_) => {
                info!("Final stats: Processed {}/{} messages ({:.1}% success rate)", 
                      messages_processed, messages_received,
                      (messages_processed as f64 / messages_received as f64) * 100.0);
                debug!("stdout channel closed, stopping main loop");
                break;
            }
        }
    }

    // Wait for threads to finish
    let _ = stdout_handle.join();
    let _ = stderr_handle.join();

    // Check subprocess exit status
    match subprocess.wait() {
        Ok(status) => {
            if !status.success() {
                return Err(Error::InternalError(format!(
                    "journalctl process exited with status: {}",
                    status
                )));
            }
        }
        Err(e) => {
            return Err(Error::InternalError(format!(
                "failed to wait for journalctl process: {}",
                e
            )));
        }
    }

    Ok(())
}

pub fn process_stdin(config: Config) -> Result<()> {
    // bind to socket
    let sender = create_sender_udp(config.sender_port)?;

    // obtain target address (first resolve may fail)
    let (mut target_addr, mut target_addr_updated_at) = get_target_addr(&config.graylog_addr)?;

    debug!("start reading from stdin");

    let stdin_stream = io::stdin();
    for raw in stdin_stream.lock().lines() {
        // renew outdated target address
        if target_addr_updated_at
            .elapsed()
            .unwrap_or_default()
            .as_secs()
            > config.graylog_addr_ttl
        {
            match get_target_addr(&config.graylog_addr) {
                Ok((addr, updated_at)) => {
                    target_addr = addr;
                    target_addr_updated_at = updated_at;
                    debug!("target address updated");
                }

                // use outdated address
                Err(e) => warn!("cannot resolve graylog address: {}", e),
            }
        }

        match raw {
            Ok(log_line) => {
                process_log_record(&log_line.trim(), &config, &sender, &target_addr);
            }

            Err(err) => return Err(Error::from(err)),
        }
    }

    Ok(())
}

fn process_log_record(data: &str, config: &Config, sender: &UdpSocket, target: &SocketAddr) {
    match transform_record(data, config) {
        Ok(compressed_gelf) => {
            match ChunkedMessage::new(ChunkSize::WAN, compressed_gelf.clone()) {
                Some(chunked) => {
                    let mut chunks_sent = 0;
                    let mut send_errors = 0;
                    for chunk in chunked.iter() {
                        match sender.send_to(&chunk, &target) {
                            Ok(_) => chunks_sent += 1,
                            Err(e) => {
                                error!("UDP send failure for chunk {}: {}", chunks_sent, e);
                                send_errors += 1;
                            }
                        }
                    }
                    if send_errors > 0 {
                        error!("Message partially sent: {}/{} chunks failed", send_errors, chunks_sent + send_errors);
                    }
                }
                None => {
                    error!("CRITICAL: Message dropped - chunking failed. Size: {} bytes, Max chunks: 128", compressed_gelf.len());
                }
            }
        }

        // Log all message drops at ERROR level for visibility
        Err(Error::InsufficientLogLevel) => {
            error!("Message dropped: Insufficient log level");
        }

        Err(Error::NoMessage) => {
            error!("Message dropped: Missing MESSAGE field in JSON: {}", data);
        }

        Err(e) => {
            error!("Message dropped: Parsing error: {}, message: {}", e, data);
        }
    }
}

/// Try to decode original JSON, transform fields to GELF format, serialize and compress it.
fn transform_record(data: &str, config: &Config) -> Result<Vec<u8>> {
    // decode
    let decoded: LogRecord = serde_json::from_str(data)?;

    // absolutely mandatory field
    let short_msg = decoded
        .get("MESSAGE")
        .ok_or(Error::NoMessage)?
        .to_owned()
        .to_string();

    let host = decoded
        .get("_HOSTNAME")
        .map_or("undefined".to_string(), |h| h.to_string());

    // filter by message level
    if config.log_level_message.is_some() {
        if let Some(msg_level) = get_msg_log_level(&short_msg) {
            if msg_level > config.log_level_message.unwrap() {
                return Err(Error::InsufficientLogLevel);
            }
        }
    }

    // create GELF-message
    let mut msg = Message::new(&host, short_msg);

    // filter by system log-level
    if let Some(log_level) = decoded
        .get("PRIORITY")
        .and_then(|raw_level| raw_level.as_str())
        .and_then(|value| value.parse::<u8>().ok())
        .map(LevelSystem::from)
    {
        if log_level > config.log_level_system {
            return Err(Error::InsufficientLogLevel);
        }

        msg.set_level(log_level);
    }

    // timestamp
    if let Some(ts) = decoded.get("__REALTIME_TIMESTAMP") {
        // convert from systemd's format of microseconds expressed as
        // an integer to graylog's float format, eg: "seconds.microseconds"
        ts.as_str()
            .and_then(|s| s.parse::<f64>().ok())
            .map(|t| msg.set_timestamp(t / 1_000_000_f64));
    }

    // additional fields
    for (k, v) in decoded.into_iter() {
        if is_metadata(&k) {
            msg.set_metadata(k, v);
        }
    }

    config.compression.compress(&WireMessage::new(
        msg,
        OptFieldsIterator::new(&config.optional),
    ))
}

fn is_metadata(field: &str) -> bool {
    !IGNORED_FIELDS.contains(&field)
}

fn is_platform_supported() -> bool {
    cfg!(target_os = "linux")
}

fn get_msg_log_level(msg: &str) -> Option<LevelMsg> {
    lazy_static! {
        // try to find pattern in message: 'level=some_log_level'
        static ref RE: Regex = Regex::new(r#"level=([a-zA-Z]+ )"#).unwrap();
    }

    // first group match
    let level = RE.captures(msg)?.get(1)?.as_str().trim();
    Some(LevelMsg::from(level))
}

/// Just bind a socket to any interface.
fn create_sender_udp(port: u16) -> Result<UdpSocket> {
    Ok(UdpSocket::bind(format!("0.0.0.0:{}", port))?)
}

/// Try to resolve and return first IP-address for given host.
fn get_target_addr(host: &str) -> io::Result<(SocketAddr, SystemTime)> {
    let mut addrs = host.to_socket_addrs()?;

    // UDP sendto always takes first resolved address
    let target_addr = addrs
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "empty address list"))?;
    let target_addr_updated_at = SystemTime::now();

    Ok((target_addr, target_addr_updated_at))
}
