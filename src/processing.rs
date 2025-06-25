use std::collections::HashMap;
use std::fs;
use std::io::{self, BufRead};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use std::process;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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

    // bind to socket
    let sender = create_sender_udp(config.sender_port)?;

    // obtain target address (first resolve may fail)
    let (mut target_addr, mut target_addr_updated_at) = get_target_addr(&config.graylog_addr)?;

    // Load cursor/timestamp from file to resume from last position
    let cursor_file = get_cursor_file_path(&config);
    let mut last_timestamp = load_last_timestamp(&cursor_file);
    
    if last_timestamp.is_none() {
        // First run - start from current time to avoid historical messages
        last_timestamp = Some(get_current_timestamp());
        info!("First run, starting from current time");
    } else {
        info!("Resuming from timestamp: {}", last_timestamp.unwrap());
    }

    info!("Starting polling-based journalctl monitoring");

    // Message counting for diagnostics
    let mut total_messages_processed = 0u64;
    let mut poll_count = 0u64;

    // Main polling loop
    loop {
        poll_count += 1;
        let current_timestamp = get_current_timestamp();
        
        // Query for messages since last timestamp
        let messages = query_journalctl_range(&config, last_timestamp.unwrap(), current_timestamp)?;
        
        if !messages.is_empty() {
            info!("Poll #{}: Found {} new messages", poll_count, messages.len());
            
            for msg in messages {
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
                        Err(e) => warn!("cannot resolve graylog address: {}", e),
                    }
                }

                process_log_record(&msg, &config, &sender, &target_addr);
                total_messages_processed += 1;
                
                // Log progress every 1000 messages (check after each message)
                if total_messages_processed % 1000 == 0 {
                    info!("Total processed: {} messages across {} polls", 
                          total_messages_processed, poll_count);
                }
            }
            
            // Update last timestamp to current time and save it
            last_timestamp = Some(current_timestamp);
            if let Err(e) = save_last_timestamp(&cursor_file, current_timestamp) {
                warn!("Failed to save timestamp: {}", e);
            }
        } else {
            debug!("Poll #{}: No new messages", poll_count);
        }
        
        // Sleep for configurable interval before next poll (default 1 second)
        let poll_interval = std::env::var("JCTL2GRAY_POLL_INTERVAL")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(1);
        thread::sleep(Duration::from_secs(poll_interval));
    }
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

/// Generate cursor file path based on journal directory
fn get_cursor_file_path(config: &Config) -> String {
    if config.journal_dir.is_empty() {
        "/tmp/jctl2gray_cursor".to_string()
    } else {
        format!("/tmp/jctl2gray_cursor_{}", 
                config.journal_dir.replace('/', "_").replace("-", "_"))
    }
}

/// Get current timestamp in seconds since epoch
fn get_current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Format timestamp for journalctl --since/--until
fn format_timestamp(timestamp: u64) -> String {
    // journalctl accepts "@timestamp" format for epoch seconds
    format!("@{}", timestamp)
}

/// Load last timestamp from file
fn load_last_timestamp(cursor_file: &str) -> Option<u64> {
    match fs::read_to_string(cursor_file) {
        Ok(content) => {
            content.trim().parse::<u64>().ok()
        }
        Err(_) => None,
    }
}

/// Save last timestamp to file
fn save_last_timestamp(cursor_file: &str, timestamp: u64) -> Result<()> {
    fs::write(cursor_file, timestamp.to_string())
        .map_err(|e| Error::InternalError(format!("Failed to write timestamp file: {}", e)))
}

/// Query journalctl for messages in a specific time range
fn query_journalctl_range(config: &Config, since: u64, until: u64) -> Result<Vec<String>> {
    let mut process_args = Vec::new();
    let slice = &["-o", "json", "--merge"];
    process_args.extend_from_slice(slice);

    if config.journal_dir.len() > 0 {
        process_args.push("--directory");
        process_args.push(&config.journal_dir);
    }

    // Add time range
    let since_str = format_timestamp(since);
    let until_str = format_timestamp(until);
    process_args.push("--since");
    process_args.push(&since_str);
    process_args.push("--until");  
    process_args.push(&until_str);

    debug!("Querying journalctl: {:?}", process_args);

    let output = process::Command::new("journalctl")
        .args(&process_args)
        .output()
        .map_err(|e| Error::InternalError(format!("Failed to execute journalctl: {}", e)))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::InternalError(format!(
            "journalctl query failed: {}", stderr
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let messages: Vec<String> = stdout
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| line.to_string())
        .collect();

    Ok(messages)
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
