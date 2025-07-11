#[macro_use]
extern crate log;

extern crate clap;
extern crate jctl2gray;
extern crate loggerv;

use std::net::ToSocketAddrs;
use std::process;

use clap::{App, Arg};
use jctl2gray::config::{parse_log_source, Config, LogSource};
use jctl2gray::processing;
use jctl2gray::{LevelMsg, LevelSystem, MessageCompression};

fn parse_options() -> Config {
    let args = App::new("jctl2gray")
        .version("0.2")
        .author("Anton Dort-Golts <dortgolts@gmail.com>")
        .about("Reading logs from stdin/journalctl and sending it to Graylog")
        .arg(
            Arg::with_name("log_source")
                .short("s")
                .long("source")
                .value_name("log source")
                .help("Log source")
                .takes_value(true)
                .possible_values(&["stdin", "journal"])
                .required(true),
        )
        .arg(
            Arg::with_name("journal_dir")
                .short("d")
                .long("journal_dir")
                .value_name("journal dir")
                .help("Directory to read journal files from (useful for remote)")
                .takes_value(true)
                .required(false)
                .default_value(""),
        )
        .arg(
            Arg::with_name("port")
                .short("p")
                .long("port")
                .value_name("UDP-port")
                .help("Local UDP-port to send from")
                .takes_value(true)
                .validator(validate_port)
                .default_value("5000"),
        )
        .arg(
            Arg::with_name("target")
                .short("t")
                .long("target")
                .value_name("address")
                .help("Full address of target Graylog")
                .takes_value(true)
                .validator(validate_address)
                .default_value("127.0.0.1:9000"),
        )
        .arg(
            Arg::with_name("ttl")
                .long("ttl")
                .value_name("TTL")
                .help("Period of resolving target's IP-address, secs")
                .takes_value(true)
                .validator(validate_ttl)
                .default_value("60"),
        )
        .arg(
            Arg::with_name("compression")
                .short("c")
                .long("comp")
                .value_name("algorithm")
                .help("Message compression type")
                .takes_value(true)
                .possible_values(&["none", "gzip", "zlib"])
                .default_value("none"),
        )
        .arg(
            Arg::with_name("opt_fields")
                .long("opt")
                .value_name("name=text")
                .help("Optional fields to be attached to the message")
                .long_help("Optional fields could be attached to every message sent to Graylog. Fields must be defined as comma delimited pairs in format <field_name=text>, e.g.: `--opt team=t1,service=backend`")
                .takes_value(true)
                .use_delimiter(true)
        )
        .arg(
            Arg::with_name("system_level")
                .short("l")
                .long("sys")
                .value_name("level")
                .help("System logging level threshold")
                .takes_value(true)
                .possible_values(&[
                    "emergency",
                    "alert",
                    "critical",
                    "error",
                    "warning",
                    "notice",
                    "info",
                    "debug",
                ])
                .default_value("info"),
        )
        .arg(
            Arg::with_name("msg_level")
                .short("m")
                .long("msg")
                .value_name("level")
                .help("Message filter logging level threshold")
                .takes_value(true)
                .possible_values(&["fatal", "panic", "error", "warning", "info", "debug"]),
        )
        .get_matches();

    let log_source = parse_log_source(args.value_of("log_source").unwrap()).unwrap();
    let journal_dir = args.value_of("journal_dir").unwrap().to_string();
    let sender_port: u16 = args.value_of("port").unwrap().parse().unwrap();
    let graylog_addr = args.value_of("target").unwrap().to_string();
    let graylog_addr_ttl: u64 = args.value_of("ttl").unwrap().parse().unwrap();
    let compression = MessageCompression::from(args.value_of("compression").unwrap());
    let log_level_system = LevelSystem::from(args.value_of("system_level").unwrap());
    let log_level_message = args.value_of("msg_level").map(|l| LevelMsg::from(l));
    let optional: Vec<(String, String)> = match args.values_of("opt_fields") {
        Some(fields) => parse_opt_fields(fields),
        None => Vec::new(),
    };

    print_opt_fields(&optional);

    Config {
        log_source,
        journal_dir,
        sender_port,
        graylog_addr,
        graylog_addr_ttl,
        compression,
        log_level_system,
        log_level_message,
        optional,
    }
}

fn main() {
    // init logger
    loggerv::Logger::new()
        .max_level(log_level())
        .level(true)
        .separator(" | ")
        .colors(true)
        .no_module_path()
        .init()
        .unwrap();

    // get config from CLI options
    let config = parse_options();

    // choose source and start processing input
    match config.log_source {
        LogSource::Stdin => {
            if let Err(e) = processing::process_stdin(config) {
                error!("stdin processing stopped: {}", e);
            }
        }

        LogSource::Journalctl => {
            if let Err(e) = processing::process_journalctl(config) {
                error!("journalctl processing stopped: {}", e);
            }
        }
    }

    // normally unreachable
    process::exit(1);
}

/// Set different logging levels for debug/release builds
fn log_level() -> log::Level {
    #[cfg(debug_assertions)]
    return log::Level::Debug;
    #[cfg(not(debug_assertions))]
    log::Level::Info
}

/* CLI arg validators */

fn validate_address(addr: String) -> Result<(), String> {
    match addr.to_socket_addrs() {
        Ok(_) => Ok(()),
        Err(_) => Err(String::from("Bad address provided")),
    }
}

fn validate_port(port: String) -> Result<(), String> {
    match port.parse::<u16>() {
        Ok(_) => Ok(()),
        Err(_) => Err(String::from("Bad port provided")),
    }
}

fn validate_ttl(interval: String) -> Result<(), String> {
    match interval.parse::<u64>() {
        Ok(i) => {
            if i > 0 {
                Ok(())
            } else {
                Err(String::from("TTL could not be zero"))
            }
        }
        Err(_) => Err(String::from("Bad TTL value provided")),
    }
}

/* Optional fields */

fn parse_opt_fields<'a, A: Iterator<Item = &'a str>>(data: A) -> Vec<(String, String)> {
    data.map(|field| field.split('='))
        .map(|mut i| {
            let name = i.next();
            let value = i.next();
            match (name, value) {
                (Some(n), Some(v)) => Some((n, v)),
                _ => None,
            }
        })
        .filter(|v| v.is_some())
        .map(|v| v.unwrap())
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
}

fn print_opt_fields(opt: &[(String, String)]) {
    debug!("additional fields to be attached:");
    opt.iter().for_each(|(n, v)| debug!("- {}: {}", n, v));
}
