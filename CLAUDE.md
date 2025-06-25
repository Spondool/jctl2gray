# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

jctl2gray is a Rust-based tool that converts journalctl logs into Graylog Extended Log Format (GELF) and sends them to remote Graylog instances. It serves as a modern replacement for journal2gelf, designed to work with newer systemd versions (>= 190) that support single-line JSON format output.

## Development Commands

### Building and Installation
- `cargo build` - Build the project
- `cargo build --release` - Build optimized release version
- `cargo install --path .` - Install the binary locally
- `cargo run -- --help` - Run with help to see available options

### Testing and Validation
- `cargo test` - Run unit tests
- `cargo check` - Quick syntax and type checking
- `cargo clippy` - Run linter for code quality checks
- `cargo fmt` - Format code according to Rust standards

### Running the Application
- `cargo run -- -s stdin -t <graylog_host:port>` - Read from stdin
- `cargo run -- -s journal -t <graylog_host:port>` - Read from journalctl directly
- `journalctl -o json -f | cargo run -- -s stdin -t <graylog_host:port>` - Pipe journalctl output

## Architecture

### Core Components

**Main Binary** (`src/bin/jctl2gray.rs`)
- Command-line argument parsing using clap
- Configuration setup and validation
- Entry point that delegates to processing module

**Processing Engine** (`src/processing.rs`)
- Core logic for reading from two sources: stdin or journalctl subprocess
- Message filtering by system priority and internal log levels
- GELF message construction and UDP transmission
- Platform detection (currently Linux-only)

**Configuration** (`src/config.rs`)
- Defines LogSource enum (Stdin, Journalctl)
- Config struct containing all runtime parameters
- Command-line argument parsing utilities

**GELF Module** (`src/gelf/`)
- `mod.rs` - Main GELF message structure and builder
- `wire_message.rs` - UDP wire format serialization
- `chunked_message.rs` - Large message chunking for UDP limits
- `compression.rs` - Message compression (gzip/zlib)
- `level.rs` - Log level mappings (system priority and message levels)

### Key Design Patterns

**Dual Input Sources**: The application supports reading either from stdin (for piped journalctl output) or directly spawning journalctl as a subprocess.

**Message Filtering**: Two-tier filtering system - systemd priority levels and application-level log patterns within message content.

**UDP Chunking**: Large GELF messages are automatically chunked to fit UDP packet size limits, with proper reassembly headers.

**Field Mapping**: Converts journalctl JSON fields to GELF format, filtering out system-specific fields while preserving relevant metadata.

## Configuration Options

- `--source/-s` - Log source: "stdin" or "journal" (required)
- `--target/-t` - Graylog server address (required)
- `--port/-p` - Local UDP port (default: 5000)
- `--journal_dir/-d` - Custom journal directory path
- `--compression/-c` - Message compression type
- `--sys` - System log level threshold
- `--msg` - Message log level filtering
- `--opt` - Additional GELF fields (format: field=value,field=value)

## Dependencies

The project uses standard Rust ecosystem crates:
- `clap` for CLI parsing
- `serde`/`serde_json` for JSON handling
- `libflate` for compression
- `regex` for log level pattern matching
- `log`/`loggerv` for internal logging