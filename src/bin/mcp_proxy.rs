//! Guard MCP Proxy - MCP server wrapper with I/O sanitization
//!
//! Usage:
//!   guard-mcp -- npx @hanzo/mcp serve
//!   guard-mcp -- python -m mcp_server
//!
//! Wraps any MCP server and filters tool inputs/outputs through guard.

use hanzo_guard::{Guard, GuardConfig, SanitizeResult};
use serde_json::Value;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::Arc;

/// Filter JSON-RPC message content through guard
async fn filter_jsonrpc(guard: &Guard, line: &str, is_input: bool) -> String {
    // Parse JSON-RPC
    let Ok(mut msg) = serde_json::from_str::<Value>(line) else {
        return line.to_string();
    };

    // Filter based on method
    if let Some(method) = msg.get("method").and_then(|m| m.as_str()) {
        match method {
            // Tool calls - filter arguments
            "tools/call" => {
                if let Some(params) = msg.get_mut("params") {
                    if let Some(args) = params.get_mut("arguments") {
                        filter_value(guard, args, is_input).await;
                    }
                }
            }
            // Completions - filter prompt content
            "completion/complete" => {
                if let Some(params) = msg.get_mut("params") {
                    if let Some(prompt) = params.get_mut("prompt") {
                        filter_value(guard, prompt, is_input).await;
                    }
                }
            }
            // Sampling - filter messages
            "sampling/createMessage" => {
                if let Some(params) = msg.get_mut("params") {
                    if let Some(messages) = params.get_mut("messages") {
                        filter_value(guard, messages, is_input).await;
                    }
                }
            }
            _ => {}
        }
    }

    // Filter results
    if let Some(result) = msg.get_mut("result") {
        filter_value(guard, result, is_input).await;
    }

    serde_json::to_string(&msg).unwrap_or_else(|_| line.to_string())
}

/// Recursively filter string values in JSON
async fn filter_value(guard: &Guard, value: &mut Value, is_input: bool) {
    match value {
        Value::String(s) => {
            let result = if is_input {
                guard.sanitize_input(s).await
            } else {
                guard.sanitize_output(s).await
            };
            match result {
                Ok(SanitizeResult::Clean(t)) => *s = t,
                Ok(SanitizeResult::Redacted { text: t, .. }) => *s = t,
                Ok(SanitizeResult::Blocked { .. }) => *s = "[BLOCKED]".to_string(),
                Err(_) => {} // Keep original on error
            }
        }
        Value::Array(arr) => {
            for item in arr {
                Box::pin(filter_value(guard, item, is_input)).await;
            }
        }
        Value::Object(map) => {
            // Special handling for content/text fields
            for (key, val) in map.iter_mut() {
                if key == "content" || key == "text" || key == "value" {
                    Box::pin(filter_value(guard, val, is_input)).await;
                }
            }
            // Also filter nested objects
            for val in map.values_mut() {
                if val.is_object() || val.is_array() {
                    Box::pin(filter_value(guard, val, is_input)).await;
                }
            }
        }
        _ => {}
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 || args.iter().any(|a| a == "--help" || a == "-h") {
        println!("guard-mcp - MCP server wrapper with I/O sanitization");
        println!();
        println!("USAGE:");
        println!("    guard-mcp [OPTIONS] -- <COMMAND> [ARGS...]");
        println!();
        println!("OPTIONS:");
        println!("    -v, --verbose    Show filtered messages");
        println!("    -h, --help       Print help");
        println!();
        println!("EXAMPLES:");
        println!("    guard-mcp -- npx @hanzo/mcp serve");
        println!("    guard-mcp -- python -m mcp_server");
        println!("    guard-mcp -v -- node mcp-server.js");
        println!();
        println!("The proxy reads JSON-RPC from stdin, filters it, forwards to the");
        println!("wrapped server, then filters and outputs the response.");
        return;
    }

    // Parse options
    let verbose = args.iter().any(|a| a == "--verbose" || a == "-v");

    // Find command after --
    let cmd_start = args.iter().position(|a| a == "--").map(|i| i + 1);
    let Some(cmd_start) = cmd_start else {
        eprintln!("Usage: guard-mcp -- <COMMAND> [ARGS...]");
        std::process::exit(1);
    };

    if cmd_start >= args.len() {
        eprintln!("No command specified after --");
        std::process::exit(1);
    }

    let command = &args[cmd_start];
    let cmd_args = &args[cmd_start + 1..];

    // Create async runtime
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Initialize guard
    let guard = Arc::new(Guard::new(GuardConfig::default()));

    // Spawn the wrapped MCP server
    let mut child = Command::new(command)
        .args(cmd_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("Failed to spawn MCP server");

    let mut child_stdin = child.stdin.take().expect("Failed to get child stdin");
    let child_stdout = child.stdout.take().expect("Failed to get child stdout");

    // Read from our stdin, filter, write to child stdin
    let guard_in = guard.clone();
    let stdin_handle = std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let reader = BufReader::new(stdin.lock());

        for line in reader.lines().map_while(Result::ok) {
            // Filter input (to MCP server)
            let filtered = rt.block_on(filter_jsonrpc(&guard_in, &line, true));

            if verbose {
                eprintln!("[guard-mcp] IN: {filtered}");
            }

            if writeln!(child_stdin, "{filtered}").is_err() {
                break;
            }
            let _ = child_stdin.flush();
        }
    });

    // Read from child stdout, filter, write to our stdout
    let guard_out = guard.clone();
    let stdout_rt = tokio::runtime::Runtime::new().unwrap();
    let stdout_handle = std::thread::spawn(move || {
        let reader = BufReader::new(child_stdout);
        let stdout = std::io::stdout();
        let mut stdout = stdout.lock();

        for line in reader.lines().map_while(Result::ok) {
            // Filter output (from MCP server)
            let filtered = stdout_rt.block_on(filter_jsonrpc(&guard_out, &line, false));

            if verbose {
                eprintln!("[guard-mcp] OUT: {filtered}");
            }

            if writeln!(stdout, "{filtered}").is_err() {
                break;
            }
            let _ = stdout.flush();
        }
    });

    // Wait for threads
    let _ = stdin_handle.join();
    let _ = stdout_handle.join();

    // Wait for child
    let status = child.wait().expect("Failed to wait for child");
    if let Some(code) = status.code() {
        std::process::exit(code);
    }
}
