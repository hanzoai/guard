//! Guard Wrap - PTY wrapper for CLI tools with I/O sanitization
//!
//! Usage:
//!   guard-wrap claude
//!   guard-wrap codex
//!   guard-wrap -- python script.py
//!
//! Wraps any CLI command and filters stdin/stdout through guard in real-time.

use hanzo_guard::{Guard, GuardConfig, SanitizeResult};
use portable_pty::{native_pty_system, CommandBuilder, PtySize};
use std::io::{Read, Write};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Filter text through guard, returning sanitized version
async fn filter_text(guard: &Guard, text: &str, is_input: bool) -> String {
    if text.trim().is_empty() {
        return text.to_string();
    }

    let result = if is_input {
        guard.sanitize_input(text).await
    } else {
        guard.sanitize_output(text).await
    };

    match result {
        Ok(SanitizeResult::Clean(t)) => t,
        Ok(SanitizeResult::Redacted { text: t, redactions }) => {
            if !redactions.is_empty() {
                eprintln!("\x1b[33m[guard] Redacted {} item(s)\x1b[0m", redactions.len());
            }
            t
        }
        Ok(SanitizeResult::Blocked { reason, .. }) => {
            eprintln!("\x1b[31m[guard] BLOCKED: {reason}\x1b[0m");
            String::new() // Don't pass blocked content
        }
        Err(e) => {
            eprintln!("\x1b[31m[guard] Error: {e}\x1b[0m");
            text.to_string() // Pass through on error
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 || args.iter().any(|a| a == "--help" || a == "-h") {
        println!("guard-wrap - PTY wrapper with I/O sanitization");
        println!();
        println!("USAGE:");
        println!("    guard-wrap <COMMAND> [ARGS...]");
        println!();
        println!("OPTIONS:");
        println!("    -h, --help    Print help");
        println!();
        println!("EXAMPLES:");
        println!("    guard-wrap claude");
        println!("    guard-wrap codex chat");
        println!("    guard-wrap -- python -i");
        println!();
        println!("All input you type will be sanitized before reaching the command.");
        println!("All output from the command will be sanitized before display.");
        return;
    }

    // Skip -- if present
    let cmd_start = if args.get(1).map(|s| s.as_str()) == Some("--") {
        2
    } else {
        1
    };

    if cmd_start >= args.len() {
        eprintln!("No command specified");
        std::process::exit(1);
    }

    let command = &args[cmd_start];
    let cmd_args = &args[cmd_start + 1..];

    // Create async runtime
    let rt = tokio::runtime::Runtime::new().unwrap();

    // Initialize guard
    let guard = Arc::new(Guard::new(GuardConfig::default()));

    // Create PTY
    let pty_system = native_pty_system();
    let pair = pty_system
        .openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .expect("Failed to open PTY");

    // Build command
    let mut cmd = CommandBuilder::new(command);
    for arg in cmd_args {
        cmd.arg(arg);
    }

    // Spawn child process
    let mut child = pair.slave.spawn_command(cmd).expect("Failed to spawn command");

    // Get PTY master for I/O
    let master = pair.master;

    // Channels for async communication
    let (stdin_tx, mut stdin_rx) = mpsc::channel::<String>(100);
    let (stdout_tx, mut stdout_rx) = mpsc::channel::<String>(100);

    // Clone guard for tasks
    let guard_in = guard.clone();
    let guard_out = guard.clone();

    // Stdin reader thread (sync -> async)
    let stdin_tx_clone = stdin_tx.clone();
    std::thread::spawn(move || {
        let stdin = std::io::stdin();
        let mut buffer = [0u8; 1024];
        loop {
            match stdin.lock().read(&mut buffer) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    let text = String::from_utf8_lossy(&buffer[..n]).to_string();
                    if stdin_tx_clone.blocking_send(text).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // PTY reader thread (sync -> async)
    let stdout_tx_clone = stdout_tx;
    let mut reader = master.try_clone_reader().expect("Failed to clone PTY reader");
    std::thread::spawn(move || {
        let mut buffer = [0u8; 4096];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => break, // EOF
                Ok(n) => {
                    let text = String::from_utf8_lossy(&buffer[..n]).to_string();
                    if stdout_tx_clone.blocking_send(text).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });

    // Get writer for PTY
    let mut writer = master.take_writer().expect("Failed to take PTY writer");

    // Main async loop
    rt.block_on(async {
        loop {
            tokio::select! {
                // Handle input from stdin -> filter -> PTY
                Some(text) = stdin_rx.recv() => {
                    let filtered = filter_text(&guard_in, &text, true).await;
                    if !filtered.is_empty() {
                        if writer.write_all(filtered.as_bytes()).is_err() {
                            break;
                        }
                        let _ = writer.flush();
                    }
                }
                // Handle output from PTY -> filter -> stdout
                Some(text) = stdout_rx.recv() => {
                    let filtered = filter_text(&guard_out, &text, false).await;
                    if !filtered.is_empty() {
                        print!("{filtered}");
                        let _ = std::io::stdout().flush();
                    }
                }
                else => break,
            }
        }
    });

    // Wait for child to exit
    let status = child.wait().expect("Failed to wait for child");
    std::process::exit(status.exit_code() as i32);
}
