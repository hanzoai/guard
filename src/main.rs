//! Hanzo Guard CLI - LLM I/O sanitization tool
//!
//! Usage:
//!   echo "My SSN is 123-45-6789" | hanzo-guard
//!   hanzo-guard --file input.txt

use hanzo_guard::{Guard, GuardConfig, SanitizeResult};
use std::io::{self, BufRead, Write};

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.iter().any(|a| a == "--help" || a == "-h") {
        println!("hanzo-guard - LLM I/O sanitization tool");
        println!();
        println!("USAGE:");
        println!("    echo \"text\" | hanzo-guard");
        println!("    hanzo-guard --file <FILE>");
        println!("    hanzo-guard --text \"My SSN is 123-45-6789\"");
        println!();
        println!("OPTIONS:");
        println!("    -f, --file <FILE>    Read input from file");
        println!("    -t, --text <TEXT>    Sanitize text directly");
        println!("    -j, --json           Output as JSON");
        println!("    -h, --help           Print help");
        return;
    }

    let json_output = args.iter().any(|a| a == "--json" || a == "-j");

    // Get input
    let input = if let Some(pos) = args.iter().position(|a| a == "--text" || a == "-t") {
        args.get(pos + 1).cloned().unwrap_or_default()
    } else if let Some(pos) = args.iter().position(|a| a == "--file" || a == "-f") {
        let path = args.get(pos + 1).expect("Missing file path");
        std::fs::read_to_string(path).expect("Failed to read file")
    } else {
        // Read from stdin
        let stdin = io::stdin();
        let mut input = String::new();
        for line in stdin.lock().lines() {
            if let Ok(line) = line {
                input.push_str(&line);
                input.push('\n');
            }
        }
        input
    };

    if input.trim().is_empty() {
        eprintln!("No input provided");
        std::process::exit(1);
    }

    // Run sanitization
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let guard = Guard::new(GuardConfig::default());

        match guard.sanitize_input(&input).await {
            Ok(result) => {
                if json_output {
                    let output = match &result {
                        SanitizeResult::Clean(text) => serde_json::json!({
                            "status": "clean",
                            "text": text
                        }),
                        SanitizeResult::Redacted { text, redactions } => serde_json::json!({
                            "status": "redacted",
                            "text": text,
                            "redactions": redactions.len()
                        }),
                        SanitizeResult::Blocked { reason, .. } => serde_json::json!({
                            "status": "blocked",
                            "reason": reason
                        }),
                    };
                    println!("{}", serde_json::to_string_pretty(&output).unwrap());
                } else {
                    match result {
                        SanitizeResult::Clean(text) => print!("{}", text),
                        SanitizeResult::Redacted { text, redactions } => {
                            eprintln!("# Redacted {} items", redactions.len());
                            print!("{}", text);
                        }
                        SanitizeResult::Blocked { reason, .. } => {
                            eprintln!("BLOCKED: {}", reason);
                            std::process::exit(2);
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
    });
}
