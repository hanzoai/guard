//! Guard Proxy - LLM API middleware for I/O sanitization
//!
//! Usage:
//!   guard-proxy --upstream https://api.openai.com --port 8080
//!   guard-proxy --upstream https://api.anthropic.com --port 8080
//!
//! Then point your LLM client to http://localhost:8080 instead of the upstream API.

use hanzo_guard::{Guard, GuardConfig, SanitizeResult};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

struct ProxyState {
    guard: Guard,
    upstream: String,
    client: reqwest::Client,
}

async fn handle_request(
    req: Request<hyper::body::Incoming>,
    state: Arc<ProxyState>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let method = req.method().clone();
    let uri = req.uri().clone();
    let headers = req.headers().clone();

    // Collect request body
    let body_bytes = req.collect().await?.to_bytes();
    let body_str = String::from_utf8_lossy(&body_bytes);

    // Sanitize request body (input to LLM)
    let sanitized_input = if !body_str.is_empty() {
        match sanitize_llm_request(&state.guard, &body_str).await {
            Ok(sanitized) => sanitized,
            Err(e) => {
                return Ok(error_response(
                    StatusCode::BAD_REQUEST,
                    &format!("Input blocked: {e}"),
                ));
            }
        }
    } else {
        body_str.to_string()
    };

    // Build upstream URL
    let upstream_url = format!("{}{}", state.upstream, uri.path_and_query().map(|p| p.as_str()).unwrap_or("/"));

    // Forward to upstream
    let mut upstream_req = state.client.request(method, &upstream_url);

    // Copy headers (except Host which reqwest sets)
    for (name, value) in headers.iter() {
        if name != "host" {
            upstream_req = upstream_req.header(name, value);
        }
    }

    // Send request
    let upstream_resp = match upstream_req.body(sanitized_input).send().await {
        Ok(resp) => resp,
        Err(e) => {
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                &format!("Upstream error: {e}"),
            ));
        }
    };

    let status = upstream_resp.status();
    let resp_headers = upstream_resp.headers().clone();
    let resp_body = match upstream_resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            return Ok(error_response(
                StatusCode::BAD_GATEWAY,
                &format!("Response read error: {e}"),
            ));
        }
    };

    // Sanitize response body (output from LLM)
    let resp_str = String::from_utf8_lossy(&resp_body);
    let sanitized_output = if !resp_str.is_empty() {
        match sanitize_llm_response(&state.guard, &resp_str).await {
            Ok(sanitized) => sanitized,
            Err(e) => {
                return Ok(error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    &format!("Output blocked: {e}"),
                ));
            }
        }
    } else {
        resp_str.to_string()
    };

    // Build response
    let mut response = Response::builder().status(status);
    for (name, value) in resp_headers.iter() {
        if name != "content-length" && name != "transfer-encoding" {
            response = response.header(name, value);
        }
    }

    Ok(response
        .body(Full::new(Bytes::from(sanitized_output)))
        .unwrap())
}

/// Sanitize LLM request body (user input)
async fn sanitize_llm_request(guard: &Guard, body: &str) -> Result<String, String> {
    // Try to parse as JSON and sanitize message content
    if let Ok(mut json) = serde_json::from_str::<Value>(body) {
        sanitize_json_messages(guard, &mut json, true).await?;
        return Ok(serde_json::to_string(&json).unwrap_or_else(|_| body.to_string()));
    }

    // Plain text - sanitize directly
    match guard.sanitize_input(body).await {
        Ok(SanitizeResult::Clean(text)) => Ok(text),
        Ok(SanitizeResult::Redacted { text, .. }) => Ok(text),
        Ok(SanitizeResult::Blocked { reason, .. }) => Err(reason),
        Err(e) => Err(e.to_string()),
    }
}

/// Sanitize LLM response body (model output)
async fn sanitize_llm_response(guard: &Guard, body: &str) -> Result<String, String> {
    // Try to parse as JSON and sanitize message content
    if let Ok(mut json) = serde_json::from_str::<Value>(body) {
        sanitize_json_messages(guard, &mut json, false).await?;
        return Ok(serde_json::to_string(&json).unwrap_or_else(|_| body.to_string()));
    }

    // Plain text - sanitize directly
    match guard.sanitize_output(body).await {
        Ok(SanitizeResult::Clean(text)) => Ok(text),
        Ok(SanitizeResult::Redacted { text, .. }) => Ok(text),
        Ok(SanitizeResult::Blocked { reason, .. }) => Err(reason),
        Err(e) => Err(e.to_string()),
    }
}

/// Recursively sanitize message content in JSON (OpenAI/Anthropic format)
async fn sanitize_json_messages(guard: &Guard, json: &mut Value, is_input: bool) -> Result<(), String> {
    match json {
        Value::Object(map) => {
            // OpenAI format: messages[].content
            // Anthropic format: messages[].content, content[].text
            if let Some(content) = map.get_mut("content") {
                if let Value::String(text) = content {
                    let sanitized = if is_input {
                        guard.sanitize_input(text).await
                    } else {
                        guard.sanitize_output(text).await
                    };
                    match sanitized {
                        Ok(SanitizeResult::Clean(t)) => *text = t,
                        Ok(SanitizeResult::Redacted { text: t, .. }) => *text = t,
                        Ok(SanitizeResult::Blocked { reason, .. }) => return Err(reason),
                        Err(e) => return Err(e.to_string()),
                    }
                } else if let Value::Array(arr) = content {
                    for item in arr {
                        Box::pin(sanitize_json_messages(guard, item, is_input)).await?;
                    }
                }
            }

            // Anthropic content block: text field
            if let Some(Value::String(text)) = map.get_mut("text") {
                let sanitized = if is_input {
                    guard.sanitize_input(text).await
                } else {
                    guard.sanitize_output(text).await
                };
                match sanitized {
                    Ok(SanitizeResult::Clean(t)) => *text = t,
                    Ok(SanitizeResult::Redacted { text: t, .. }) => *text = t,
                    Ok(SanitizeResult::Blocked { reason, .. }) => return Err(reason),
                    Err(e) => return Err(e.to_string()),
                }
            }

            // Recurse into other fields
            if let Some(messages) = map.get_mut("messages") {
                Box::pin(sanitize_json_messages(guard, messages, is_input)).await?;
            }
            if let Some(choices) = map.get_mut("choices") {
                Box::pin(sanitize_json_messages(guard, choices, is_input)).await?;
            }
            if let Some(message) = map.get_mut("message") {
                Box::pin(sanitize_json_messages(guard, message, is_input)).await?;
            }
            if let Some(delta) = map.get_mut("delta") {
                Box::pin(sanitize_json_messages(guard, delta, is_input)).await?;
            }
        }
        Value::Array(arr) => {
            for item in arr {
                Box::pin(sanitize_json_messages(guard, item, is_input)).await?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn error_response(status: StatusCode, message: &str) -> Response<Full<Bytes>> {
    let body = json!({
        "error": {
            "message": message,
            "type": "guard_error"
        }
    });
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Parse args
    let mut upstream = String::from("https://api.openai.com");
    let mut port: u16 = 8080;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--upstream" | "-u" => {
                if i + 1 < args.len() {
                    upstream = args[i + 1].clone();
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--port" | "-p" => {
                if i + 1 < args.len() {
                    port = args[i + 1].parse().unwrap_or(8080);
                    i += 2;
                } else {
                    i += 1;
                }
            }
            "--help" | "-h" => {
                println!("guard-proxy - LLM API sanitization proxy");
                println!();
                println!("USAGE:");
                println!("    guard-proxy [OPTIONS]");
                println!();
                println!("OPTIONS:");
                println!("    -u, --upstream <URL>   Upstream API URL (default: https://api.openai.com)");
                println!("    -p, --port <PORT>      Listen port (default: 8080)");
                println!("    -h, --help             Print help");
                println!();
                println!("EXAMPLES:");
                println!("    guard-proxy --upstream https://api.openai.com --port 8080");
                println!("    guard-proxy --upstream https://api.anthropic.com --port 8081");
                println!();
                println!("Then set OPENAI_BASE_URL=http://localhost:8080 in your client.");
                return;
            }
            _ => i += 1,
        }
    }

    let state = Arc::new(ProxyState {
        guard: Guard::new(GuardConfig::default()),
        upstream,
        client: reqwest::Client::new(),
    });

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await.unwrap();

    eprintln!("Guard proxy listening on http://{addr}");
    eprintln!("Forwarding to: {}", state.upstream);
    eprintln!();
    eprintln!("Set OPENAI_BASE_URL=http://localhost:{port} or");
    eprintln!("    ANTHROPIC_BASE_URL=http://localhost:{port}");

    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let io = TokioIo::new(stream);
        let state = state.clone();

        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let state = state.clone();
                async move { handle_request(req, state).await }
            });

            if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                eprintln!("Connection error: {e}");
            }
        });
    }
}
