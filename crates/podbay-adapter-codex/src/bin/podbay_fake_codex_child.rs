//! Disposable fake stdio peer for process transport tests. Never invokes Codex.

use std::io::{self, BufRead, Write};
use std::time::Duration;

use serde_json::json;

fn main() -> io::Result<()> {
    let mode = std::env::args().nth(1).unwrap_or_default();
    match mode.as_str() {
        "handshake" => {
            let mut input = io::BufReader::new(io::stdin().lock());
            let mut line = String::new();
            input.read_line(&mut line)?;
            if serde_json::from_str::<serde_json::Value>(&line)?["method"] != "initialize" {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "missing initialize",
                ));
            }
            writeln!(
                io::stdout(),
                "{}",
                json!({"id":1,"result":{"codexHome":"isolated","platformFamily":"unix","platformOs":"linux","userAgent":"fake/1"}})
            )?;
            line.clear();
            input.read_line(&mut line)?;
            if serde_json::from_str::<serde_json::Value>(&line)?["method"] != "initialized" {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "missing initialized",
                ));
            }
            line.clear();
            input.read_line(&mut line)?;
            if serde_json::from_str::<serde_json::Value>(&line)?["method"] != "model/list" {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "missing model/list",
                ));
            }
            writeln!(
                io::stdout(),
                "{}",
                json!({"id":2,"result":{"data":[],"nextCursor":null}})
            )?;
            std::thread::sleep(Duration::from_secs(60));
        }
        "malformed" => {
            io::stdout().write_all(b"{not-json}\n")?;
            io::stdout().flush()?;
            std::thread::sleep(Duration::from_secs(60));
        }
        "fragmented" => {
            io::stdout().write_all(b"{\"id\":1")?;
            io::stdout().flush()?;
            std::thread::sleep(Duration::from_millis(25));
            io::stdout().write_all(b",\"result\":{\"ok\":true}}\n")?;
            io::stdout().flush()?;
            std::thread::sleep(Duration::from_secs(60));
        }
        "oversize" => {
            let chunk = vec![b'x'; 8192];
            for _ in 0..(16 * 1024 * 1024 / chunk.len() + 2) {
                io::stdout().write_all(&chunk)?;
            }
            io::stdout().flush()?;
            std::thread::sleep(Duration::from_secs(60));
        }
        "blocked" => std::thread::sleep(Duration::from_secs(60)),
        "environment" => {
            writeln!(
                io::stdout(),
                "{}",
                json!({
                    "homeSet":std::env::var_os("HOME").is_some(),
                    "codexHomeSet":std::env::var_os("CODEX_HOME").is_some(),
                    "pathSet":std::env::var_os("PATH").is_some(),
                    "openaiKeySet":std::env::var_os("OPENAI_API_KEY").is_some(),
                    "awsKeySet":std::env::var_os("AWS_SECRET_ACCESS_KEY").is_some(),
                    "lang":std::env::var("LANG").ok(),
                })
            )?;
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "unknown fake mode",
            ));
        }
    }
    Ok(())
}
