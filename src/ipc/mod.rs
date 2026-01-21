use std::io::{BufRead, BufReader, Write};

use anyhow::{Context, Result};
use interprocess::local_socket::{GenericFilePath, GenericNamespaced, Name, prelude::*};
use serde::{Deserialize, Serialize};

pub const SOCKET_PRINT_NAME: &str = "policy-routerd.sock";
pub const SOCKET_FS_FALLBACK: &str = "/tmp/policy-routerd.sock";

/// Builds the IPC socket name.
///
/// # Errors
///
/// Returns an error if the platform specific socket name cannot be constructed.
pub fn socket_name() -> Result<Name<'static>> {
    let name = if GenericNamespaced::is_supported() {
        SOCKET_PRINT_NAME
            .to_ns_name::<GenericNamespaced>()
            .context("failed to build namespaced local socket name")?
    } else {
        SOCKET_FS_FALLBACK
            .to_fs_name::<GenericFilePath>()
            .context("failed to build filesystem local socket name")?
    };

    Ok(name)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Request {
    Status,
    Reload,
    Stop,
    Explain(ExplainRequest),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainRequest {
    pub process: Option<String>,
    pub domain: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Response {
    OkStatus(StatusResponse),
    OkReload,
    OkStop,
    OkExplain(ExplainResponse),
    Err(ErrorResponse),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub uptime_ms: u128,
    pub config_path: String,
    pub egress: Vec<EgressInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressInfo {
    pub id: String,
    pub kind: String,
    pub endpoint: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExplainResponse {
    pub decision: DecisionInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionInfo {
    pub egress: String,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorResponse {
    pub message: String,
}

/// Serializes `value` as JSON and writes it as a single line terminated by `\n`.
///
/// # Errors
///
/// Returns an error if JSON serialization fails or the underlying writer fails.
pub fn write_json_line<W: Write, T: Serialize>(mut w: W, value: &T) -> Result<()> {
    let mut line = serde_json::to_vec(value).context("failed to serialize JSON")?;
    line.push(b'\n');
    w.write_all(&line).context("failed to write JSON line")?;
    w.flush().ok();
    Ok(())
}

/// Reads a single `\n` terminated line and deserializes it from JSON.
///
/// # Errors
///
/// Returns an error if reading fails or the input is not valid JSON for `T`.
pub fn read_json_line<R: BufRead, T: for<'de> Deserialize<'de>>(mut r: R) -> Result<T> {
    let mut line = String::new();
    r.read_line(&mut line).context("failed to read JSON line")?;
    let value = serde_json::from_str::<T>(&line).context("failed to deserialize JSON")?;
    Ok(value)
}

/// Sends one request and waits for one response over the same stream.
///
/// # Errors
///
/// Returns an error if writing the request fails, reading fails, or JSON parsing fails.
pub fn client_roundtrip(
    stream: &mut interprocess::local_socket::Stream,
    req: &Request,
) -> Result<Response> {
    write_json_line(&mut *stream, req)?;
    let reader = BufReader::new(&*stream);
    read_json_line(reader)
}
