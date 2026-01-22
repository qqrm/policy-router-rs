use std::net::SocketAddr;

use anyhow::{Context, Result};
use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo, get_sockets_info};
use windows::{
    Win32::{
        Foundation::{CloseHandle, ERROR_ACCESS_DENIED, ERROR_INSUFFICIENT_BUFFER, HANDLE},
        System::Threading::{
            OpenProcess, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
            QueryFullProcessImageNameW,
        },
    },
    core::{Error as WindowsError, HRESULT, PWSTR},
};

use super::{ProcessInfo, ProcessLookup};

const UNKNOWN_EXE: &str = "<unknown>";

pub struct WindowsProcessLookup;

impl WindowsProcessLookup {
    pub fn new() -> Self {
        Self
    }
}

impl ProcessLookup for WindowsProcessLookup {
    fn lookup_client_process(&self, client_addr: SocketAddr) -> Result<Option<ProcessInfo>> {
        let Some(pid) = lookup_pid_by_local_endpoint(client_addr)? else {
            return Ok(None);
        };

        if pid == 0 {
            return Ok(None);
        }

        Ok(query_process_image_path(pid)?.map(|exe| ProcessInfo { pid, exe }))
    }
}

fn lookup_pid_by_local_endpoint(client: SocketAddr) -> Result<Option<u32>> {
    let sockets = get_sockets_info(
        AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6,
        ProtocolFlags::TCP,
    )
    .context("get_sockets_info failed")?;

    for socket in sockets {
        let ProtocolSocketInfo::Tcp(tcp) = socket.protocol_socket_info else {
            continue;
        };
        if tcp.local_addr == client.ip() && tcp.local_port == client.port() {
            return Ok(socket.associated_pids.into_iter().next());
        }
    }

    Ok(None)
}

fn query_process_image_path(pid: u32) -> Result<Option<String>> {
    let process = match unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) } {
        Ok(handle) => Handle::new(handle),
        Err(err) => {
            if is_access_denied(&err) {
                return Ok(Some(UNKNOWN_EXE.to_string()));
            }
            return Err(anyhow::Error::new(err))
                .with_context(|| format!("OpenProcess failed for pid {pid}"));
        }
    };

    let mut buffer = vec![0u16; 260];
    loop {
        let mut size = buffer.len() as u32;
        let result = unsafe {
            QueryFullProcessImageNameW(
                process.handle(),
                PROCESS_NAME_FORMAT(0),
                PWSTR(buffer.as_mut_ptr()),
                &mut size,
            )
        };

        match result {
            Ok(()) => {
                let exe = String::from_utf16_lossy(&buffer[..size as usize]);
                return Ok(Some(exe));
            }
            Err(err) => {
                if is_access_denied(&err) {
                    return Ok(Some(UNKNOWN_EXE.to_string()));
                }
                if err.code() == HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0) {
                    buffer.resize(buffer.len().saturating_mul(2), 0);
                    continue;
                }
                return Err(anyhow::Error::new(err))
                    .with_context(|| format!("QueryFullProcessImageNameW failed for pid {pid}"));
            }
        }
    }
}

fn is_access_denied(err: &WindowsError) -> bool {
    err.code() == HRESULT::from_win32(ERROR_ACCESS_DENIED.0)
}

struct Handle {
    handle: HANDLE,
}

impl Handle {
    fn new(handle: HANDLE) -> Self {
        Self { handle }
    }

    fn handle(&self) -> HANDLE {
        self.handle
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe {
            CloseHandle(self.handle);
        }
    }
}
