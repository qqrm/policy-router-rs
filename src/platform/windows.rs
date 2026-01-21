use anyhow::Result;

use super::{ProcessInfo, ProcessLookup};

pub struct WindowsProcessLookup;

impl WindowsProcessLookup {
    pub fn new() -> Self {
        Self
    }
}

impl ProcessLookup for WindowsProcessLookup {
    fn lookup_client_process(
        &self,
        _client_addr: std::net::SocketAddr,
    ) -> Result<Option<ProcessInfo>> {
        // TODO: implement TCP table lookup and map to PID/exe
        Ok(None)
    }
}
