use anyhow::Result;

use super::{ProcessInfo, ProcessLookup};

pub struct StubProcessLookup;

impl ProcessLookup for StubProcessLookup {
    fn lookup_client_process(
        &self,
        _client_addr: std::net::SocketAddr,
    ) -> Result<Option<ProcessInfo>> {
        Ok(None)
    }
}
