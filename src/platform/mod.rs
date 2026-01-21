use anyhow::Result;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub exe: String,
}

/// Lookup client process metadata for a given socket address.
pub trait ProcessLookup: Send + Sync + 'static {
    /// Returns the process metadata for the client address when available.
    ///
    /// # Errors
    ///
    /// Returns an error if the platform-specific lookup fails.
    fn lookup_client_process(
        &self,
        client_addr: std::net::SocketAddr,
    ) -> Result<Option<ProcessInfo>>;
}

#[must_use]
pub fn process_lookup() -> Box<dyn ProcessLookup> {
    platform_process_lookup()
}

#[cfg(all(target_os = "windows", feature = "windows"))]
fn platform_process_lookup() -> Box<dyn ProcessLookup> {
    Box::new(windows::WindowsProcessLookup::new())
}

#[cfg(not(all(target_os = "windows", feature = "windows")))]
fn platform_process_lookup() -> Box<dyn ProcessLookup> {
    Box::new(stub::StubProcessLookup)
}

#[cfg(all(target_os = "windows", feature = "windows"))]
mod windows;

#[cfg(not(all(target_os = "windows", feature = "windows")))]
mod stub;
