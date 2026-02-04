use std::{
    collections::{BTreeMap, VecDeque},
    process::{Child, Command, ExitStatus},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use tracing::{info, warn};

use crate::{
    ipc::ProcessStatus,
    policy::config::{EgressId, ProcessSpec, RestartPolicy},
};

const RATE_LIMIT_ERROR: &str = "restart rate limit exceeded (cooldown)";

#[cfg(any(test, debug_assertions))]
const RATE_LIMIT_WINDOW: Duration = Duration::from_millis(200);

#[cfg(not(any(test, debug_assertions)))]
#[allow(clippy::duration_suboptimal_units)]
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);

#[cfg(windows)]
mod winjob {
    use std::{ffi::c_void, mem::MaybeUninit, os::windows::process::ChildExt, ptr};

    type BOOL = i32;
    type DWORD = u32;
    type HANDLE = *mut c_void;
    type LONG = i32;
    type SIZE_T = usize;
    type ULONGLONG = u64;

    const FALSE: BOOL = 0;
    const JOB_OBJECT_EXTENDED_LIMIT_INFORMATION: DWORD = 9;
    const JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: DWORD = 0x0000_2000;

    #[repr(C)]
    struct IO_COUNTERS {
        read_operation_count: ULONGLONG,
        write_operation_count: ULONGLONG,
        other_operation_count: ULONGLONG,
        read_transfer_count: ULONGLONG,
        write_transfer_count: ULONGLONG,
        other_transfer_count: ULONGLONG,
    }

    #[repr(C)]
    struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
        per_process_user_time_limit: i64,
        per_job_user_time_limit: i64,
        limit_flags: DWORD,
        minimum_working_set_size: SIZE_T,
        maximum_working_set_size: SIZE_T,
        active_process_limit: DWORD,
        affinity: usize,
        priority_class: DWORD,
        scheduling_class: DWORD,
    }

    #[repr(C)]
    struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
        basic_limit_information: JOBOBJECT_BASIC_LIMIT_INFORMATION,
        io_info: IO_COUNTERS,
        process_memory_limit: SIZE_T,
        job_memory_limit: SIZE_T,
        peak_process_memory_used: SIZE_T,
        peak_job_memory_used: SIZE_T,
    }

    extern "system" {
        fn CreateJobObjectW(job_attributes: *mut c_void, name: *const u16) -> HANDLE;
        fn SetInformationJobObject(
            job: HANDLE,
            job_object_info_class: DWORD,
            job_object_info: *mut c_void,
            job_object_info_length: DWORD,
        ) -> BOOL;
        fn AssignProcessToJobObject(job: HANDLE, process: HANDLE) -> BOOL;
        fn CloseHandle(handle: HANDLE) -> BOOL;
    }

    #[derive(Debug)]
    pub(super) struct JobHandle {
        handle: HANDLE,
    }

    impl JobHandle {
        pub(super) fn new(child: &std::process::Child) -> Result<Self, String> {
            unsafe {
                let handle = CreateJobObjectW(ptr::null_mut(), ptr::null());
                if handle.is_null() {
                    return Err("CreateJobObjectW failed".to_string());
                }
                let mut info = MaybeUninit::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>::zeroed();
                let mut info = info.assume_init();
                info.basic_limit_information.limit_flags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                let ok = SetInformationJobObject(
                    handle,
                    JOB_OBJECT_EXTENDED_LIMIT_INFORMATION,
                    ptr::addr_of_mut!(info).cast(),
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as DWORD,
                );
                if ok == FALSE {
                    let _ = CloseHandle(handle);
                    return Err("SetInformationJobObject failed".to_string());
                }
                let proc_handle = child.as_raw_handle() as HANDLE;
                let ok = AssignProcessToJobObject(handle, proc_handle);
                if ok == FALSE {
                    let _ = CloseHandle(handle);
                    return Err("AssignProcessToJobObject failed".to_string());
                }
                Ok(Self { handle })
            }
        }

        pub(super) fn close(&mut self) {
            if !self.handle.is_null() {
                unsafe {
                    let _ = CloseHandle(self.handle);
                }
                self.handle = ptr::null_mut();
            }
        }
    }

    impl Drop for JobHandle {
        fn drop(&mut self) {
            self.close();
        }
    }
}

#[derive(Debug, Clone)]
pub struct DesiredProcess {
    pub egress_id: EgressId,
    pub spec: ProcessSpec,
}

#[derive(Debug)]
pub enum SupervisorCmd {
    ApplyDesired(Vec<DesiredProcess>),
    Stop,
}

#[derive(Debug)]
pub struct Supervisor {
    processes: BTreeMap<EgressId, SupervisedProcess>,
    status: Arc<Mutex<Vec<ProcessStatus>>>,
}

impl Supervisor {
    pub const fn new(status: Arc<Mutex<Vec<ProcessStatus>>>) -> Self {
        Self {
            processes: BTreeMap::new(),
            status,
        }
    }

    pub fn reconcile(&mut self, desired: Vec<DesiredProcess>) {
        let mut desired_ids = BTreeMap::new();

        for item in desired {
            desired_ids.insert(item.egress_id.clone(), item.spec.clone());
            if let Some(proc) = self.processes.get_mut(&item.egress_id) {
                let was_enabled = proc.last_desired_enabled;
                let next_fp = ProcessFingerprint::from(&item.spec);
                if proc.fingerprint == next_fp {
                    proc.spec = item.spec;
                    if proc.spec.enabled {
                        if !was_enabled {
                            proc.clear_rate_limit();
                        }
                        if proc.child.is_none() {
                            proc.start(&item.egress_id, StartMode::Initial);
                        }
                    } else {
                        proc.stop_child("disabled", &item.egress_id);
                    }
                } else {
                    proc.stop_child("reconfigure", &item.egress_id);
                    *proc = SupervisedProcess::new(item.spec);
                    if proc.spec.enabled {
                        proc.start(&item.egress_id, StartMode::Initial);
                    }
                }
                proc.last_desired_enabled = proc.spec.enabled;
            } else {
                let mut proc = SupervisedProcess::new(item.spec);
                if proc.spec.enabled {
                    proc.start(&item.egress_id, StartMode::Initial);
                }
                self.processes.insert(item.egress_id, proc);
            }
        }

        let existing: Vec<EgressId> = self.processes.keys().cloned().collect();
        for id in existing {
            if desired_ids.contains_key(&id) {
                continue;
            }
            if let Some(mut proc) = self.processes.remove(&id) {
                proc.stop_child("removed", &id);
            }
        }

        self.update_snapshot();
    }

    pub fn tick(&mut self) {
        let now = Instant::now();
        let ids: Vec<EgressId> = self.processes.keys().cloned().collect();

        for id in &ids {
            if let Some(proc) = self.processes.get_mut(id) {
                proc.poll_exit(id, now);
            }
        }

        for id in &ids {
            if let Some(proc) = self.processes.get_mut(id) {
                proc.maybe_restart(id, now);
            }
        }

        self.update_snapshot();
    }

    pub fn stop_all(&mut self) {
        let ids: Vec<EgressId> = self.processes.keys().cloned().collect();
        for id in ids {
            if let Some(proc) = self.processes.get_mut(&id) {
                proc.stop_child("shutdown", &id);
            }
        }
        self.update_snapshot();
    }

    fn update_snapshot(&self) {
        let snapshot = self
            .processes
            .iter()
            .map(|(id, proc)| ProcessStatus {
                egress_id: id.to_string(),
                enabled: proc.spec.enabled,
                running: proc.child.is_some(),
                pid: proc.child.as_ref().map(Child::id),
                restarts: proc.restarts,
                last_exit_code: proc.last_exit_code,
                last_error: proc.last_error.clone(),
            })
            .collect::<Vec<_>>();

        if let Ok(mut guard) = self.status.lock() {
            *guard = snapshot;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProcessFingerprint {
    program: Option<String>,
    args: Vec<String>,
    cwd: Option<String>,
    env: BTreeMap<String, String>,
    restart: RestartPolicy,
    backoff_ms: u64,
    max_backoff_ms: u64,
    max_restarts_per_minute: u32,
}

impl From<&ProcessSpec> for ProcessFingerprint {
    fn from(spec: &ProcessSpec) -> Self {
        Self {
            program: spec.program.clone(),
            args: spec.args.clone(),
            cwd: spec.cwd.clone(),
            env: spec.env.clone(),
            restart: spec.restart,
            backoff_ms: spec.backoff_ms,
            max_backoff_ms: spec.max_backoff_ms,
            max_restarts_per_minute: spec.max_restarts_per_minute,
        }
    }
}

#[derive(Debug)]
struct SupervisedProcess {
    spec: ProcessSpec,
    fingerprint: ProcessFingerprint,
    child: Option<Child>,
    restarts: u64,
    last_exit_code: Option<i32>,
    last_error: Option<String>,
    restart_backoff_ms: u64,
    next_restart_at: Option<Instant>,
    restart_times: VecDeque<Instant>,
    rate_limited_until: Option<Instant>,
    started_once: bool,
    last_desired_enabled: bool,
    #[cfg(windows)]
    job: Option<winjob::JobHandle>,
}

impl SupervisedProcess {
    fn new(spec: ProcessSpec) -> Self {
        let backoff = spec.backoff_ms;
        let last_desired_enabled = spec.enabled;
        Self {
            fingerprint: ProcessFingerprint::from(&spec),
            spec,
            child: None,
            restarts: 0,
            last_exit_code: None,
            last_error: None,
            restart_backoff_ms: backoff,
            next_restart_at: None,
            restart_times: VecDeque::new(),
            rate_limited_until: None,
            started_once: false,
            last_desired_enabled,
            #[cfg(windows)]
            job: None,
        }
    }

    fn clear_rate_limit(&mut self) {
        self.rate_limited_until = None;
        self.restart_times.clear();
        self.next_restart_at = None;
        self.restart_backoff_ms = self.spec.backoff_ms;
        if self.last_error.as_deref() == Some(RATE_LIMIT_ERROR) {
            self.last_error = None;
        }
    }

    fn start(&mut self, egress_id: &EgressId, mode: StartMode) {
        let now = Instant::now();
        if matches!(mode, StartMode::Restart) && !self.allow_restart(now, egress_id) {
            return;
        }

        let Some(program) = self
            .spec
            .program
            .as_deref()
            .filter(|value| !value.trim().is_empty())
        else {
            self.last_error = Some("process program missing".to_string());
            return;
        };
        let mut cmd = Command::new(program);
        cmd.args(&self.spec.args);
        if let Some(cwd) = &self.spec.cwd {
            cmd.current_dir(cwd);
        }
        if !self.spec.env.is_empty() {
            cmd.envs(&self.spec.env);
        }

        match cmd.spawn() {
            Ok(child) => {
                #[cfg(windows)]
                let mut child = child;
                #[cfg(not(windows))]
                let child = child;
                #[cfg(windows)]
                let job = match winjob::JobHandle::new(&child) {
                    Ok(job) => Some(job),
                    Err(err) => {
                        warn!(egress = %egress_id, error = %err, "job object attach failed");
                        let _ = child.kill();
                        let _ = child.wait();
                        self.last_error = Some(format!("job object attach failed: {err}"));
                        return;
                    }
                };
                info!(egress = %egress_id, pid = child.id(), "process started");
                self.child = Some(child);
                #[cfg(windows)]
                {
                    self.job = job;
                }
                if self.started_once {
                    self.restarts = self.restarts.saturating_add(1);
                } else {
                    self.started_once = true;
                }
                self.last_error = None;
                self.next_restart_at = None;
            }
            Err(err) => {
                warn!(egress = %egress_id, error = %err, "process start failed");
                self.last_error = Some(err.to_string());
                self.child = None;
                self.schedule_restart(now, egress_id);
            }
        }
    }

    fn stop_child(&mut self, reason: &str, egress_id: &EgressId) {
        self.next_restart_at = None;
        #[cfg(windows)]
        if let Some(mut job) = self.job.take() {
            job.close();
        }
        if let Some(mut child) = self.child.take() {
            info!(egress = %egress_id, reason, "stopping process");
            let outcome = terminate_child(&mut child);
            self.last_exit_code = outcome.status.and_then(|s| s.code());
            if let Some(err) = outcome.error {
                self.last_error = Some(err);
            }
        }
    }

    fn poll_exit(&mut self, egress_id: &EgressId, now: Instant) {
        let Some(mut child) = self.child.take() else {
            return;
        };

        match child.try_wait() {
            Ok(Some(status)) => {
                self.last_exit_code = status.code();
                self.child = None;
                #[cfg(windows)]
                if let Some(mut job) = self.job.take() {
                    job.close();
                }
                self.on_exit(status, egress_id, now);
            }
            Ok(None) => {
                self.child = Some(child);
            }
            Err(err) => {
                warn!(egress = %egress_id, error = %err, "failed to poll process");
                self.child = Some(child);
                self.last_error = Some(err.to_string());
            }
        }
    }

    fn maybe_restart(&mut self, egress_id: &EgressId, now: Instant) {
        if self.child.is_some() || !self.spec.enabled {
            return;
        }
        if let Some(until) = self.rate_limited_until
            && now >= until
        {
            self.clear_rate_limit();
            self.start(egress_id, StartMode::Restart);
            return;
        }
        if self.next_restart_at.is_some_and(|when| now >= when) {
            self.next_restart_at = None;
            self.start(egress_id, StartMode::Restart);
        }
    }

    fn on_exit(&mut self, status: ExitStatus, egress_id: &EgressId, now: Instant) {
        let failure = status.code() != Some(0);
        let should_restart = match self.spec.restart {
            RestartPolicy::Never => false,
            RestartPolicy::OnFailure => failure,
            RestartPolicy::Always => true,
        };

        if should_restart {
            self.schedule_restart(now, egress_id);
        }
    }

    fn schedule_restart(&mut self, now: Instant, egress_id: &EgressId) {
        if !self.spec.enabled {
            return;
        }
        if matches!(self.spec.restart, RestartPolicy::Never) {
            return;
        }

        let backoff = self.restart_backoff_ms.max(1);
        self.next_restart_at = Some(now + Duration::from_millis(backoff));
        self.restart_backoff_ms = next_backoff(self.restart_backoff_ms, self.spec.max_backoff_ms);
        info!(
            egress = %egress_id,
            backoff_ms = backoff,
            "process scheduled to restart"
        );
    }

    fn allow_restart(&mut self, now: Instant, egress_id: &EgressId) -> bool {
        if self.spec.max_restarts_per_minute == 0 {
            return false;
        }
        if let Some(until) = self.rate_limited_until {
            if now < until {
                return false;
            }
            self.rate_limited_until = None;
            if self.last_error.as_deref() == Some(RATE_LIMIT_ERROR) {
                self.last_error = None;
            }
        }
        let window = RATE_LIMIT_WINDOW;
        while let Some(front) = self.restart_times.front() {
            if now.duration_since(*front) >= window {
                self.restart_times.pop_front();
            } else {
                break;
            }
        }

        if self.restart_times.len() >= self.spec.max_restarts_per_minute as usize {
            let until = now + window;
            self.rate_limited_until = Some(until);
            self.next_restart_at = Some(until);
            self.last_error = Some(RATE_LIMIT_ERROR.to_string());
            warn!(egress = %egress_id, "restart rate limit exceeded");
            return false;
        }

        self.restart_times.push_back(now);
        true
    }
}

#[derive(Debug, Clone, Copy)]
enum StartMode {
    Initial,
    Restart,
}

fn next_backoff(current: u64, max: u64) -> u64 {
    let next = current.saturating_mul(2).max(1);
    if max == 0 { next } else { next.min(max) }
}

struct TerminateOutcome {
    status: Option<ExitStatus>,
    error: Option<String>,
}

fn terminate_child(child: &mut Child) -> TerminateOutcome {
    let mut error = if let Err(err) = child.kill() {
        Some(err.to_string())
    } else {
        None
    };
    let deadline = Instant::now() + Duration::from_secs(2);
    let tick = Duration::from_millis(50);

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                return TerminateOutcome {
                    status: Some(status),
                    error,
                };
            }
            Ok(None) => {
                if Instant::now() >= deadline {
                    if error.is_none() {
                        error = Some("process did not exit before timeout".to_string());
                    }
                    break;
                }
                thread::sleep(tick);
            }
            Err(err) => {
                error = Some(err.to_string());
                break;
            }
        }
    }

    if let Err(err) = child.kill() {
        error = Some(err.to_string());
    }
    let status = match child.wait() {
        Ok(status) => Some(status),
        Err(err) => {
            error = Some(err.to_string());
            None
        }
    };
    TerminateOutcome { status, error }
}
