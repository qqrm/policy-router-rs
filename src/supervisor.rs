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

#[cfg(all(target_os = "windows", feature = "windows"))]
mod winjob {
    use std::os::windows::process::ChildExt;

    use anyhow::Context;
    use windows::Win32::{
        Foundation::{CloseHandle, HANDLE},
        System::JobObjects::{
            AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        },
    };

    trait WinjobApi {
        fn create_job(&self) -> windows::core::Result<HANDLE>;
        fn set_information(
            &self,
            job: HANDLE,
            info: &JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        ) -> windows::core::Result<()>;
        fn assign_process(&self, job: HANDLE, process: HANDLE) -> windows::core::Result<()>;
        fn close_handle(&self, handle: HANDLE) -> windows::core::Result<()>;
    }

    #[derive(Debug, Default)]
    struct SystemWinjobApi;

    impl WinjobApi for SystemWinjobApi {
        fn create_job(&self) -> windows::core::Result<HANDLE> {
            unsafe { CreateJobObjectW(None, None) }
        }

        fn set_information(
            &self,
            job: HANDLE,
            info: &JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        ) -> windows::core::Result<()> {
            unsafe {
                SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    info as *const _ as *const _,
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            }
        }

        fn assign_process(&self, job: HANDLE, process: HANDLE) -> windows::core::Result<()> {
            unsafe { AssignProcessToJobObject(job, process) }
        }

        fn close_handle(&self, handle: HANDLE) -> windows::core::Result<()> {
            unsafe { CloseHandle(handle) }
        }
    }

    #[derive(Debug)]
    pub(super) struct JobHandle {
        handle: HANDLE,
    }

    impl JobHandle {
        pub(super) fn new(child: &std::process::Child) -> anyhow::Result<Self> {
            let api = SystemWinjobApi::default();
            Self::new_with_api(child, &api)
        }

        fn new_with_api(child: &std::process::Child, api: &dyn WinjobApi) -> anyhow::Result<Self> {
            let handle = api.create_job().context("CreateJobObjectW failed")?;
            let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            if let Err(err) = api.set_information(handle, &info) {
                let _ = api.close_handle(handle);
                return Err(anyhow::Error::new(err).context("SetInformationJobObject failed"));
            }
            let proc_handle = HANDLE(child.as_raw_handle() as *mut _);
            if let Err(err) = api.assign_process(handle, proc_handle) {
                let _ = api.close_handle(handle);
                return Err(anyhow::Error::new(err).context("AssignProcessToJobObject failed"));
            }
            Ok(Self { handle })
        }

        pub(super) fn close(&mut self) {
            if !self.handle.is_invalid() {
                let _ = unsafe { CloseHandle(self.handle) };
                self.handle = HANDLE::default();
            }
        }
    }

    impl Drop for JobHandle {
        fn drop(&mut self) {
            self.close();
        }
    }

    #[cfg(all(test, target_os = "windows", feature = "windows"))]
    mod tests {
        use std::{
            process::Command,
            sync::atomic::{AtomicUsize, Ordering},
        };

        use windows::{
            Win32::{Foundation::HANDLE, System::JobObjects::JOBOBJECT_EXTENDED_LIMIT_INFORMATION},
            core::{Error as WindowsError, HRESULT},
        };

        use super::{JobHandle, WinjobApi};

        struct StubApi {
            create_result: windows::core::Result<HANDLE>,
            set_result: windows::core::Result<()>,
            assign_result: windows::core::Result<()>,
            close_calls: AtomicUsize,
        }

        impl WinjobApi for StubApi {
            fn create_job(&self) -> windows::core::Result<HANDLE> {
                self.create_result.clone()
            }

            fn set_information(
                &self,
                _job: HANDLE,
                _info: &JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
            ) -> windows::core::Result<()> {
                self.set_result.clone()
            }

            fn assign_process(&self, _job: HANDLE, _process: HANDLE) -> windows::core::Result<()> {
                self.assign_result.clone()
            }

            fn close_handle(&self, _handle: HANDLE) -> windows::core::Result<()> {
                self.close_calls.fetch_add(1, Ordering::SeqCst);
                Ok(())
            }
        }

        fn spawn_child() -> std::process::Child {
            Command::new("cmd")
                .args(["/C", "exit", "0"])
                .spawn()
                .expect("spawn child")
        }

        #[test]
        fn job_handle_reports_create_error() {
            let child = spawn_child();
            let api = StubApi {
                create_result: Err(WindowsError::from_hresult(HRESULT(0x80070005))),
                set_result: Ok(()),
                assign_result: Ok(()),
                close_calls: AtomicUsize::new(0),
            };
            let err = JobHandle::new_with_api(&child, &api).unwrap_err();
            assert!(err.to_string().contains("CreateJobObjectW failed"));
            assert!(err.to_string().contains("0x80070005"));
            assert_eq!(api.close_calls.load(Ordering::SeqCst), 0);
        }

        #[test]
        fn job_handle_closes_on_set_information_error() {
            let child = spawn_child();
            let api = StubApi {
                create_result: Ok(HANDLE(1 as *mut _)),
                set_result: Err(WindowsError::from_hresult(HRESULT(0x80070057))),
                assign_result: Ok(()),
                close_calls: AtomicUsize::new(0),
            };
            let err = JobHandle::new_with_api(&child, &api).unwrap_err();
            assert!(err.to_string().contains("SetInformationJobObject failed"));
            assert!(err.to_string().contains("0x80070057"));
            assert_eq!(api.close_calls.load(Ordering::SeqCst), 1);
        }

        #[test]
        fn job_handle_closes_on_assign_error() {
            let child = spawn_child();
            let api = StubApi {
                create_result: Ok(HANDLE(1 as *mut _)),
                set_result: Ok(()),
                assign_result: Err(WindowsError::from_hresult(HRESULT(0x80070006))),
                close_calls: AtomicUsize::new(0),
            };
            let err = JobHandle::new_with_api(&child, &api).unwrap_err();
            assert!(err.to_string().contains("AssignProcessToJobObject failed"));
            assert!(err.to_string().contains("0x80070006"));
            assert_eq!(api.close_calls.load(Ordering::SeqCst), 1);
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
    #[cfg(all(target_os = "windows", feature = "windows"))]
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
            #[cfg(all(target_os = "windows", feature = "windows"))]
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
                #[cfg(all(target_os = "windows", feature = "windows"))]
                let mut child = child;
                #[cfg(not(all(target_os = "windows", feature = "windows")))]
                let child = child;
                #[cfg(all(target_os = "windows", feature = "windows"))]
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
                #[cfg(all(target_os = "windows", feature = "windows"))]
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
        #[cfg(all(target_os = "windows", feature = "windows"))]
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
                #[cfg(all(target_os = "windows", feature = "windows"))]
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
