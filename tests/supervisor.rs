use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use policy_router_rs::{
    ipc::ProcessStatus,
    policy::config::{EgressId, ProcessSpec, RestartPolicy},
    supervisor::{DesiredProcess, Supervisor},
};

#[cfg(unix)]
#[test]
fn supervisor_rate_limits_restarts() {
    let status = Arc::new(Mutex::new(Vec::<ProcessStatus>::new()));
    let mut supervisor = Supervisor::new(Arc::clone(&status));

    let spec = ProcessSpec {
        enabled: true,
        program: Some("sh".to_string()),
        args: vec!["-c".to_string(), "exit 0".to_string()],
        cwd: None,
        env: BTreeMap::new(),
        restart: RestartPolicy::Always,
        backoff_ms: 10,
        max_backoff_ms: 20,
        max_restarts_per_minute: 1,
    };

    supervisor.reconcile(vec![DesiredProcess {
        egress_id: EgressId("vpn".to_string()),
        spec,
    }]);

    let start = Instant::now();
    while start.elapsed() < Duration::from_millis(500) {
        supervisor.tick();
        thread::sleep(Duration::from_millis(20));
    }

    let snapshot = status.lock().expect("lock status").clone();
    let proc = snapshot
        .iter()
        .find(|p| p.egress_id == "vpn")
        .expect("process status");

    assert!(!proc.running);
    assert!(proc.restarts >= 1);
    assert_eq!(
        proc.last_error.as_deref(),
        Some("restart rate limit exceeded (cooldown)")
    );

    thread::sleep(Duration::from_millis(400));
    let resume_deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < resume_deadline {
        supervisor.tick();
        thread::sleep(Duration::from_millis(20));
        let snapshot = status.lock().expect("lock status").clone();
        let proc = snapshot
            .iter()
            .find(|p| p.egress_id == "vpn")
            .expect("process status");
        if proc.restarts >= 2 {
            return;
        }
        if proc.last_error.as_deref() != Some("restart rate limit exceeded (cooldown)") {
            return;
        }
    }

    let snapshot = status.lock().expect("lock status").clone();
    let proc = snapshot
        .iter()
        .find(|p| p.egress_id == "vpn")
        .expect("process status");
    assert!(
        proc.restarts >= 2
            || proc.last_error.as_deref() != Some("restart rate limit exceeded (cooldown)")
    );
}
