#[cfg(all(target_os = "windows", feature = "windows"))]
mod windows_process_lookup {
    use std::{
        net::{TcpListener, TcpStream},
        thread::sleep,
        time::Duration,
    };

    use policy_router_rs::platform::process_lookup;

    #[test]
    fn lookup_finds_current_process_by_local_endpoint() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind listener");
        let listener_addr = listener.local_addr().expect("listener addr");
        let stream = TcpStream::connect(listener_addr).expect("connect to listener");
        let _server_stream = listener.accept().expect("accept connection").0;
        let client_local_addr = stream.local_addr().expect("client local addr");

        let lookup = process_lookup();
        let mut info = None;
        for _ in 0..25 {
            info = lookup
                .lookup_client_process(client_local_addr)
                .expect("lookup client process");
            if info.is_some() {
                break;
            }
            sleep(Duration::from_millis(10));
        }

        let info = info.expect("process info not found");
        assert_eq!(info.pid, std::process::id());
        assert!(
            info.exe == "<unknown>" || !info.exe.is_empty(),
            "exe path should be <unknown> or non-empty"
        );
    }
}
