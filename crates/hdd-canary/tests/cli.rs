//! End-to-end tests of the `hdd-canary` binary as systemd starts it: real process, real listener, fail-closed startup.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "test helpers"
)]

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use hdd_canary::{DEFAULT_BASE_PATH, MANIFEST_NAME};

fn temp_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hdd-canary-cli-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hdd-canary"))
}

/// Kill the sidecar even when an assertion panics.
struct Sidecar(Child);

impl Drop for Sidecar {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn t0210_the_binary_prints_help_and_version() {
    let help = binary().arg("--help").output().expect("run");
    let text = String::from_utf8_lossy(&help.stdout).into_owned();
    assert_eq!(help.status.code(), Some(0), "{text}");
    for needle in [
        "Usage: hdd-canary",
        "--bind",
        "--base-path",
        "--root",
        "--manifest",
    ] {
        assert!(text.contains(needle), "{needle} missing in:\n{text}");
    }
    let version = binary().arg("--version").output().expect("run");
    assert_eq!(version.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&version.stdout).contains(env!("CARGO_PKG_NAME")));
    let unknown = binary().arg("--no-such-flag").output().expect("run");
    assert_eq!(unknown.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&unknown.stderr).contains("unknown argument"));
}

#[test]
fn t0210_the_binary_fails_closed_without_the_contract_files() {
    let empty = temp_dir("empty");
    let out = binary()
        .args(["--bind", "127.0.0.1:0", "--root"])
        .arg(&empty)
        .output()
        .expect("run");
    let text = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(
        out.status.code(),
        Some(2),
        "must refuse to serve missing files: {text}"
    );
    assert!(text.contains("cannot read"), "{text}");
    assert!(text.contains("ok.txt"), "{text}");
    let _ = std::fs::remove_dir_all(&empty);
}

#[test]
fn t0210_the_binary_fails_closed_on_a_manifest_mismatch() {
    let dir = temp_dir("manifest-mismatch");
    hdd_canary::generate(&dir, DEFAULT_BASE_PATH).expect("generate");
    std::fs::write(dir.join("ok.txt"), b"tampered").expect("tamper");
    let out = binary()
        .args(["--bind", "127.0.0.1:0", "--root"])
        .arg(&dir)
        .args(["--manifest"])
        .arg(dir.join(MANIFEST_NAME))
        .output()
        .expect("run");
    let text = String::from_utf8_lossy(&out.stderr).into_owned();
    assert_eq!(
        out.status.code(),
        Some(2),
        "must refuse a changed file: {text}"
    );
    assert!(
        text.contains("ok.txt") && text.contains("does not match"),
        "{text}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn t0210_the_binary_serves_the_contract_files_on_the_reported_listener() {
    let dir = temp_dir("serve");
    hdd_canary::generate(&dir, DEFAULT_BASE_PATH).expect("generate");
    let mut child = binary()
        .args(["--bind", "127.0.0.1:0", "--root"])
        .arg(&dir)
        .args(["--manifest"])
        .arg(dir.join(MANIFEST_NAME))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn");
    let stdout = child.stdout.take().expect("stdout");
    let _sidecar = Sidecar(child);
    let (sender, receiver) = mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(stdout).lines().map_while(Result::ok) {
            let _ = sender.send(line);
        }
    });
    let address = loop {
        match receiver.recv_timeout(Duration::from_secs(15)) {
            Ok(line) => {
                if let Some(rest) = line.trim().strip_prefix("listening: http://") {
                    break rest.to_owned();
                }
            }
            Err(_) => panic!("the sidecar never reported a listening address"),
        }
    };
    let mut stream = TcpStream::connect(&address).expect("connect to the reported address");
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("timeout");
    stream
        .write_all(format!("GET {DEFAULT_BASE_PATH}ok.txt HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
        .expect("write");
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let mut response = Vec::new();
    let mut buffer = [0u8; 1024];
    loop {
        match stream.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => response.extend_from_slice(&buffer[..n]),
            Err(_) => break,
        }
    }
    let text = String::from_utf8_lossy(&response).into_owned();
    assert!(text.starts_with("HTTP/1.1 200 OK"), "{text}");
    assert!(text.ends_with("hdd-canary-ok"), "{text}");
    // the process is stopped by the Sidecar guard (Drop kills and reaps it)
    let _ = std::fs::remove_dir_all(&dir);
}
