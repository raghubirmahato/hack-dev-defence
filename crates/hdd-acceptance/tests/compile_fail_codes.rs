//! Review item N-9: the crate-root `compile_fail` doc-tests must fail for the **right reason**, not for any compile error.
//!
//! rustdoc's `compile_fail` annotation accepts *any* compile error, and it has no error-code form: the `compile_fail,EXxxx`
//! spelling some reviews suggest is not a rustdoc feature (it is silently treated as an unknown attribute), so a doctest
//! annotated that way still passes on a different error. This integration test therefore compiles the same snippets with
//! the compiler that built the crate and asserts the exact `error[EXXXX]` code of each one. It is the non-vacuous version of
//! the eight crate-root doc-tests.
//!
//! The test needs the library artefact to resolve `hdd_acceptance`; the test executable itself lives next to the rlib in
//! `target/<profile>/deps`, so it uses the newest `libhdd_acceptance-*.rlib` found there.

use std::path::{Path, PathBuf};
use std::process::Command;

/// The eight crate-root compile_fail snippets and the exact rustc error code each must produce.
const SNIPPETS: &[(&str, &str)] = &[
    (
        "E0624",
        "// `Connector::new` is crate-private: only `CheckContext::connector` (built by the executor) can create one.\n\
         let _ = hdd_acceptance::guard::Connector::new;",
    ),
    (
        "E0061",
        "// The connector takes no profile argument: the profile comes from the executor (review item S-1).\n\
         fn probe(ctx: &hdd_acceptance::runner::CheckContext) {\n\
             let _ = ctx.connector(\"rev-1\", \"a profile cannot be passed here\");\n\
         }",
    ),
    (
        "E0624",
        "struct FakeClient;\n\
         impl hdd_acceptance::inspect::InspectClient for FakeClient {\n\
             fn inspect(\n\
                 &mut self,\n\
                 _request: &hdd_acceptance::inspect::InspectRequest,\n\
             ) -> Result<\n\
                 hdd_acceptance::inspect::InspectResponse,\n\
                 hdd_acceptance::inspect::InspectClientError,\n\
             > {\n\
                 unimplemented!()\n\
             }\n\
         }\n\
         // `InspectGate::new` is crate-private: a check cannot build a gate and mint a ticket (review item S-2).\n\
         let _ = hdd_acceptance::inspect::InspectGate::new(FakeClient, \"rev-1\");",
    ),
    (
        "E0624",
        "// `CheckContext::new` is crate-private: a check body cannot forge the destructive flag or a fresh latch.\n\
         let _ = hdd_acceptance::runner::CheckContext::new;",
    ),
    (
        "E0624",
        "// `EvidenceRef::new` is crate-private: only `EvidenceStore` hashes the bytes it wrote.\n\
         let _ = hdd_acceptance::status::EvidenceRef::new;",
    ),
    (
        "E0624",
        "// `AbortLatch::new` and `RunInvalidLatch::new` are crate-private: only the executor creates the run's latches.\n\
         let _ = hdd_acceptance::runner::AbortLatch::new;",
    ),
    (
        "E0451",
        "// `EvidenceRef` has private fields: a struct literal cannot bypass the store (review item S-6).\n\
         let _ = hdd_acceptance::status::EvidenceRef {\n\
             path: \"x\".into(),\n\
             sha256: String::new(),\n\
             bytes: 0,\n\
         };",
    ),
    (
        "E0277",
        "// `AbortLatch` has no `Default` impl: only the executor builds the run's latches (review item S-6).\n\
         let _: hdd_acceptance::runner::AbortLatch = Default::default();",
    ),
];

/// The `deps` directory holding the test executable and the library rlib.
#[allow(clippy::expect_used)]
fn deps_dir() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
        .expect("the test executable is inside target/<profile>/deps")
}

/// The newest `libhdd_acceptance-*.rlib` in `deps`.
#[allow(clippy::expect_used, clippy::indexing_slicing)]
fn newest_rlib(deps: &Path) -> PathBuf {
    let mut best: Option<(std::time::SystemTime, PathBuf)> = None;
    for entry in std::fs::read_dir(deps).expect("the deps directory is readable") {
        let path = entry.expect("a readable directory entry").path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if name.starts_with("libhdd_acceptance-") && name.ends_with(".rlib") {
            let modified = std::fs::metadata(&path)
                .and_then(|meta| meta.modified())
                .expect("the rlib has a modification time");
            if best.as_ref().is_none_or(|(seen, _)| modified > *seen) {
                best = Some((modified, path));
            }
        }
    }
    best.expect("the library rlib is next to the test executable")
        .1
}

#[allow(clippy::expect_used, clippy::panic)]
#[test]
fn the_compile_fail_doctests_fail_for_their_exact_error_code() {
    let deps = deps_dir();
    let rlib = newest_rlib(&deps);
    let tmp = std::env::temp_dir().join(format!(
        "hdd-acceptance-compile-fail-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("create the snippet directory");
    for (index, (code, snippet)) in SNIPPETS.iter().enumerate() {
        let source = tmp.join(format!("case-{index}.rs"));
        std::fs::write(&source, format!("fn main() {{\n{snippet}\n}}\n"))
            .expect("write the snippet");
        let output = Command::new("rustc")
            .arg("--edition")
            .arg("2021")
            .arg("--crate-type")
            .arg("lib")
            .arg("-L")
            .arg(format!("dependency={}", deps.display()))
            .arg("--extern")
            .arg(format!("hdd_acceptance={}", rlib.display()))
            .arg("--out-dir")
            .arg(&tmp)
            .arg(&source)
            .output()
            .expect("run rustc");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "snippet {index} must not compile, but it did:\n{stderr}"
        );
        assert!(
            stderr.contains(&format!("error[{code}]")),
            "snippet {index} must fail with error[{code}] and no other reason, got:\n{stderr}"
        );
    }
    let _ = std::fs::remove_dir_all(&tmp);
}
