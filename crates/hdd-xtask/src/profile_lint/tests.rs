#![allow(clippy::expect_used, clippy::unwrap_used, reason = "tests")]

use std::fs;
use std::path::{Path, PathBuf};

use super::*;

const CONFIG: &str = r#"
profile_free_paths = ["crates/hdd-waf-core/**", "crates/hdd-proxy/**", "crates/hdd-common/src/net.rs"]
profile_patterns = ["RuntimeProfile", "runtime.profile", "Profile::", "HDD_LOCAL_", "feature = \"local\"", ".availability("]
profile_confined_patterns = ["RuntimeProfile", "HDD_LOCAL_"]
profile_allowed_paths = ["crates/hdd-local/**", "crates/hdd-common/src/profile/**"]
kv_patterns = ["fred::", "redis::"]
kv_crates = ["fred", "redis"]
kv_allowed_paths = ["crates/hdd-common/src/kv/**"]
kv_allowed_manifests = ["crates/hdd-common/Cargo.toml"]
"#;

fn cfg() -> Config {
    toml::from_str(CONFIG).expect("config")
}

struct Repo(PathBuf);

impl Repo {
    fn new(name: &str) -> Repo {
        let dir = std::env::temp_dir().join(format!("hdd-xtask-pl-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("docs")).expect("mkdir");
        fs::write(dir.join("docs").join("profile-lint.toml"), CONFIG).expect("config");
        Repo(dir)
    }

    fn put(&self, rel: &str, text: &str) {
        let p = self.0.join(rel);
        fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
        fs::write(p, text).expect("write");
    }

    fn root(&self) -> &Path {
        &self.0
    }
}

impl Drop for Repo {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn profile_findings(root: &Path) -> Vec<Finding> {
    // the repository-wide capability and table checks need the real files; only the scan part is exercised here
    let cfg = load_config(root).expect("config");
    let mut f = Vec::new();
    for (r, p) in crate_files(root) {
        if r.ends_with(".rs") {
            f.extend(scan_profile(&cfg, &r, &read_text(&p).expect("read")));
        } else if r.ends_with("/Cargo.toml") {
            f.extend(scan_profile_manifest(
                &cfg,
                &r,
                &read_text(&p).expect("read"),
            ));
        }
    }
    f
}

#[test]
fn a2_a_profile_check_added_to_the_detection_crate_fails_and_the_clean_tree_passes() {
    let repo = Repo::new("a2");
    repo.put(
        "crates/hdd-waf-core/src/lib.rs",
        "pub fn score(x: u32) -> u32 { x }\n",
    );
    assert!(profile_findings(repo.root()).is_empty());

    repo.put(
        "crates/hdd-waf-core/src/lib.rs",
        "pub fn score(p: &Profile) -> u32 {\n    if p.runtime.profile == RuntimeProfile::Local { 1 } else { 2 }\n}\n",
    );
    let f = profile_findings(repo.root());
    assert!(f.len() >= 2, "{f:?}");
    assert!(
        f.iter()
            .all(|x| x.location.starts_with("crates/hdd-waf-core/src/lib.rs:"))
    );
    assert!(f.iter().any(|x| x.message.contains("R-31")));
}

#[test]
fn profile_cfg_features_and_environment_variables_are_caught() {
    let repo = Repo::new("cfgs");
    repo.put(
        "crates/hdd-proxy/src/lib.rs",
        "#[cfg(feature = \"local\")]\npub fn a() {}\npub fn b() -> String { std::env::var(\"HDD_LOCAL_PORTS\").unwrap_or_default() }\n",
    );
    repo.put(
        "crates/hdd-proxy/Cargo.toml",
        "[package]\nname = \"hdd-proxy\"\n\n[features]\nlocal = []\ndefault = []\n",
    );
    let f = profile_findings(repo.root());
    assert_eq!(
        f.iter()
            .filter(|x| x.location.ends_with("lib.rs:1"))
            .count(),
        1,
        "{f:?}"
    );
    assert!(f.iter().any(|x| x.location.ends_with("lib.rs:3")), "{f:?}");
    assert!(
        f.iter()
            .any(|x| x.location.ends_with("Cargo.toml:5") && x.message.contains("`local`")),
        "{f:?}"
    );
}

#[test]
fn comments_test_code_and_other_crates_are_not_flagged() {
    let repo = Repo::new("exempt");
    repo.put(
        "crates/hdd-waf-core/src/lib.rs",
        "// explains why RuntimeProfile must not be used here\npub fn a() {}\n#[cfg(test)]\nmod tests {\n    use RuntimeProfile;\n}\n",
    );
    repo.put(
        "crates/hdd-waf-core/tests/it.rs",
        "fn t() { let _ = RuntimeProfile::Local; }\n",
    );
    repo.put(
        "crates/hdd-local/src/lib.rs",
        "pub fn a(p: RuntimeProfile) {}\n",
    );
    repo.put("crates/hdd-common/src/net.rs", "pub fn a() {}\n");
    repo.put(
        "crates/hdd-common/src/profile/mod.rs",
        "pub fn a(p: RuntimeProfile) {}\n",
    );
    assert!(profile_findings(repo.root()).is_empty());
    // the same text in a profile-free module of hdd-common is caught
    repo.put(
        "crates/hdd-common/src/net.rs",
        "pub fn a(p: RuntimeProfile) {}\n",
    );
    assert_eq!(profile_findings(repo.root()).len(), 1);
}

#[test]
fn a3_a_redis_client_call_outside_the_kv_module_fails() {
    let c = cfg();
    assert!(
        scan_kv(
            &c,
            "crates/hdd-proxy/src/lib.rs",
            "let c = fred::clients::Client::default();\n"
        )
        .len()
            == 1
    );
    assert!(scan_kv(&c, "crates/hdd-common/src/lib.rs", "use redis::Commands;\n").len() == 1);
    assert!(
        scan_kv(
            &c,
            "crates/hdd-common/src/kv/redis.rs",
            "use fred::prelude::*;\n"
        )
        .is_empty()
    );
    assert!(
        scan_kv(
            &c,
            "crates/hdd-proxy/src/lib.rs",
            "// we do not call redis::cmd here\n"
        )
        .is_empty()
    );
    assert!(scan_kv(&c, "crates/hdd-proxy/src/lib.rs", "pub fn plain() {}\n").is_empty());
}

#[test]
fn redis_client_dependencies_are_caught_in_every_manifest_but_the_common_one() {
    let c = cfg();
    let toml = "[dependencies]\nserde = \"1\"\nfred = { version = \"1\" }\n\n[dependencies.redis]\nversion = \"1\"\n";
    let f = scan_kv_manifest(&c, "crates/hdd-proxy/Cargo.toml", toml);
    assert_eq!(f.len(), 2, "{f:?}");
    assert!(scan_kv_manifest(&c, "crates/hdd-common/Cargo.toml", toml).is_empty());
    assert!(
        scan_kv_manifest(
            &c,
            "crates/hdd-proxy/Cargo.toml",
            "[dependencies]\nredisx = \"1\"\nfredo = \"1\"\n"
        )
        .is_empty()
    );
}

#[test]
fn the_kv_check_walks_the_crates_and_reports_each_file() {
    let repo = Repo::new("kvwalk");
    repo.put("Cargo.toml", "[workspace]\nmembers = []\n");
    repo.put("crates/hdd-common/src/kv/mod.rs", "use fred::prelude::*;\n");
    repo.put(
        "crates/hdd-common/Cargo.toml",
        "[dependencies]\nfred = \"1\"\n",
    );
    assert!(check_kv(repo.root()).is_empty());
    repo.put(
        "crates/hdd-api/src/lib.rs",
        "fn f() { redis::cmd(\"GET\"); }\n",
    );
    repo.put(
        "crates/hdd-api/Cargo.toml",
        "[dependencies]\nredis = \"0.1\"\n",
    );
    let f = check_kv(repo.root());
    assert_eq!(f.len(), 2, "{f:?}");
}

#[test]
fn a_missing_config_is_a_finding_not_a_pass() {
    let dir = std::env::temp_dir().join(format!("hdd-xtask-pl-{}-noconfig", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("mkdir");
    assert_eq!(check_profile(&dir).len(), 1);
    assert_eq!(check_kv(&dir).len(), 1);
    let _ = fs::remove_dir_all(&dir);
}

const CAPS: &str = "pub enum Capability {\n    /// a\n    A,\n    /// b\n    B,\n}\nimpl Capability {\n    pub const ALL: [Capability; 2] = [\n        Capability::A,\n        Capability::B,\n    ];\n}\n";

#[test]
fn a_capability_missing_from_the_matrix_list_fails() {
    assert!(check_capability_text("c.rs", CAPS).is_empty());
    let added = CAPS.replace("    B,\n}", "    B,\n    /// c\n    C,\n}");
    let f = check_capability_text("c.rs", &added);
    assert_eq!(f.len(), 1, "{f:?}");
    assert!(f.first().is_some_and(|x| x.message.contains("`C`")));
    let stale = CAPS.replace(
        "        Capability::B,\n",
        "        Capability::B,\n        Capability::Gone,\n",
    );
    assert!(
        check_capability_text("c.rs", &stale)
            .iter()
            .any(|x| x.message.contains("Gone"))
    );
    assert_eq!(check_capability_text("c.rs", "nothing").len(), 1);
}

#[test]
fn the_registry_rows_are_parsed_and_the_generated_table_round_trips() {
    let spec = "| Check | Title | First live | Tier |\n| --- | --- | --- | --- |\n| AC-00 | Preflight \"quoted\" | P11 (T-0217) | smoke |\n| AC-01 | Auth | P06 | release |\n| not-a-row | x | y | z |\n";
    let rows = ac_rows(spec);
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows.first().map(|r| r.1.as_str()),
        Some("Preflight \"quoted\"")
    );
    let rust = render_ac_table(spec);
    assert!(
        rust.contains("(\"AC-00\", \"Preflight \\\"quoted\\\"\", \"P11 (T-0217)\", \"smoke\"),")
    );
    assert!(rust.ends_with("];\n"));
}

#[test]
fn the_shipped_tree_passes_both_lints() {
    let root = crate::util::repo_root().expect("repo root");
    let p = check_profile(&root);
    assert!(p.is_empty(), "{p:?}");
    let k = check_kv(&root);
    assert!(k.is_empty(), "{k:?}");
}

#[test]
fn the_runtime_profile_is_confined_to_the_places_that_may_know_it() {
    let c = cfg();
    let code = "pub fn f(p: RuntimeProfile) {}\n";
    // allowed places
    assert!(scan_confined(&c, "crates/hdd-local/src/lib.rs", code).is_empty());
    assert!(scan_confined(&c, "crates/hdd-common/src/profile/types.rs", code).is_empty());
    // any other crate, including ones nobody listed as profile-free
    for path in [
        "crates/hdd-api/src/lib.rs",
        "crates/hdd-worker/src/main.rs",
        "crates/hdd-dns/src/lib.rs",
        "crates/hdd-common/src/net.rs",
    ] {
        assert_eq!(scan_confined(&c, path, code).len(), 1, "{path}");
    }
    assert_eq!(
        scan_confined(
            &c,
            "crates/hdd-api/src/lib.rs",
            "let x = std::env::var(\"HDD_LOCAL_PORTS\");\n"
        )
        .len(),
        1
    );
    // comments and test code are not code that decides
    assert!(
        scan_confined(
            &c,
            "crates/hdd-api/src/lib.rs",
            "// RuntimeProfile is explained here\n"
        )
        .is_empty()
    );
    assert!(scan_confined(&c, "crates/hdd-api/tests/it.rs", code).is_empty());
    assert!(
        scan_confined(
            &c,
            "crates/hdd-api/src/lib.rs",
            "fn a() {}\n#[cfg(test)]\nmod tests { fn t(p: RuntimeProfile) {} }\n"
        )
        .is_empty()
    );
}

#[test]
fn a_mention_of_the_test_marker_in_a_comment_does_not_hide_the_rest_of_the_file() {
    let c = cfg();
    let text =
        "// the next line starts the test module: #[cfg(test)]\nlet p = RuntimeProfile::Local;\n";
    assert_eq!(
        scan_confined(&c, "crates/hdd-api/src/lib.rs", text).len(),
        1
    );
    let in_string = "const S: &str = \"#[cfg(test)]\";\nlet p = RuntimeProfile::Local;\n";
    assert_eq!(
        scan_confined(&c, "crates/hdd-api/src/lib.rs", in_string).len(),
        1
    );
}

#[test]
fn a_renamed_redis_dependency_is_still_caught() {
    let c = cfg();
    let toml = "[dependencies]\nrds = { package = \"redis\", version = \"1\" }\n";
    assert_eq!(
        scan_kv_manifest(&c, "crates/hdd-api/Cargo.toml", toml).len(),
        1
    );
    assert!(scan_kv_manifest(&c, "crates/hdd-common/Cargo.toml", toml).is_empty());
}
