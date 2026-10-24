//! `spec split|check|show`: deterministic split of `docs/SPEC.md` at the `PART`/`PHASE` markers (T-0005 step 2).
//!
//! The split is byte-lossless: concatenating the pieces in manifest order reproduces the master specification.
//! Line numbering follows the bootstrap tool (a trailing newline counts as an extra empty last line) so the
//! committed `MANIFEST.tsv` is reproduced exactly.

use std::path::Path;

use regex::Regex;

use crate::tasks;
use crate::util::{
    Error, Finding, Result, read_bytes, read_text, rel, sha256_hex, walk_files, write_text,
};

/// Maximum number of lines of one split file (T-0001 A4).
pub const MAX_SPLIT_LINES: usize = 3000;

/// One piece of the split specification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Segment {
    /// Marker id (for example `A0`, `P00`) or `00-preamble`.
    pub id: String,
    /// First line (1-based).
    pub start_line: usize,
    /// Last line (1-based, inclusive).
    pub end_line: usize,
    /// Exact text of the segment.
    pub text: String,
}

impl Segment {
    /// File name inside `docs/spec/`.
    pub fn file(&self) -> String {
        format!("{}.md", self.id)
    }

    /// Number of lines under the bootstrap counting rule.
    pub fn lines(&self) -> usize {
        self.end_line + 1 - self.start_line
    }
}

fn marker_regex() -> Result<Regex> {
    Ok(Regex::new(r"^<!-- (PART|PHASE):([A-Za-z0-9]+) -->\r?$")?)
}

/// Split the master specification text at its markers.
pub fn split(text: &str) -> Result<Vec<Segment>> {
    let marker = marker_regex()?;
    let lines: Vec<&str> = text.split('\n').collect();
    let mut marks: Vec<(usize, String)> = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        if let Some(c) = marker.captures(line) {
            let id = c.get(2).map(|m| m.as_str().to_owned()).unwrap_or_default();
            marks.push((i, id));
        }
    }
    let mut ranges: Vec<(String, usize, usize)> = Vec::new();
    if let Some((first, _)) = marks.first() {
        if *first > 0 {
            ranges.push(("00-preamble".to_owned(), 0, *first));
        }
    } else {
        return Err(Error(
            "no PART/PHASE markers found in the specification".into(),
        ));
    }
    for (k, (start, id)) in marks.iter().enumerate() {
        let end = marks.get(k + 1).map_or(lines.len(), |m| m.0);
        ranges.push((id.clone(), *start, end));
    }
    let mut out = Vec::new();
    for (id, a, b) in ranges {
        let slice = lines
            .get(a..b)
            .ok_or_else(|| Error("segment range out of bounds".into()))?;
        let mut piece = slice.join("\n");
        if b < lines.len() {
            piece.push('\n');
        }
        out.push(Segment {
            id,
            start_line: a + 1,
            end_line: b,
            text: piece,
        });
    }
    Ok(out)
}

/// Render `MANIFEST.tsv` for the given segments.
pub fn manifest(segs: &[Segment]) -> String {
    let mut out = String::from("order\tfile\tstart_line\tend_line\tlines\tsha256\n");
    for (n, s) in segs.iter().enumerate() {
        out.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\t{}\n",
            n + 1,
            s.file(),
            s.start_line,
            s.end_line,
            s.lines(),
            sha256_hex(s.text.as_bytes())
        ));
    }
    out
}

/// Load the master specification and verify it against `docs/SPEC.sha256`.
pub fn load_master(root: &Path) -> Result<String> {
    let path = root.join("docs").join("SPEC.md");
    let raw = read_bytes(&path)?;
    let recorded = read_text(&root.join("docs").join("SPEC.sha256"))?;
    let want = recorded.split_whitespace().next().unwrap_or("");
    let got = sha256_hex(&raw);
    if want != got {
        return Err(Error(format!(
            "docs/SPEC.md sha256 {got} does not match docs/SPEC.sha256 ({want})"
        )));
    }
    String::from_utf8(raw).map_err(|_| Error("docs/SPEC.md is not valid UTF-8".into()))
}

/// `spec split`: write `docs/spec/<id>.md` and `MANIFEST.tsv` from `docs/SPEC.md`. Refuses when the checksum differs.
pub fn run_split(root: &Path) -> Result<()> {
    let text = load_master(root)?;
    let segs = split(&text)?;
    let joined: String = segs.iter().map(|s| s.text.as_str()).collect();
    if joined != text {
        return Err(Error("split is not lossless; nothing written".into()));
    }
    for s in &segs {
        if s.lines() > MAX_SPLIT_LINES {
            return Err(Error(format!(
                "{} has {} lines (maximum {MAX_SPLIT_LINES})",
                s.file(),
                s.lines()
            )));
        }
    }
    let dir = root.join("docs").join("spec");
    for s in &segs {
        write_text(&dir.join(s.file()), &s.text)?;
    }
    write_text(&dir.join("MANIFEST.tsv"), &manifest(&segs))?;
    println!("spec split: wrote {} files and MANIFEST.tsv", segs.len());
    Ok(())
}

/// `spec check`: compare `docs/spec/` with a fresh split of `docs/SPEC.md` (T-0001 A1 to A4, T-0005 A2).
pub fn check(root: &Path) -> Vec<Finding> {
    let mut findings = Vec::new();
    let text = match load_master(root) {
        Ok(t) => t,
        Err(e) => return vec![Finding::new("spec", "docs/SPEC.md", e.0)],
    };
    let segs = match split(&text) {
        Ok(s) => s,
        Err(e) => return vec![Finding::new("spec", "docs/SPEC.md", e.0)],
    };
    let dir = root.join("docs").join("spec");
    let mut expected_files: Vec<String> = Vec::new();
    for s in &segs {
        expected_files.push(s.file());
        let path = dir.join(s.file());
        match read_bytes(&path) {
            Ok(bytes) => {
                if bytes != s.text.as_bytes() {
                    findings.push(Finding::new(
                        "spec",
                        rel(root, &path),
                        "differs from a fresh split of docs/SPEC.md (edit the master spec, then run `cargo xtask spec split`)",
                    ));
                }
            }
            Err(_) => findings.push(Finding::new("spec", rel(root, &path), "missing")),
        }
        if s.lines() > MAX_SPLIT_LINES {
            findings.push(Finding::new(
                "spec",
                s.file(),
                format!("{} lines exceeds {MAX_SPLIT_LINES}", s.lines()),
            ));
        }
        if !s.id.starts_with("00-") && !s.text.starts_with("<!-- ") {
            findings.push(Finding::new("spec", s.file(), "first line is not a marker"));
        }
    }
    match read_text(&dir.join("MANIFEST.tsv")) {
        Ok(m) if m == manifest(&segs) => {}
        Ok(_) => findings.push(Finding::new(
            "spec",
            "docs/spec/MANIFEST.tsv",
            "differs from the manifest of a fresh split",
        )),
        Err(e) => findings.push(Finding::new("spec", "docs/spec/MANIFEST.tsv", e.0)),
    }
    expected_files.push("MANIFEST.tsv".into());
    expected_files.push("INDEX.md".into());
    for f in walk_files(&dir) {
        let name = f
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if !expected_files.contains(&name) {
            findings.push(Finding::new(
                "spec",
                rel(root, &f),
                "not produced by the split (stray file)",
            ));
        }
    }
    findings
}

/// Registry id patterns resolved by `spec show` (section 0.1 item 3).
const REGISTRY_PATTERNS: &[(&str, &str)] = &[
    ("screen", r"\bS-\d{3}\b"),
    ("journey", r"\bJ-\d{2}\b"),
    ("attack", r"\bATK-\d{3}\b"),
    ("check", r"\bAC-\d{2}\b"),
    ("error", r"\bERR-[A-Z]+-\d{3}\b"),
    ("metric", r"\bMET-[a-z_0-9]+\b"),
    ("audit", r"\bAUD-[a-z_]+\.[a-z_]+\b"),
    ("permission", r"\bPERM-[a-z_]+\.[a-z_]+\b"),
];

/// Return the registry ids a task block references, grouped by kind.
pub fn registry_refs(block: &str) -> Result<Vec<(&'static str, Vec<String>)>> {
    let mut out = Vec::new();
    for (kind, pat) in REGISTRY_PATTERNS {
        let re = Regex::new(pat)?;
        let mut ids: Vec<String> = re.find_iter(block).map(|m| m.as_str().to_owned()).collect();
        ids.sort();
        ids.dedup();
        if !ids.is_empty() {
            out.push((*kind, ids));
        }
    }
    Ok(out)
}

/// `spec show T-nnnn`: print the task block and, for each referenced registry id, the first spec lines that mention it as a table row.
pub fn show(root: &Path, task_id: &str) -> Result<String> {
    let text = load_master(root)?;
    let model = tasks::parse(&text)?;
    let task = model
        .tasks
        .iter()
        .find(|t| t.id == task_id)
        .ok_or_else(|| Error(format!("unknown task {task_id}")))?;
    let mut out = String::new();
    out.push_str(&format!(
        "{}\n\n(docs/spec/{}.md line {}, docs/SPEC.md line {})\n",
        task.block, task.seg, task.seg_line, task.spec_line
    ));
    let refs = registry_refs(&task.block)?;
    if !refs.is_empty() {
        out.push_str("\nReferenced registry rows:\n");
    }
    let lines: Vec<&str> = text.lines().collect();
    for (kind, ids) in refs {
        for id in ids {
            let needle_row = format!("| {id} |");
            let hit = lines
                .iter()
                .enumerate()
                .find(|(_, l)| l.contains(&needle_row) || l.starts_with(&format!("### {id}")));
            match hit {
                Some((n, l)) => out.push_str(&format!(
                    "- [{kind}] {id} (SPEC.md line {}): {}\n",
                    n + 1,
                    l.trim()
                )),
                None => out.push_str(&format!(
                    "- [{kind}] {id}: no table row found (grep docs/SPEC.md)\n"
                )),
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str =
        "<!-- PART:A0 -->\n# Title\nbody\n<!-- PHASE:P00 -->\n## PHASE P00\n### T-0001 · x\n";

    #[test]
    fn split_is_lossless_and_cut_at_markers() {
        let segs = split(SAMPLE).expect("split");
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0].id, "A0");
        assert_eq!(segs[0].text, "<!-- PART:A0 -->\n# Title\nbody\n");
        assert_eq!(segs[1].id, "P00");
        assert_eq!(segs[1].start_line, 4);
        let joined: String = segs.iter().map(|s| s.text.as_str()).collect();
        assert_eq!(joined, SAMPLE);
    }

    #[test]
    fn preamble_is_kept_when_text_precedes_the_first_marker() {
        let text = format!("intro\n{SAMPLE}");
        let segs = split(&text).expect("split");
        assert_eq!(segs[0].id, "00-preamble");
        let joined: String = segs.iter().map(|s| s.text.as_str()).collect();
        assert_eq!(joined, text);
    }

    #[test]
    fn golden_manifest_for_the_sample() {
        let segs = split(SAMPLE).expect("split");
        let m = manifest(&segs);
        let mut lines = m.lines();
        assert_eq!(
            lines.next(),
            Some("order\tfile\tstart_line\tend_line\tlines\tsha256")
        );
        let row1 = lines.next().expect("row 1");
        assert!(row1.starts_with("1\tA0.md\t1\t3\t3\t"), "{row1}");
        let row2 = lines.next().expect("row 2");
        // the trailing newline counts as an extra empty line (bootstrap rule): lines 4..=7
        assert!(row2.starts_with("2\tP00.md\t4\t7\t4\t"), "{row2}");
    }

    #[test]
    fn missing_markers_is_an_error() {
        assert!(split("no markers here\n").is_err());
    }

    #[test]
    fn registry_refs_finds_ids() {
        let refs =
            registry_refs("see S-042, AC-37 and ERR-LOCAL-001; also AC-37 again").expect("refs");
        let kinds: Vec<&str> = refs.iter().map(|r| r.0).collect();
        assert_eq!(kinds, vec!["screen", "check", "error"]);
        assert_eq!(
            refs.iter().find(|r| r.0 == "check").map(|r| r.1.len()),
            Some(1)
        );
    }
}
