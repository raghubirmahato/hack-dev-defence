//! The acceptance registry: AC-00 to AC-62 as typed rows, each `UNVERIFIED(stage_not_reached)` until its check exists.
//!
//! The rows are projected from [`hdd_common::buildplan::ACCEPTANCE_CHECKS`] (itself spec-generated and spec-checked) and are
//! **cross-checked** against the specification text by tests: the ids parsed from `docs/spec/E3.md` and `docs/SPEC.md` must be
//! exactly the registry's ids as whole tokens, and exactly `AC-00`..`AC-62` (task acceptance A4). The cross-check does not
//! trust `ACCEPTANCE_CHECKS`; it reads the specification itself.
//!
//! A dry run of the full list emits one status line per registered id (E3.3: the full list always executes in dry-run mode
//! from P11).

use std::collections::BTreeSet;
use std::fmt;

use hdd_common::buildplan::ACCEPTANCE_CHECKS;

use crate::status::{ReasonCode, StatusLine, is_check_id};

/// Number of acceptance checks in Appendix E3 (AC-00 to AC-62 inclusive).
pub const CHECK_COUNT: usize = 63;

/// One registry row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RegistryEntry {
    /// `AC-nn` whole token.
    pub id: &'static str,
    /// Human title from Appendix E3.
    pub title: &'static str,
    /// Where the check is built (phase and task ids).
    pub built_in: &'static str,
    /// Suite tiers of E3.2 the check belongs to.
    pub tier: &'static str,
}

/// Every registry row, projected from the spec-generated table.
pub fn entries() -> impl Iterator<Item = RegistryEntry> {
    ACCEPTANCE_CHECKS
        .iter()
        .map(|(id, title, built_in, tier)| RegistryEntry {
            id,
            title,
            built_in,
            tier,
        })
}

/// The id of every registered check, in registry order.
pub fn ids() -> Vec<&'static str> {
    ACCEPTANCE_CHECKS.iter().map(|(id, _, _, _)| *id).collect()
}

/// The id `AC-00`..`AC-62`, generated: the expected set independent of any table.
pub fn expected_ids() -> Vec<String> {
    (0..CHECK_COUNT).map(|n| format!("AC-{n:02}")).collect()
}

/// A dry-run status line for every registered check: `UNVERIFIED(stage_not_reached)` (E3.3, A4).
pub fn dry_run_lines() -> Vec<StatusLine> {
    entries()
        .map(|entry| StatusLine::stage_not_reached(entry.id, entry.title, entry.tier))
        .collect()
}

/// The registry section of the specification: `### E3.5 The checks` up to `### E3.6`.
const E3_5_START: &str = "### E3.5 The checks";
const E3_6_START: &str = "### E3.6 ";

/// Why the registry and the specification disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RegistryMismatch {
    /// The parsed section has no `#### AC-nn · Title` row.
    NoRows {
        /// The file that was parsed.
        source: String,
    },
    /// The parsed id set is not `AC-00`..`AC-62`.
    NotSequential {
        /// The file that was parsed.
        source: String,
        /// Ids missing from the parsed set.
        missing: Vec<String>,
        /// Ids present but unexpected.
        extra: Vec<String>,
    },
    /// The registry and the specification have different ids.
    RegistryDiffers {
        /// The file that was parsed.
        source: String,
        /// Ids in the specification but not in the registry.
        missing: Vec<String>,
        /// Ids in the registry but not in the specification.
        extra: Vec<String>,
    },
    /// A row's title differs from the specification heading.
    TitleDiffers {
        /// The check id.
        id: String,
        /// Title in the registry.
        registry: String,
        /// Title in the specification.
        spec: String,
    },
    /// An id in the parsed rows is not an `AC-nn` whole token.
    BadId {
        /// The offending token.
        token: String,
    },
    /// The section marker was not found.
    SectionMissing {
        /// The file that was parsed.
        source: String,
    },
}

impl fmt::Display for RegistryMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RegistryMismatch::NoRows { source } => {
                write!(f, "{source}: no `#### AC-nn` check rows found")
            }
            RegistryMismatch::NotSequential {
                source,
                missing,
                extra,
            } => write!(
                f,
                "{source}: check ids are not AC-00..AC-62 (missing {missing:?}, extra {extra:?})"
            ),
            RegistryMismatch::RegistryDiffers {
                source,
                missing,
                extra,
            } => write!(
                f,
                "the registry differs from {source} (spec-only {missing:?}, registry-only {extra:?})"
            ),
            RegistryMismatch::TitleDiffers { id, registry, spec } => write!(
                f,
                "{id}: registry title `{registry}` differs from the specification title `{spec}`"
            ),
            RegistryMismatch::BadId { token } => {
                write!(f, "`{token}` is not an AC-nn whole-token check id")
            }
            RegistryMismatch::SectionMissing { source } => {
                write!(f, "{source}: `{E3_5_START}` not found")
            }
        }
    }
}

impl std::error::Error for RegistryMismatch {}

/// One check row parsed from the specification: id and title.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpecRow {
    /// The `AC-nn` id.
    pub id: String,
    /// The title after the `·` separator.
    pub title: String,
}

/// Parse the `#### AC-nn · Title` rows of section E3.5 of a specification text.
///
/// Only lines that are exactly a level-4 heading beginning with a whole `AC-nn` token count, so `AC-0` inside `AC-00`, a
/// substring such as `AC-1` in `AC-10`, or an id mentioned in prose cannot be mistaken for a check row.
pub fn parse_spec_rows(source: &str, text: &str) -> Result<Vec<SpecRow>, RegistryMismatch> {
    let start = text
        .find(E3_5_START)
        .ok_or_else(|| RegistryMismatch::SectionMissing {
            source: source.to_owned(),
        })?;
    let rest = &text[start..];
    let end = rest.find(E3_6_START).unwrap_or(rest.len());
    let section = &rest[..end];
    let mut rows = Vec::new();
    for line in section.lines() {
        let Some(heading) = line.strip_prefix("#### ") else {
            continue;
        };
        let Some((id, title)) = heading.split_once(' ') else {
            let token = heading.trim();
            if token.starts_with("AC-") {
                return Err(RegistryMismatch::BadId {
                    token: token.to_owned(),
                });
            }
            continue;
        };
        if !id.starts_with("AC-") {
            continue;
        }
        if !is_check_id(id) {
            return Err(RegistryMismatch::BadId {
                token: id.to_owned(),
            });
        }
        let title = title.trim_start_matches('\u{00b7}').trim().to_owned();
        rows.push(SpecRow {
            id: id.to_owned(),
            title,
        });
    }
    if rows.is_empty() {
        return Err(RegistryMismatch::NoRows {
            source: source.to_owned(),
        });
    }
    Ok(rows)
}

/// Compare a parsed specification section with the registry: same whole-token id set, `AC-00`..`AC-62`, same titles.
pub fn cross_check(source: &str, text: &str) -> Result<Vec<SpecRow>, RegistryMismatch> {
    let rows = parse_spec_rows(source, text)?;
    let spec_ids: BTreeSet<&str> = rows.iter().map(|r| r.id.as_str()).collect();
    let expected = expected_ids();
    let expected_set: BTreeSet<&str> = expected.iter().map(String::as_str).collect();
    let missing: Vec<String> = expected_set
        .difference(&spec_ids)
        .map(|s| (*s).to_owned())
        .collect();
    let extra: Vec<String> = spec_ids
        .difference(&expected_set)
        .map(|s| (*s).to_owned())
        .collect();
    if !missing.is_empty() || !extra.is_empty() {
        return Err(RegistryMismatch::NotSequential {
            source: source.to_owned(),
            missing,
            extra,
        });
    }
    let registry: BTreeSet<&str> = ids().into_iter().collect();
    let missing: Vec<String> = spec_ids
        .difference(&registry)
        .map(|s| (*s).to_owned())
        .collect();
    let extra: Vec<String> = registry
        .difference(&spec_ids)
        .map(|s| (*s).to_owned())
        .collect();
    if !missing.is_empty() || !extra.is_empty() {
        return Err(RegistryMismatch::RegistryDiffers {
            source: source.to_owned(),
            missing,
            extra,
        });
    }
    for row in &rows {
        if let Some((_, title, _, _)) = ACCEPTANCE_CHECKS.iter().find(|(id, _, _, _)| *id == row.id)
            && *title != row.title
        {
            return Err(RegistryMismatch::TitleDiffers {
                id: row.id.clone(),
                registry: (*title).to_owned(),
                spec: row.title.clone(),
            });
        }
    }
    Ok(rows)
}

/// A dry run over the registry: one line per id, all `UNVERIFIED(stage_not_reached)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DryRun {
    /// One status line per registered check, in registry order.
    pub lines: Vec<StatusLine>,
}

impl DryRun {
    /// Build the dry run.
    pub fn new() -> DryRun {
        DryRun {
            lines: dry_run_lines(),
        }
    }

    /// Number of status lines (must be [`CHECK_COUNT`]).
    pub fn len(&self) -> usize {
        self.lines.len()
    }

    /// True when the dry run is empty (never expected).
    pub fn is_empty(&self) -> bool {
        self.lines.is_empty()
    }

    /// The lines.
    pub fn lines(&self) -> &[StatusLine] {
        &self.lines
    }

    /// The reason code of every line, as written in the report (`stage_not_reached`).
    pub fn all_stage_not_reached(&self) -> bool {
        self.lines.iter().all(|line| {
            line.verdict
                == crate::status::Verdict::Unverified {
                    reason: ReasonCode::StageNotReached,
                }
        })
    }

    /// The ids, in order.
    pub fn ids(&self) -> Vec<&str> {
        self.lines.iter().map(|line| line.id.as_str()).collect()
    }

    /// Verify the dry run covers every id exactly once.
    pub fn validate(&self) -> Result<(), RegistryMismatch> {
        let ids: Vec<&str> = self.ids();
        let unique: BTreeSet<&str> = ids.iter().copied().collect();
        if unique.len() != ids.len() {
            return Err(RegistryMismatch::NoRows {
                source: "dry run".to_owned(),
            });
        }
        let expected: BTreeSet<String> = expected_ids().into_iter().collect();
        let got: BTreeSet<String> = ids.iter().map(|s| (*s).to_owned()).collect();
        let missing: Vec<String> = expected.difference(&got).cloned().collect();
        let extra: Vec<String> = got.difference(&expected).cloned().collect();
        if !missing.is_empty() || !extra.is_empty() {
            return Err(RegistryMismatch::NotSequential {
                source: "dry run".to_owned(),
                missing,
                extra,
            });
        }
        Ok(())
    }
}

impl Default for DryRun {
    fn default() -> DryRun {
        DryRun::new()
    }
}

#[cfg(test)]
mod tests;
