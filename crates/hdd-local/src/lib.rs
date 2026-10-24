//! `hdd-local`: local runtime: supervisor, embedded PostgreSQL manager, local CA, hosts helper, doctor, self-test, local backups.
//!
//! Implemented so far: the embedded PostgreSQL manager ([`pg`], T-0563). The supervisor, the local certificate authority, the
//! hosts helper and `doctor` belong to T-0564 and later.
#![forbid(unsafe_code)]

pub mod pg;
