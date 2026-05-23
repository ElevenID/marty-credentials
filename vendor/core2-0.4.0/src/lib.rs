#![allow(dead_code)]

// Workspace compatibility shim:
// this self-host/server build always targets a standard Linux environment,
// so re-exporting std::error and std::io is sufficient for the dependency
// graph that expects the core2 crate to exist.
pub use std::error as error;
pub use std::io as io;
