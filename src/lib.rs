//! Drakkar — static MITRE ATT&CK for Mobile detection on Android APKs.
//!
//! Pipeline: LIEF (DEX/ELF/manifest) -> CFG inter-proc -> matching MITRE
//!           -> export NetworkX (pour APKolgomorov) + candidats Kharon.

pub mod model;
pub mod parser;
pub mod cfg;
pub mod rules;
pub mod export;
pub mod kharon;
