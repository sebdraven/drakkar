//! Drakkar — static MITRE ATT&CK for Mobile detection on Android APKs.
//!
//! Pipeline: DEX (dex-parser + dex-bytecode) + manifest (AXML) + ELF natif (LIEF)
//!           -> CFG inter-proc -> matching MITRE (catalogue auto-update STIX)
//!           -> export NetworkX (pour APKolgomorov).

pub mod bulk;
pub mod cfg;
pub mod enrich;
pub mod export;
pub mod model;
pub mod parser;
pub mod rules;
