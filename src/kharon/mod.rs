//! Bridge Kharon (DSE natif) — DÉSACTIVÉ pour le moment.
//!
//! Kharon fait du symbolic execution sur le code natif JNI (.so via angr).
//! Il n'est donc pertinent QUE pour les techniques réalisées en natif — pas
//! pour les apps full-Java (cas majoritaire du stalkerware grand public).
//!
//! Ce module sera réécrit quand on câblera la confirmation dynamique, avec une
//! logique conditionnée à la présence de .so + symboles natifs liés à la
//! technique candidate (et non une confirmation naïve par ID).
//!
//! Module volontairement non déclaré dans lib.rs tant que la logique native
//! n'est pas définie.
