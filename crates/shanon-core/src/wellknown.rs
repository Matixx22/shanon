//! Deprecated compatibility predicates.
//!
//! These are thin queries over `shanon.catalog` (the `CATALOG` table,
//! `classify_sid`, and the derived `_CORE_CANONICAL_NAMES` set). The catalog
//! itself is module 5 and lands in **P1**, so the catalog-derived facts are
//! abstracted behind [`WellKnownCatalog`]. This module implements the *normalization*
//! logic that wraps those queries (strip / casefold / lowercasing / `str(rid)`),
//! which is the only non-catalog behavior here.
//!
//! When `core::catalog` is implemented, it implements [`WellKnownCatalog`] and these
//! predicates keep working unchanged.

use crate::casefold::casefold;

/// The catalog-derived facts `wellknown` needs. Implemented by `core::catalog`
/// in P1; unit-tested here against a fake built from the committed ground-truth fixtures.
pub trait WellKnownCatalog {
    /// `classify_sid(sid) is PrivacyClass.CORE_GLOBAL_DEFAULT`.
    fn sid_is_core_global_default(&self, sid: &str) -> bool;

    /// Membership test against `_CORE_CANONICAL_NAMES` (values are stored folded).
    /// `folded_name` has already been `strip().casefold()`ed by the caller.
    fn is_core_canonical_name(&self, folded_name: &str) -> bool;

    /// Whether `rid` (decimal string) is an explicitly cataloged core-domain RID.
    fn is_core_rid(&self, rid: &str) -> bool;

    /// Whether `normalized_guid` (already `strip().lower()`ed) is a baseline-safe
    /// fixed GPO / null GUID.
    fn is_wellknown_guid(&self, normalized_guid: &str) -> bool;
}

/// Return whether `sid` is a baseline-safe full SID.
pub fn is_wellknown_sid(catalog: &dyn WellKnownCatalog, sid: &str) -> bool {
    catalog.sid_is_core_global_default(sid)
}

/// Return whether `name` is an exact canonical core catalog name.
pub fn is_builtin_name(catalog: &dyn WellKnownCatalog, name: &str) -> bool {
    catalog.is_core_canonical_name(&casefold(name.trim()))
}

/// Return whether `rid` is an explicitly cataloged core domain RID.
pub fn is_builtin_rid(catalog: &dyn WellKnownCatalog, rid: i64) -> bool {
    catalog.is_core_rid(&rid.to_string())
}

/// Return whether `guid` is a baseline-safe fixed GPO GUID.
pub fn is_wellknown_guid(catalog: &dyn WellKnownCatalog, guid: &str) -> bool {
    catalog.is_wellknown_guid(&guid.trim().to_lowercase())
}
