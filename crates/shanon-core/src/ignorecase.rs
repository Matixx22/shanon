//! Unicode case-insensitive single-character equivalence.
//!
//! `patterns::factor_literals` checks whether a case-insensitive match of one
//! single trie-edge character against another character would succeed, to
//! decide whether two edges collide under ignore-case (and therefore whether a
//! node must fall back to flat alternation).
//!
//! A unicode ignore-case single-char match is done by lowering both the pattern
//! and the subject through `getlower` (simple Unicode lowercasing) and, when the
//! lowered pattern char has *extra* case variants, by testing membership in
//! `_EXTRA_CASES`. Two chars therefore overlap iff their
//! simple-lowercased forms are equal, or one's lowered form is in the other's
//! `_EXTRA_CASES` set.
//!
//! Validated exhaustively against the committed ground-truth fixtures over the Latin +
//! Greek + special ranges the tests exercise (`tests/patterns.rs`).

/// `_EXTRA_CASES`, keyed on the (simple-lowered)
/// codepoint. Symmetric and closed.
static EXTRA_CASES: &[(u32, &[u32])] = &[
    (105, &[305]),
    (115, &[383]),
    (181, &[956]),
    (305, &[105]),
    (383, &[115]),
    (837, &[953, 8126]),
    (912, &[8147]),
    (944, &[8163]),
    (946, &[976]),
    (949, &[1013]),
    (952, &[977]),
    (953, &[837, 8126]),
    (954, &[1008]),
    (956, &[181]),
    (960, &[982]),
    (961, &[1009]),
    (962, &[963]),
    (963, &[962]),
    (966, &[981]),
    (976, &[946]),
    (977, &[952]),
    (981, &[966]),
    (982, &[960]),
    (1008, &[954]),
    (1009, &[961]),
    (1013, &[949]),
    (1074, &[7296]),
    (1076, &[7297]),
    (1086, &[7298]),
    (1089, &[7299]),
    (1090, &[7300, 7301]),
    (1098, &[7302]),
    (1123, &[7303]),
    (7296, &[1074]),
    (7297, &[1076]),
    (7298, &[1086]),
    (7299, &[1089]),
    (7300, &[1090, 7301]),
    (7301, &[1090, 7300]),
    (7302, &[1098]),
    (7303, &[1123]),
    (7304, &[42571]),
    (7777, &[7835]),
    (7835, &[7777]),
    (8126, &[837, 953]),
    (8147, &[912]),
    (8163, &[944]),
    (42571, &[7304]),
    (64261, &[64262]),
    (64262, &[64261]),
];

fn extra_cases(lo: u32) -> &'static [u32] {
    // Linear scan over 50 entries — cheap and only hit for multi-edge nodes.
    for (k, v) in EXTRA_CASES {
        if *k == lo {
            return v;
        }
    }
    &[]
}

/// Simple Unicode lowercase used by ignore-case matching (`getlower`). The mapping is
/// 1:1; `char::to_lowercase().next()` matches it across the validated ranges
/// (its only multi-char expansion, `İ`, still yields `i` as the first char,
/// which equals the simple lowercase).
fn re_lower(c: char) -> u32 {
    c.to_lowercase()
        .next()
        .map(|x| x as u32)
        .unwrap_or(c as u32)
}

/// Whether `a` and `b` match each other as single-char literals under
/// `re.IGNORECASE` (unicode).
pub fn chars_overlap_ignorecase(a: char, b: char) -> bool {
    let la = re_lower(a);
    let lb = re_lower(b);
    if la == lb {
        return true;
    }
    extra_cases(la).contains(&lb)
}
