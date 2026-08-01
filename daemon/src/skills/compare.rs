//! Classify findings across two sweeps.
//!
//! Pure by design: no I/O, no clock, no daemon state. The caller owns reading
//! the history file; this module owns only the decision, which is where the
//! correctness lives.

use crate::skills::sweep::{ItemKind, SweepRecord, Verdict};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    Reopened,
    New,
    Persisting,
    Changed,
    Resolved,
    Unknown,
}

impl Status {
    pub fn as_str(&self) -> &'static str {
        match self {
            Status::Reopened => "reopened",
            Status::New => "new",
            Status::Persisting => "persisting",
            Status::Changed => "changed",
            Status::Resolved => "resolved",
            Status::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Classified {
    pub status: Status,
    pub kind: ItemKind,
    pub agent: String,
    pub name: String,
    pub path: String,
    pub content_hash: String,
}

/// Identity for hash-based matching and for the resolved set. Content hash
/// alone is not identity: a skill and an MCP config can coincidentally share
/// a hash (an empty file, a common boilerplate stanza), and `ItemKind` is
/// what keeps them from cross-matching. Used everywhere a hash is compared,
/// not just here.
type HashKey = (ItemKind, String);

fn hash_key(kind: ItemKind, hash: &str) -> HashKey {
    (kind, hash.to_string())
}

/// Every `(kind, hash)` that was ever confirmed clean after having been
/// flagged. Needed only for `Reopened`, and derivable from the same NDJSON in
/// one pass.
///
/// Processed record by record, in the caller's chronological order (oldest
/// first). Within one record, this record's flagged and clean hashes are
/// collected separately first, and only compared afterward against hashes
/// flagged in a STRICTLY EARLIER record: a resolution needs an earlier flag
/// and a later clean, so a flagged entry and a clean entry that happen to
/// share a record are simultaneous facts, not a chronology, and the order
/// they were pushed into that record's `examined` vector cannot change the
/// answer.
pub fn resolved_hashes(history: &[SweepRecord]) -> HashSet<HashKey> {
    let mut ever_flagged: HashSet<HashKey> = HashSet::new();
    let mut resolved: HashSet<HashKey> = HashSet::new();

    for rec in history {
        let mut flagged_here: HashSet<HashKey> = HashSet::new();
        let mut clean_here: HashSet<HashKey> = HashSet::new();
        for e in &rec.examined {
            let key = hash_key(e.kind, &e.content_hash);
            match e.verdict {
                Verdict::Flagged | Verdict::Quarantined => {
                    flagged_here.insert(key);
                }
                Verdict::Clean => {
                    clean_here.insert(key);
                }
            }
        }
        // Only hashes flagged in an EARLIER record count: this record's own
        // flagged set is folded in only after this check, below.
        for key in &clean_here {
            if ever_flagged.contains(key) {
                resolved.insert(key.clone());
            }
        }
        ever_flagged.extend(flagged_here);
    }

    resolved
}

fn is_flagged(v: Verdict) -> bool {
    matches!(v, Verdict::Flagged | Verdict::Quarantined)
}

/// Classify `current` against `prior`.
///
/// Matching is two-stage, and both stages carry `ItemKind` alongside the
/// path or hash, so a skill and an MCP config can never cross-match:
///
///   1. Same path, same name, same kind, prior flagged: the same item in
///      place. `Persisting` if the content hash is unchanged, `Changed` if
///      it moved. `name` matters here: `ItemKind::McpConfig` records one
///      row per MCP SERVER, and several servers can share one config file's
///      path, so path and kind alone are not identity for that kind.
///   2. Else same content hash, same kind, same agent, prior flagged, AND
///      the prior entry's own path was not re-examined anywhere in this
///      sweep: the same item at a new path (a rename or a move).
///      `Persisting` - the finding did not go away, it just changed address,
///      and matching by path alone would otherwise split it into an
///      untracked `New` row plus a lost `Unknown` row for the old path.
///      The two extra conditions matter: without the agent check, two
///      agents installing the identical published skill (same content hash,
///      different path - identity otherwise carries no agent component)
///      would look like one item renaming itself into the other. Without
///      the "path not re-examined" check, an item resolved in place (a
///      current entry AT ITS OWN PRIOR PATH, any verdict) could still be
///      stolen by an unrelated current entry elsewhere that merely shares
///      its hash, because that entry's own path already gives a definitive,
///      more specific account of what happened to it.
///   3. Else `previously_resolved` contains `(kind, hash)`: `Reopened`.
///   4. Else: `New`.
///
/// `Reopened` is tested before `New`, because a returning finding is
/// otherwise indistinguishable from a discovery and the fact that a fix did
/// not hold would be lost.
///
/// Every prior flagged entry that step 1 or 2 matches is recorded, by its
/// index into `prior.examined`, in `consumed`. The backward pass below
/// consults ONLY that set to decide whether a prior flagged entry was
/// handled by the forward pass - it never re-derives "handled" with an
/// independent lookup of its own. Two independent lookups using the same
/// broad criteria can disagree about WHICH entry matched WHICH: an
/// unrelated current entry could satisfy the backward pass's existence
/// check without ever being the entry the forward pass actually matched,
/// silently dropping the prior entry with no row at all - neither Resolved
/// nor Unknown. Pairing both passes to the same `consumed` set is what
/// makes that impossible: a prior entry falls through to the backward pass
/// if and only if the forward pass did not actually claim it, and the
/// `Option`-returning match search plus `consumed.insert` below guarantee a
/// prior entry is claimed by at most one current entry and a current entry
/// claims at most one prior entry.
pub fn classify(
    current: &SweepRecord,
    prior: &SweepRecord,
    previously_resolved: &HashSet<HashKey>,
) -> Vec<Classified> {
    let mut out = Vec::new();
    let mut consumed: HashSet<usize> = HashSet::new();

    // Forward pass: everything flagged now.
    for e in current.examined.iter().filter(|e| is_flagged(e.verdict)) {
        let mut matched: Option<(usize, Status)> = None;

        // Stage 1: same path, same name, same kind, prior flagged, not
        // already claimed. `name` is required alongside `path`: a single
        // MCP config file produces one `Examined` row per server, so two
        // different servers can otherwise share `(kind, path)` and falsely
        // match each other.
        for (i, p) in prior.examined.iter().enumerate() {
            if consumed.contains(&i) || p.kind != e.kind || p.path != e.path || p.name != e.name {
                continue;
            }
            if !is_flagged(p.verdict) {
                continue;
            }
            let status = if p.content_hash == e.content_hash {
                Status::Persisting
            } else {
                Status::Changed
            };
            matched = Some((i, status));
            break;
        }

        // Stage 2: same content hash, same kind, same agent, prior flagged,
        // not already claimed, and the prior entry's own path was not
        // re-examined anywhere in this sweep (see the doc comment above).
        // Deliberately no `name` check here, unlike stage 1 and the
        // backward pass below: this stage exists to match renames, and
        // `name` is derived from the path, so requiring it to match would
        // defeat the rename match it exists to perform. The `agent` check
        // instead of `name` is also deliberate and asymmetric with stage 1
        // for the same reason - see the doc comment above for why.
        if matched.is_none() {
            for (i, p) in prior.examined.iter().enumerate() {
                if consumed.contains(&i)
                    || p.kind != e.kind
                    || p.agent != e.agent
                    || p.content_hash != e.content_hash
                {
                    continue;
                }
                if !is_flagged(p.verdict) {
                    continue;
                }
                let path_reexamined = current
                    .examined
                    .iter()
                    .any(|c| c.kind == p.kind && c.path == p.path);
                if path_reexamined {
                    continue;
                }
                matched = Some((i, Status::Persisting));
                break;
            }
        }

        let status = if let Some((i, status)) = matched {
            consumed.insert(i);
            status
        } else if previously_resolved.contains(&hash_key(e.kind, &e.content_hash)) {
            Status::Reopened
        } else {
            Status::New
        };

        out.push(Classified {
            status,
            kind: e.kind,
            agent: e.agent.clone(),
            name: e.name.clone(),
            path: e.path.clone(),
            content_hash: e.content_hash.clone(),
        });
    }

    // Backward pass: everything flagged BEFORE that is not flagged now. This is
    // where resolved and unknown are separated, and the separation is the
    // entire point: resolved demands positive confirmation of examination.
    for (i, p) in prior.examined.iter().enumerate() {
        if !is_flagged(p.verdict) || consumed.contains(&i) {
            // Not flagged, or already claimed by the forward pass above -
            // see `consumed` in the doc comment. This is the only source of
            // truth for "handled"; there is no second, independent check.
            continue;
        }
        // Same path and name only, deliberately - NOT hash. A renamed item
        // that is no longer flagged therefore reports Unknown rather than
        // Resolved, which is a false negative in the safe direction: making
        // this hash-based would risk resolving one item off a different
        // item's clean verdict, exactly the cross-item mistake this module
        // exists to prevent. `name` is required alongside `path` for the
        // same reason as stage 1 above: several MCP servers can share one
        // config file's path, so path and kind alone would let a clean
        // server resolve a still-flagged sibling in the same file.
        let examined_clean = current.examined.iter().any(|e| {
            e.kind == p.kind && e.path == p.path && e.name == p.name && e.verdict == Verdict::Clean
        });
        let status = if examined_clean {
            Status::Resolved
        } else {
            // Skipped this sweep, or absent entirely. Both are unknown: a
            // finding that stopped being checked is not good news.
            Status::Unknown
        };
        out.push(Classified {
            status,
            kind: p.kind,
            agent: p.agent.clone(),
            name: p.name.clone(),
            path: p.path.clone(),
            content_hash: p.content_hash.clone(),
        });
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::skills::sweep::{Examined, ItemKind, Skipped, SkipReason, SweepRecord, Verdict};
    use std::collections::HashSet;

    fn ex(name: &str, hash: &str, verdict: Verdict) -> Examined {
        Examined {
            kind: ItemKind::Skill,
            agent: "claude".into(),
            name: name.into(),
            path: format!("/h/.claude/skills/{name}/SKILL.md"),
            content_hash: hash.into(),
            verdict,
            rule_ids: vec![],
        }
    }

    fn sweep(id: &str, examined: Vec<Examined>, skipped: Vec<Skipped>) -> SweepRecord {
        SweepRecord {
            sweep_id: id.into(),
            started_at_ms: 0,
            finished_at_ms: 1,
            trigger: "periodic".to_string(),
            examined,
            skipped,
        }
    }

    fn status_of<'a>(out: &'a [Classified], name: &str) -> &'a Status {
        &out.iter().find(|c| c.name == name).expect("item present").status
    }

    #[test]
    fn a_first_time_flag_is_new() {
        let prior = sweep("p", vec![], vec![]);
        let cur = sweep("c", vec![ex("a", "h1", Verdict::Flagged)], vec![]);
        let out = classify(&cur, &prior, &HashSet::new());
        assert_eq!(*status_of(&out, "a"), Status::New);
    }

    #[test]
    fn the_same_flag_with_the_same_content_is_persisting() {
        let prior = sweep("p", vec![ex("a", "h1", Verdict::Flagged)], vec![]);
        let cur = sweep("c", vec![ex("a", "h1", Verdict::Flagged)], vec![]);
        let out = classify(&cur, &prior, &HashSet::new());
        assert_eq!(*status_of(&out, "a"), Status::Persisting);
    }

    #[test]
    fn a_flag_whose_content_moved_is_changed_not_persisting() {
        let prior = sweep("p", vec![ex("a", "h1", Verdict::Flagged)], vec![]);
        let cur = sweep("c", vec![ex("a", "h2", Verdict::Flagged)], vec![]);
        let out = classify(&cur, &prior, &HashSet::new());
        assert_eq!(
            *status_of(&out, "a"),
            Status::Changed,
            "a modified flagged skill is a different risk from a static one"
        );
    }

    /// Resolved requires POSITIVE confirmation the item was examined and clean.
    #[test]
    fn a_flag_examined_and_now_clean_is_resolved() {
        let prior = sweep("p", vec![ex("a", "h1", Verdict::Flagged)], vec![]);
        let cur = sweep("c", vec![ex("a", "h1", Verdict::Clean)], vec![]);
        let out = classify(&cur, &prior, &HashSet::new());
        assert_eq!(*status_of(&out, "a"), Status::Resolved);
    }

    /// The whole point of the feature. A flagged item the sweep could not
    /// examine is UNKNOWN, never resolved.
    #[test]
    fn a_flag_that_was_skipped_is_unknown_not_resolved() {
        let prior = sweep("p", vec![ex("a", "h1", Verdict::Flagged)], vec![]);
        let cur = sweep(
            "c",
            vec![],
            vec![Skipped {
                kind: ItemKind::Skill,
                agent: "claude".into(),
                path: "/h/.claude/skills/a/SKILL.md".into(),
                reason: SkipReason::PermissionDenied,
                detail: "EACCES".into(),
            }],
        );
        let out = classify(&cur, &prior, &HashSet::new());
        assert_eq!(*status_of(&out, "a"), Status::Unknown);
    }

    /// An item that simply vanished is also unknown. Absence is not evidence.
    #[test]
    fn a_flag_that_vanished_entirely_is_unknown_not_resolved() {
        let prior = sweep("p", vec![ex("a", "h1", Verdict::Flagged)], vec![]);
        let cur = sweep("c", vec![], vec![]);
        let out = classify(&cur, &prior, &HashSet::new());
        assert_eq!(
            *status_of(&out, "a"),
            Status::Unknown,
            "a finding that stopped being checked is not good news"
        );
    }

    /// Reopened outranks new, or a returning finding looks like a discovery
    /// and the fact that a fix did not hold is lost.
    #[test]
    fn a_flag_that_was_resolved_before_is_reopened_not_new() {
        let prior = sweep("p", vec![], vec![]);
        let cur = sweep("c", vec![ex("a", "h1", Verdict::Flagged)], vec![]);
        let mut resolved = HashSet::new();
        resolved.insert((ItemKind::Skill, "h1".to_string()));
        let out = classify(&cur, &prior, &resolved);
        assert_eq!(*status_of(&out, "a"), Status::Reopened);
    }

    #[test]
    fn resolved_hashes_collects_every_resolution_in_history() {
        let h = vec![
            sweep("1", vec![ex("a", "h1", Verdict::Flagged)], vec![]),
            sweep("2", vec![ex("a", "h1", Verdict::Clean)], vec![]),
        ];
        let set = resolved_hashes(&h);
        assert!(set.contains(&(ItemKind::Skill, "h1".to_string())));
    }

    /// Finding 1: a flagged skill whose directory is renamed between sweeps,
    /// with identical content and still flagged, must be ONE `Persisting`
    /// row, not a `New` row at the new path plus a lost `Unknown` row at the
    /// old one. Matching by content hash after a path miss is what recovers
    /// this, and the backward pass must recognize the old entry as already
    /// handled by that same hash match.
    #[test]
    fn a_renamed_still_flagged_identical_content_skill_is_persisting_once() {
        let mut old_location = ex("a", "h1", Verdict::Flagged);
        old_location.path = "/h/.claude/skills/a-old-name/SKILL.md".into();
        let prior = sweep("p", vec![old_location.clone()], vec![]);

        let mut new_location = ex("a", "h1", Verdict::Flagged);
        new_location.name = "a-renamed".into();
        new_location.path = "/h/.claude/skills/a-renamed/SKILL.md".into();
        let cur = sweep("c", vec![new_location.clone()], vec![]);

        let out = classify(&cur, &prior, &HashSet::new());

        assert_eq!(
            out.len(),
            1,
            "a rename must not split into a New row plus a lost Unknown row"
        );
        assert_eq!(out[0].status, Status::Persisting);
        assert_eq!(out[0].path, new_location.path);
        assert!(
            !out.iter().any(|c| c.path == old_location.path),
            "the old path must not survive as its own row"
        );
    }

    /// Finding 2: `resolved_hashes` must not depend on the order entries
    /// happen to be pushed within a single record. A flagged entry and a
    /// clean entry that share a hash but appear in the SAME record are
    /// simultaneous facts, not a chronology, and must not resolve each other
    /// regardless of which one was pushed first.
    #[test]
    fn resolved_hashes_does_not_depend_on_entry_order_within_a_record() {
        let flagged_entry = ex("a", "h1", Verdict::Flagged);
        let clean_entry = ex("b", "h1", Verdict::Clean);

        let flagged_then_clean = vec![sweep(
            "1",
            vec![flagged_entry.clone(), clean_entry.clone()],
            vec![],
        )];
        let clean_then_flagged = vec![sweep("1", vec![clean_entry, flagged_entry], vec![])];

        let a = resolved_hashes(&flagged_then_clean);
        let b = resolved_hashes(&clean_then_flagged);

        assert_eq!(
            a, b,
            "the same facts in a different Vec order must return the same answer"
        );
        assert!(
            !a.contains(&(ItemKind::Skill, "h1".to_string())),
            "flagged and clean within the SAME record are simultaneous, not a resolution"
        );
    }

    /// Finding 3: content hash alone is not identity. A skill and an MCP
    /// config that coincidentally share a hash must not cross-match, so a
    /// brand-new item is `New`, never `Reopened`, off a different kind's
    /// resolution.
    #[test]
    fn a_hash_match_against_a_different_item_kind_is_new_not_reopened() {
        let prior = sweep("p", vec![], vec![]);
        let cur = sweep("c", vec![ex("a", "h1", Verdict::Flagged)], vec![]);
        let mut resolved = HashSet::new();
        resolved.insert((ItemKind::McpConfig, "h1".to_string()));
        let out = classify(&cur, &prior, &resolved);
        assert_eq!(*status_of(&out, "a"), Status::New);
    }

    /// Regression: a prior flagged item that is genuinely resolved at its
    /// own path must not be silently dropped just because some unrelated
    /// current item happens to share its old content hash. Before the fix,
    /// the backward pass's "handled by the forward pass" check was an
    /// independent existential lookup (kind + (path OR hash), over ALL
    /// current flagged entries) instead of the SAME match the forward pass
    /// actually made. `gadget` sharing `widget`'s old hash was enough to
    /// mark `widget` handled, so `widget` got no row at all - neither
    /// Resolved nor Unknown - while `gadget` was mislabeled `Persisting`
    /// instead of `New`.
    #[test]
    fn a_resolved_item_is_not_dropped_by_an_unrelated_current_entry_sharing_its_hash() {
        let widget = ex("widget", "h1", Verdict::Flagged);
        let prior = sweep("p", vec![widget], vec![]);

        let widget_now_clean = ex("widget", "h1", Verdict::Clean);
        let gadget = ex("gadget", "h1", Verdict::Flagged);
        let cur = sweep("c", vec![widget_now_clean, gadget], vec![]);

        let out = classify(&cur, &prior, &HashSet::new());

        let widget_rows: Vec<_> = out.iter().filter(|c| c.name == "widget").collect();
        assert_eq!(
            widget_rows.len(),
            1,
            "widget must appear exactly once, not vanish: got {widget_rows:?}"
        );
        assert_eq!(widget_rows[0].status, Status::Resolved);
        assert_eq!(
            *status_of(&out, "gadget"),
            Status::New,
            "an unrelated item merely sharing widget's old hash must not inherit Persisting"
        );
    }

    /// The vanished variant of the same regression: this time `widget`'s
    /// own path is not re-examined at all (no clean entry, nothing), so the
    /// only current-sweep evidence is `gadget`, an unrelated item at a
    /// different path installed by a different agent that happens to share
    /// `widget`'s old content hash. `widget` must still surface as
    /// `Unknown`, not be silently absorbed into `gadget`'s row: absence of
    /// its own evidence is not evidence of anything, and a coincidental
    /// hash match from a different agent's item must not stand in for it.
    #[test]
    fn a_vanished_flag_is_unknown_not_absorbed_by_an_unrelated_hash_match() {
        let widget = ex("widget", "h1", Verdict::Flagged);
        let prior = sweep("p", vec![widget], vec![]);

        let mut gadget = ex("gadget", "h1", Verdict::Flagged);
        gadget.agent = "cursor".into();
        let cur = sweep("c", vec![gadget], vec![]);

        let out = classify(&cur, &prior, &HashSet::new());

        assert_eq!(
            *status_of(&out, "widget"),
            Status::Unknown,
            "a vanished flag must not be accounted for by an unrelated item's coincidental hash match"
        );
    }

    /// Completeness property: for a realistic mixed sweep, every single
    /// prior flagged entry must appear in the output exactly once - matched
    /// forward (Persisting/Changed), Resolved, or Unknown. This is the
    /// guarantee the whole module exists to provide, checked generically by
    /// looping over the prior flagged entries rather than a hand-listed set
    /// of names, so it keeps working as the module grows new cases. Renames
    /// (identity keyed by hash, path changes) are deliberately excluded
    /// from this scenario and left to their own dedicated test above,
    /// because a renamed row's path differs from its prior path by design
    /// and would need its own correspondence check, not this one.
    #[test]
    fn every_prior_flagged_entry_appears_exactly_once() {
        // Persisting: same path, same hash, still flagged.
        let persisting = ex("persisting-item", "hash-persist", Verdict::Flagged);
        // Changed: same path, flagged, but the content hash moved.
        let changed_prior = ex("changed-item", "hash-changed-old", Verdict::Flagged);
        let mut changed_current = ex("changed-item", "hash-changed-new", Verdict::Flagged);
        changed_current.path = changed_prior.path.clone();
        // Resolved: same path, now Clean.
        let resolved_prior = ex("resolved-item", "hash-resolved", Verdict::Flagged);
        let resolved_current = ex("resolved-item", "hash-resolved", Verdict::Clean);
        // Unknown: absent from the current sweep entirely.
        let unknown_item = ex("unknown-item", "hash-unknown", Verdict::Flagged);
        // The regression pairing: collision-item is genuinely resolved at
        // its own path; collision-gadget is an unrelated, different-agent
        // item that coincidentally shares collision-item's old hash.
        let collision_item = ex("collision-item", "hash-collision", Verdict::Flagged);
        let collision_item_now_clean = ex("collision-item", "hash-collision", Verdict::Clean);
        let mut collision_gadget = ex("collision-gadget", "hash-collision", Verdict::Flagged);
        collision_gadget.agent = "cursor".into();
        // A brand-new current item with no prior counterpart at all.
        let brand_new = ex("brand-new-item", "hash-brand-new", Verdict::Flagged);

        let prior = sweep(
            "p",
            vec![
                persisting.clone(),
                changed_prior,
                resolved_prior,
                unknown_item,
                collision_item,
            ],
            vec![],
        );
        let cur = sweep(
            "c",
            vec![
                persisting,
                changed_current,
                resolved_current,
                collision_item_now_clean,
                collision_gadget,
                brand_new,
            ],
            vec![],
        );

        let out = classify(&cur, &prior, &HashSet::new());

        let prior_flagged: Vec<&Examined> = prior
            .examined
            .iter()
            .filter(|p| matches!(p.verdict, Verdict::Flagged | Verdict::Quarantined))
            .collect();
        assert!(
            !prior_flagged.is_empty(),
            "the scenario must actually exercise prior flagged entries"
        );

        for p in prior_flagged {
            let matches: Vec<&Classified> = out
                .iter()
                .filter(|c| c.kind == p.kind && c.path == p.path)
                .collect();
            assert_eq!(
                matches.len(),
                1,
                "prior flagged entry {:?} at {:?} must appear exactly once, got {:?}",
                p.name,
                p.path,
                matches
            );
        }
    }

    /// M1 mutation guard: the backward pass's `examined_clean` check must
    /// match by PATH, never by hash alone. `widget` (flagged at `/a`, hash
    /// `h1`) vanishes from the current sweep; the only current entry is a
    /// same-kind, same-name Clean decoy at a DIFFERENT path (`/b`) that
    /// merely happens to share `widget`'s old content hash. Kind and name
    /// are held equal deliberately, so this isolates exactly the path-vs-
    /// hash axis: a fix that requires `name` too (see Part B below) would
    /// otherwise mask a hash-based `path` regression by accident, when what
    /// actually makes `/a`'s `widget` and `/b`'s `widget` different items is
    /// that they were examined at different paths. Unlike the existing
    /// hash-collision tests above (which use a FLAGGED decoy the backward
    /// pass never even looks at, because it only inspects Clean entries),
    /// this decoy is Clean - the one shape that could actually satisfy a
    /// hash-based `examined_clean` and produce a false `Resolved`.
    #[test]
    fn a_vanished_flag_is_unknown_not_resolved_by_a_clean_decoy_sharing_its_hash() {
        let mut widget = ex("widget", "h1", Verdict::Flagged);
        widget.path = "/a".into();
        let prior = sweep("p", vec![widget], vec![]);

        let mut decoy = ex("widget", "h1", Verdict::Clean);
        decoy.path = "/b".into();
        let cur = sweep("c", vec![decoy], vec![]);

        let out = classify(&cur, &prior, &HashSet::new());

        assert_eq!(
            out.len(),
            1,
            "widget must appear exactly once even with a same-named decoy at a different path"
        );
        assert_eq!(
            *status_of(&out, "widget"),
            Status::Unknown,
            "a Clean decoy at a different path must not resolve widget off a shared hash alone"
        );
    }

    /// M2 mutation guard: the `consumed` guard is what stops a single prior
    /// flagged entry from being claimed by two different current entries.
    /// Prior has one flagged entry, `x` at `/x` hash `h1`; `x`'s own path is
    /// absent from the current sweep, so only stage 2 (hash fallback) can
    /// match it. Current has TWO flagged entries, `y` and `z`, both at
    /// different paths but both sharing `x`'s hash and agent. Only one of
    /// them may legitimately inherit `x`'s `Persisting` status; the other
    /// must fall through to `New`. Without the guard, both claim it.
    #[test]
    fn a_single_prior_entry_cannot_be_claimed_by_two_current_entries() {
        let mut x = ex("x", "h1", Verdict::Flagged);
        x.path = "/x".into();
        let prior = sweep("p", vec![x], vec![]);

        let mut y = ex("y", "h1", Verdict::Flagged);
        y.path = "/y".into();
        let mut z = ex("z", "h1", Verdict::Flagged);
        z.path = "/z".into();
        let cur = sweep("c", vec![y, z], vec![]);

        let out = classify(&cur, &prior, &HashSet::new());

        assert_eq!(
            *status_of(&out, "y"),
            Status::Persisting,
            "y is the first current entry, so it legitimately claims x"
        );
        assert_eq!(
            *status_of(&out, "z"),
            Status::New,
            "x is already consumed by y; z must not also inherit Persisting from the same prior entry"
        );
    }

    /// M3 mutation guard: `is_flagged` must treat `Quarantined` exactly like
    /// `Flagged`. A prior `Quarantined` entry that vanishes from the current
    /// sweep must still produce a row (Unknown, since absence is not
    /// evidence) - not disappear with zero rows, the same silent-drop shape
    /// as the round-1 regression this module was built to prevent. No
    /// existing test used `Verdict::Quarantined` before this one, even
    /// though the completeness test's own filter names it.
    #[test]
    fn a_quarantined_prior_entry_that_vanishes_still_produces_an_unknown_row() {
        let widget = ex("widget", "h1", Verdict::Quarantined);
        let prior = sweep("p", vec![widget], vec![]);
        let cur = sweep("c", vec![], vec![]);

        let out = classify(&cur, &prior, &HashSet::new());

        assert_eq!(
            out.len(),
            1,
            "a vanished Quarantined entry must still produce exactly one row, not zero"
        );
        assert_eq!(*status_of(&out, "widget"), Status::Unknown);
    }

    /// Part B regression: `ItemKind::McpConfig` records one `Examined` row
    /// per MCP SERVER, so several servers can share one config file's
    /// `path`. Before the fix, stage 1 and `examined_clean` treated
    /// `(kind, path)` as identity and ignored `name`, so a clean
    /// re-examination of `srvA` at `/cfg` could satisfy the backward pass's
    /// clean-check for `srvB` too (same path, different name) - producing a
    /// false `Resolved` for `srvB` even though `srvB`'s own current entry
    /// was still `Flagged`, with `srvB` appearing twice under contradictory
    /// statuses (`Changed` from a wrongful stage-1 match against `srvA`,
    /// AND `Resolved` from the backward pass). With `name` required
    /// alongside `path`, `srvB` matches only its own prior entry.
    #[test]
    fn two_mcp_servers_in_one_config_file_do_not_cross_match_by_path() {
        fn mcp(name: &str, hash: &str, verdict: Verdict) -> Examined {
            Examined {
                kind: ItemKind::McpConfig,
                agent: "claude".into(),
                name: name.into(),
                path: "/cfg".into(),
                content_hash: hash.into(),
                verdict,
                rule_ids: vec![],
            }
        }

        let prior = sweep(
            "p",
            vec![
                mcp("srvA", "h1", Verdict::Flagged),
                mcp("srvB", "h2", Verdict::Flagged),
            ],
            vec![],
        );
        let cur = sweep(
            "c",
            vec![
                mcp("srvA", "h9", Verdict::Clean),
                mcp("srvB", "h2", Verdict::Flagged),
            ],
            vec![],
        );

        let out = classify(&cur, &prior, &HashSet::new());

        let srv_b_rows: Vec<&Classified> = out.iter().filter(|c| c.name == "srvB").collect();
        assert_eq!(
            srv_b_rows.len(),
            1,
            "srvB must appear exactly once, not once Changed and once falsely Resolved: got {srv_b_rows:?}"
        );
        assert_eq!(
            srv_b_rows[0].status,
            Status::Persisting,
            "srvB is unchanged and still flagged - it must be Persisting"
        );
        assert!(
            !out.iter().any(|c| c.name == "srvB" && c.status == Status::Resolved),
            "srvB is still flagged in the current sweep; it must never be reported Resolved"
        );

        let srv_a_rows: Vec<&Classified> = out.iter().filter(|c| c.name == "srvA").collect();
        assert_eq!(
            srv_a_rows.len(),
            1,
            "srvA must also appear exactly once, genuinely Resolved: got {srv_a_rows:?}"
        );
        assert_eq!(srv_a_rows[0].status, Status::Resolved);
    }

    /// Accounting-identity property test. Over a deliberately
    /// collision-dense domain (2 kinds x 2 agents x 2 paths x 2 hashes, 0 to
    /// 3 entries per sweep, all three verdicts, duplicates allowed), every
    /// generated (prior, current) pair must satisfy:
    ///
    ///   - `#Persisting + #Changed + #Resolved + #Unknown == #prior_flagged`
    ///   - `#rows == #current_flagged + #backward_rows`
    ///   - every `Resolved` row has a current entry with the same kind, the
    ///     same path, and `Verdict::Clean`
    ///   - no backward row (`Resolved` or `Unknown`) names an item that was
    ///     not flagged in the prior sweep
    ///
    /// This is the property that killed M1, M2, and M3 above on its own: a
    /// hash-based `examined_clean` (M1) breaks the third bullet; a missing
    /// `consumed` guard (M2) breaks the first bullet by double-counting one
    /// prior entry as `Persisting` twice; and dropping `Quarantined` from
    /// `is_flagged` (M3) breaks both the first and second bullets by
    /// silently excluding quarantined entries from every count.
    ///
    /// Pseudo-random generation uses a small fixed-seed LCG rather than a
    /// new dependency, so the run is deterministic and reproducible.
    #[test]
    fn accounting_identity_holds_under_random_collision_dense_inputs() {
        struct Lcg(u64);
        impl Lcg {
            fn next_u64(&mut self) -> u64 {
                // Constants from Numerical Recipes; any full-period LCG is
                // fine here, this is test-only pseudo-randomness, not
                // cryptography.
                self.0 = self
                    .0
                    .wrapping_mul(6_364_136_223_846_793_005)
                    .wrapping_add(1_442_695_040_888_963_407);
                self.0
            }
            fn next_range(&mut self, n: u64) -> u64 {
                // Taken from the HIGH bits, deliberately - an LCG's low-order
                // bits have much shorter periods than its high bits (the
                // low k bits cycle with period 2^k), so `% small_n` on the
                // raw low bits is a classic LCG pitfall: it can produce
                // near-degenerate, far-from-uniform sequences for exactly
                // the small moduli used below, silently starving whole
                // regions of this collision-dense domain across the run.
                (self.next_u64() >> 33) % n
            }
        }

        let kinds = [ItemKind::Skill, ItemKind::McpConfig];
        let agents = ["claude", "cursor"];
        let paths = ["/p0", "/p1"];
        let hashes = ["h0", "h1"];
        let verdicts = [Verdict::Flagged, Verdict::Clean, Verdict::Quarantined];

        fn gen_examined(
            rng: &mut Lcg,
            kinds: &[ItemKind; 2],
            agents: &[&str; 2],
            paths: &[&str; 2],
            hashes: &[&str; 2],
            verdicts: &[Verdict; 3],
        ) -> Examined {
            let kind = kinds[rng.next_range(2) as usize];
            let agent = agents[rng.next_range(2) as usize];
            let path_idx = rng.next_range(2) as usize;
            let hash = hashes[rng.next_range(2) as usize];
            let verdict = verdicts[rng.next_range(3) as usize];
            Examined {
                kind,
                agent: agent.to_string(),
                // Deliberately constant, NOT derived from `path_idx`: the
                // domain is 4 independent axes (kind, agent, path, hash), and
                // a name derived from path would make "same name" and "same
                // path" the same signal, masking a path-vs-hash mutation
                // (M1) behind a name check that happens to imply path too.
                name: "item".to_string(),
                path: paths[path_idx].to_string(),
                content_hash: hash.to_string(),
                verdict,
                rule_ids: vec![],
            }
        }

        fn gen_sweep(
            rng: &mut Lcg,
            id: &str,
            kinds: &[ItemKind; 2],
            agents: &[&str; 2],
            paths: &[&str; 2],
            hashes: &[&str; 2],
            verdicts: &[Verdict; 3],
        ) -> SweepRecord {
            let n = rng.next_range(4) as usize; // 0..=3 entries
            let examined = (0..n)
                .map(|_| gen_examined(rng, kinds, agents, paths, hashes, verdicts))
                .collect();
            sweep(id, examined, vec![])
        }

        let mut rng = Lcg(0x9E37_79B9_7F4A_7C15);

        for _ in 0..5000 {
            let prior = gen_sweep(&mut rng, "p", &kinds, &agents, &paths, &hashes, &verdicts);
            let current = gen_sweep(&mut rng, "c", &kinds, &agents, &paths, &hashes, &verdicts);

            let mut populated_resolved: HashSet<HashKey> = HashSet::new();
            for &k in &kinds {
                for &h in &hashes {
                    if rng.next_range(2) == 1 {
                        populated_resolved.insert((k, h.to_string()));
                    }
                }
            }

            for previously_resolved in [HashSet::new(), populated_resolved.clone()] {
                let out = classify(&current, &prior, &previously_resolved);

                let prior_flagged: Vec<&Examined> = prior
                    .examined
                    .iter()
                    .filter(|e| matches!(e.verdict, Verdict::Flagged | Verdict::Quarantined))
                    .collect();
                let current_flagged_count = current
                    .examined
                    .iter()
                    .filter(|e| matches!(e.verdict, Verdict::Flagged | Verdict::Quarantined))
                    .count();

                let persisting = out.iter().filter(|c| c.status == Status::Persisting).count();
                let changed = out.iter().filter(|c| c.status == Status::Changed).count();
                let resolved = out.iter().filter(|c| c.status == Status::Resolved).count();
                let unknown = out.iter().filter(|c| c.status == Status::Unknown).count();
                let backward_rows = resolved + unknown;

                assert_eq!(
                    persisting + changed + resolved + unknown,
                    prior_flagged.len(),
                    "accounting identity broken: prior={:?} current={:?} resolved_set={:?} out={:?}",
                    prior.examined,
                    current.examined,
                    previously_resolved,
                    out
                );
                assert_eq!(
                    out.len(),
                    current_flagged_count + backward_rows,
                    "row count does not split into forward + backward rows: prior={:?} current={:?} out={:?}",
                    prior.examined,
                    current.examined,
                    out
                );
                for row in out.iter().filter(|c| c.status == Status::Resolved) {
                    let has_clean_current = current.examined.iter().any(|e| {
                        e.kind == row.kind && e.path == row.path && e.verdict == Verdict::Clean
                    });
                    assert!(
                        has_clean_current,
                        "Resolved row {row:?} has no matching Clean current entry at its own kind+path: current={:?}",
                        current.examined
                    );
                }
                for row in out
                    .iter()
                    .filter(|c| matches!(c.status, Status::Resolved | Status::Unknown))
                {
                    let was_flagged_in_prior = prior.examined.iter().any(|p| {
                        p.kind == row.kind
                            && p.path == row.path
                            && p.name == row.name
                            && p.content_hash == row.content_hash
                            && p.agent == row.agent
                            && matches!(p.verdict, Verdict::Flagged | Verdict::Quarantined)
                    });
                    assert!(
                        was_flagged_in_prior,
                        "backward row {row:?} does not correspond to a prior flagged entry: prior={:?}",
                        prior.examined
                    );
                }
            }
        }
    }
}
