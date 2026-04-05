//! Range normalization for seccomp codegen.
//!
//! The parser and resolver produce a flat list of syscall rules, but the BPF
//! emitter wants something more regular:
//!
//! - one ordered representation per syscall number
//! - explicit precedence between unconditional and conditional rules
//! - gap-free coverage from `0..=MAX_SYSCALL_NR`
//! - adjacent unconditional regions merged into larger spans
//!
//! This module performs that translation once up front so the reverse-emission
//! stage can focus on tree construction and jump layout instead of repeatedly
//! re-deriving rule precedence and default-action gaps while emitting code.
//!
//! In practice this is useful because it separates two different concerns:
//! policy semantics live here, while instruction scheduling lives in
//! `reverse.rs`. That keeps the codegen logic smaller and makes the invariants
//! around merging, fallback behavior, and full syscall-space coverage testable
//! without having to inspect raw BPF output.

use std::collections::BTreeMap;

use crate::resolve::{Action, Expr, Policy};

use super::MAX_SYSCALL_NR;

/// A conditional mapping: expression -> action, with a catch-all fallback.
#[derive(Debug, Clone)]
pub(super) struct ConditionalMapping<'a> {
    pub(super) expr: &'a Expr,
    pub(super) action: Action,
}

/// What a range does: either a simple unconditional action or a list of
/// conditional expression-to-action mappings with a fallback.
#[derive(Debug, Clone)]
pub(super) enum RangeAction<'a> {
    Unconditional(Action),
    Conditional {
        mappings: Vec<ConditionalMapping<'a>>,
        fallback: Action,
    },
}

/// A normalized syscall range covering a contiguous block of syscall numbers.
#[derive(Debug, Clone)]
pub(super) struct SyscallRange<'a> {
    pub(super) first: u32,
    pub(super) last: u32,
    pub(super) action: RangeAction<'a>,
}

#[derive(Default)]
struct SyscallActions<'a> {
    unconditional: Option<Action>,
    conditionals: Vec<ConditionalMapping<'a>>,
}

/// Normalize resolved entries into a gap-free, sorted list of ranges covering
/// `[0, MAX_SYSCALL_NR]`.
pub(super) fn normalize_ranges<'a>(policy: &'a Policy) -> Vec<SyscallRange<'a>> {
    if policy.entries.is_empty() {
        return vec![default_range(0, MAX_SYSCALL_NR, &policy.default_action)];
    }

    let per_syscall = group_syscalls(policy);
    let merged = merge_adjacent_unconditional(
        per_syscall
            .into_iter()
            .map(|(nr, actions)| to_range(nr, actions, &policy.default_action))
            .collect(),
    );
    fill_gaps(merged, &policy.default_action)
}

fn group_syscalls<'a>(policy: &'a Policy) -> BTreeMap<u32, SyscallActions<'a>> {
    let mut grouped = BTreeMap::new();

    for entry in &policy.entries {
        let actions = grouped
            .entry(entry.syscall_number)
            .or_insert_with(SyscallActions::default);
        match entry.filter.as_ref() {
            Some(expr) => actions.conditionals.push(ConditionalMapping {
                expr,
                action: entry.action.clone(),
            }),
            None if actions.unconditional.is_none() => {
                actions.unconditional = Some(entry.action.clone());
            }
            None => {}
        }
    }

    grouped
}

fn to_range<'a>(
    syscall_number: u32,
    actions: SyscallActions<'a>,
    default_action: &Action,
) -> SyscallRange<'a> {
    let action = if actions.conditionals.is_empty() {
        RangeAction::Unconditional(
            actions
                .unconditional
                .unwrap_or_else(|| default_action.clone()),
        )
    } else {
        RangeAction::Conditional {
            mappings: actions.conditionals,
            fallback: actions
                .unconditional
                .unwrap_or_else(|| default_action.clone()),
        }
    };

    SyscallRange {
        first: syscall_number,
        last: syscall_number,
        action,
    }
}

fn merge_adjacent_unconditional<'a>(ranges: Vec<SyscallRange<'a>>) -> Vec<SyscallRange<'a>> {
    let mut merged = Vec::with_capacity(ranges.len());
    for range in ranges {
        push_range(&mut merged, range);
    }
    merged
}

fn fill_gaps<'a>(merged: Vec<SyscallRange<'a>>, default_action: &Action) -> Vec<SyscallRange<'a>> {
    if merged.is_empty() {
        return vec![default_range(0, MAX_SYSCALL_NR, default_action)];
    }

    let mut filled = Vec::with_capacity(merged.len() * 2 + 1);
    let mut next_syscall = 0;

    for range in merged {
        if next_syscall < range.first {
            push_range(
                &mut filled,
                default_range(next_syscall, range.first - 1, default_action),
            );
        }
        next_syscall = range.last + 1;
        push_range(&mut filled, range);
    }

    if next_syscall <= MAX_SYSCALL_NR {
        push_range(
            &mut filled,
            default_range(next_syscall, MAX_SYSCALL_NR, default_action),
        );
    }

    filled
}

fn default_range<'a>(first: u32, last: u32, default_action: &Action) -> SyscallRange<'a> {
    SyscallRange {
        first,
        last,
        action: RangeAction::Unconditional(default_action.clone()),
    }
}

fn push_range<'a>(ranges: &mut Vec<SyscallRange<'a>>, range: SyscallRange<'a>) {
    if let Some(last) = ranges.last_mut()
        && last.last + 1 == range.first
        && same_unconditional_action(&last.action, &range.action)
    {
        last.last = range.last;
        return;
    }
    ranges.push(range);
}

fn same_unconditional_action<'a>(lhs: &RangeAction<'a>, rhs: &RangeAction<'a>) -> bool {
    matches!(
        (lhs, rhs),
        (RangeAction::Unconditional(a), RangeAction::Unconditional(b)) if a == b
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resolve::PolicyEntry;

    fn entry(syscall_number: u32, action: Action, filter: Option<Expr>) -> PolicyEntry {
        PolicyEntry {
            syscall_number,
            action,
            filter,
        }
    }

    #[test]
    fn empty_policy_becomes_full_default_range() {
        let policy = Policy {
            entries: Vec::new(),
            default_action: Action::Kill,
        };

        let ranges = normalize_ranges(&policy);
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].first, 0);
        assert_eq!(ranges[0].last, MAX_SYSCALL_NR);
        assert!(matches!(
            ranges[0].action,
            RangeAction::Unconditional(Action::Kill)
        ));
    }

    #[test]
    fn adjacent_unconditional_ranges_merge() {
        let policy = Policy {
            entries: vec![
                entry(0, Action::Allow, None),
                entry(1, Action::Allow, None),
                entry(2, Action::Allow, None),
            ],
            default_action: Action::Kill,
        };

        let ranges = normalize_ranges(&policy);
        assert_eq!(ranges[0].first, 0);
        assert_eq!(ranges[0].last, 2);
        assert_eq!(ranges[1].first, 3);
        assert_eq!(ranges[1].last, MAX_SYSCALL_NR);
    }

    #[test]
    fn gaps_are_filled_with_default_action() {
        let policy = Policy {
            entries: vec![entry(0, Action::Allow, None), entry(3, Action::Allow, None)],
            default_action: Action::Kill,
        };

        let ranges = normalize_ranges(&policy);
        assert_eq!(ranges.len(), 4);
        assert_eq!(ranges[0].first, 0);
        assert_eq!(ranges[0].last, 0);
        assert_eq!(ranges[1].first, 1);
        assert_eq!(ranges[1].last, 2);
        assert!(matches!(
            ranges[1].action,
            RangeAction::Unconditional(Action::Kill)
        ));
    }

    #[test]
    fn conditional_syscall_uses_unconditional_fallback() {
        let condition = Expr::BoolConst(true);
        let policy = Policy {
            entries: vec![
                entry(7, Action::Kill, None),
                entry(7, Action::Allow, Some(condition.clone())),
            ],
            default_action: Action::Log,
        };

        let ranges = normalize_ranges(&policy);
        match &ranges[1].action {
            RangeAction::Conditional { mappings, fallback } => {
                assert_eq!(mappings.len(), 1);
                assert_eq!(mappings[0].expr, &condition);
                assert_eq!(mappings[0].action, Action::Allow);
                assert_eq!(*fallback, Action::Kill);
            }
            other => panic!("expected conditional range, got {other:?}"),
        }
    }

    #[test]
    fn conditional_without_unconditional_falls_back_to_policy_default() {
        let policy = Policy {
            entries: vec![entry(9, Action::Allow, Some(Expr::BoolConst(true)))],
            default_action: Action::Trap(1),
        };

        let ranges = normalize_ranges(&policy);
        match &ranges[1].action {
            RangeAction::Conditional { fallback, .. } => {
                assert_eq!(*fallback, Action::Trap(1));
            }
            other => panic!("expected conditional range, got {other:?}"),
        }
    }
}
