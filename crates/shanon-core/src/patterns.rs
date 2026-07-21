//! Regex construction helpers.
//!
//! `factor_literals` builds an ordered, non-capturing trie regex source string
//! for a list of literal strings. Input order defines alternation precedence.
//! The result contains only escaped literal characters and non-capturing groups;
//! callers supply flags, boundaries, and any surrounding expression.
//!
//! Regex audit (§R2): this module compiles no regex of its own. It only decides
//! single-char overlap under case-insensitive matching (see [`crate::ignorecase`]) and
//! emits escaped literals (see [`crate::textutil::re_escape`]). No
//! lookaround/backreferences are involved, so no `fancy-regex` is needed.

use indexmap::IndexMap;

use crate::ignorecase::chars_overlap_ignorecase;
use crate::textutil::re_escape;

const MAX_FACTOR_FANOUT: usize = 64;
const MAX_FACTOR_BRANCH_DEPTH: i64 = 64;

struct TrieNode {
    /// Insertion order preserved (drives emission order).
    children: IndexMap<char, usize>,
    terminal_rank: Option<i64>,
    min_rank: i64,
    max_rank: i64,
    parent: usize,
    incoming: char,
}

impl TrieNode {
    fn new(parent: usize, incoming: char) -> Self {
        TrieNode {
            children: IndexMap::new(),
            terminal_rank: None,
            min_rank: i64::MAX,
            max_rank: -1,
            parent,
            incoming,
        }
    }
}

fn edges_overlap_ignorecase(node: &TrieNode) -> bool {
    let edges: Vec<char> = node.children.keys().copied().collect();
    for i in 0..edges.len() {
        for j in (i + 1)..edges.len() {
            if chars_overlap_ignorecase(edges[i], edges[j]) {
                return true;
            }
        }
    }
    false
}

fn flat_subtree_source(nodes: &[TrieNode], root: usize) -> String {
    let mut terminals: Vec<(i64, usize)> = Vec::new();
    let mut stack = vec![root];
    while let Some(node_index) = stack.pop() {
        let node = &nodes[node_index];
        if let Some(rank) = node.terminal_rank {
            terminals.push((rank, node_index));
        }
        stack.extend(node.children.values().copied());
    }
    terminals.sort_by_key(|item| item.0);

    let mut sources: Vec<String> = Vec::new();
    for (_, terminal_index) in terminals {
        let mut escaped_reversed: Vec<String> = Vec::new();
        let mut node_index = terminal_index;
        while node_index != root {
            let node = &nodes[node_index];
            escaped_reversed.push(re_escape(&node.incoming.to_string()));
            node_index = node.parent;
        }
        escaped_reversed.reverse();
        sources.push(escaped_reversed.concat());
    }
    format!("(?:{})", sources.join("|"))
}

enum Action {
    Node(usize, i64),
    Text(String),
}

/// Return an ordered, non-capturing trie regex source for `literals`.
pub fn factor_literals(literals: &[&str]) -> String {
    if literals.is_empty() {
        return String::new();
    }

    let mut nodes: Vec<TrieNode> = vec![TrieNode::new(usize::MAX, '\0')];
    for (rank, literal) in literals.iter().enumerate() {
        let rank = rank as i64;
        let mut node_index = 0usize;
        nodes[node_index].min_rank = nodes[node_index].min_rank.min(rank);
        nodes[node_index].max_rank = nodes[node_index].max_rank.max(rank);
        for character in literal.chars() {
            let child_index = match nodes[node_index].children.get(&character) {
                Some(&idx) => idx,
                None => {
                    let idx = nodes.len();
                    nodes[node_index].children.insert(character, idx);
                    nodes.push(TrieNode::new(node_index, character));
                    idx
                }
            };
            node_index = child_index;
            nodes[node_index].min_rank = nodes[node_index].min_rank.min(rank);
            nodes[node_index].max_rank = nodes[node_index].max_rank.max(rank);
        }
        let terminal = nodes[node_index].terminal_rank;
        if terminal.is_none() || rank < terminal.unwrap() {
            nodes[node_index].terminal_rank = Some(rank);
        }
    }

    let mut parts: Vec<String> = Vec::new();
    let mut actions: Vec<Action> = vec![Action::Node(0, 0)];
    while let Some(action) = actions.pop() {
        let (node_index, branch_depth) = match action {
            Action::Text(payload) => {
                parts.push(payload);
                continue;
            }
            Action::Node(node_index, branch_depth) => (node_index, branch_depth),
        };
        let node = &nodes[node_index];

        let fanout = node.children.len();
        let terminal_rank = node.terminal_rank;
        let terminal_rank_is_straddled = terminal_rank.is_some_and(|tr| {
            node.children
                .values()
                .any(|&ci| nodes[ci].min_rank < tr && tr < nodes[ci].max_rank)
        });
        let structural_cutoff =
            fanout > MAX_FACTOR_FANOUT || (fanout > 1 && branch_depth >= MAX_FACTOR_BRANCH_DEPTH);
        if terminal_rank_is_straddled
            || structural_cutoff
            || (fanout > 1 && edges_overlap_ignorecase(node))
        {
            parts.push(flat_subtree_source(&nodes, node_index));
            continue;
        }

        let mut alternatives: Vec<(i64, Option<usize>)> = Vec::new();
        if let Some(tr) = node.terminal_rank {
            alternatives.push((tr, None));
        }
        for &child_index in node.children.values() {
            alternatives.push((nodes[child_index].min_rank, Some(child_index)));
        }
        alternatives.sort_by_key(|item| item.0);

        let grouped = alternatives.len() > 1;
        let mut pending: Vec<Action> = Vec::new();
        if grouped {
            parts.push("(?:".to_string());
        }
        for (index, (_, child_index)) in alternatives.iter().enumerate() {
            if index > 0 {
                pending.push(Action::Text("|".to_string()));
            }
            if let Some(ci) = child_index {
                pending.push(Action::Text(re_escape(&nodes[*ci].incoming.to_string())));
                pending.push(Action::Node(*ci, branch_depth + i64::from(grouped)));
            }
        }
        if grouped {
            pending.push(Action::Text(")".to_string()));
        }
        actions.extend(pending.into_iter().rev());
    }

    parts.concat()
}
