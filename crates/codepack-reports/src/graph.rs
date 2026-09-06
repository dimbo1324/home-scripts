//! The shared internal import/dependency graph, ported from legacy
//! `reports/insights/dependency_graph.py::collect_dependency_graph`. Built **once** and
//! reused by every Group E report that needs it, exactly as legacy's own module
//! structure does: `14_dependency_graph.{md,mmd}` (this graph's own report,
//! [`crate::reports::dependency_graph`]), `16_key_files_report.md`
//! ([`crate::reports::key_files`], for its "imported by N internal files" score
//! boost), and `23_refactoring_opportunities.md` ([`crate::reports::refactoring`], for
//! its inbound/outbound dependency-count signal). `15_architecture_report.md` does
//! **not** consume this graph in legacy either (it only classifies directories into
//! layers by folder-name convention) — reproducing legacy's actual reuse pattern, not
//! every plausible-sounding one.
//!
//! Resolution deliberately uses [`crate::context::Inventory`] membership (a `HashSet`
//! of already-included `relative_path`s) rather than a filesystem `exists()` check:
//! this crate never re-walks the tree (scope boundary, `lib.rs`), and every path this
//! graph could ever resolve to is, by construction, already a member of the same
//! `ExportPlan.included_files` list the report catalog was built from.
//!
//! Three deliberate simplifications from legacy's own implementation, each documented
//! at its call site below: Python imports are extracted with a regex rather than a
//! real `ast.parse` (no Python-AST crate is a justified new dependency for this one
//! heuristic report family); Go import resolution picks the lexicographically **first**
//! matching `.go` file in a package directory for determinism (legacy's own
//! `Path.glob("*.go")` order is filesystem-dependent and not itself a contract worth
//! reproducing bit-for-bit); and every read is bounded by
//! [`crate::text::read_text_unredacted`]'s existing size/binary-sniff limits, including for
//! Python files — legacy's own `_python_edges` reads the raw file unconditionally,
//! ignoring its caller's `max_bytes_per_file` entirely, which this port does not
//! reproduce (an unbounded read is exactly the kind of latent resource risk this
//! crate's existing text-reading convention already guards against everywhere else).

use std::collections::{BTreeMap, BTreeSet, HashSet};

use regex::Regex;

use crate::context::ReportContext;
use crate::reports::dependencies::parse_go_mod;
use crate::text::read_text_unredacted;

const SOURCE_EXTENSIONS: &[&str] = &[
    "py", "js", "jsx", "ts", "tsx", "mjs", "cjs", "vue", "svelte", "astro", "go",
];
const JS_LIKE_EXTENSIONS: &[&str] = &[
    "js", "jsx", "ts", "tsx", "mjs", "cjs", "vue", "svelte", "astro",
];
const JS_RESOLUTION_EXTENSIONS: &[&str] = &[
    "", "ts", "tsx", "js", "jsx", "mjs", "cjs", "vue", "svelte", "astro", "json",
];

/// The internal import graph: `relative_path -> resolved internal targets`. Every
/// file with a [`SOURCE_EXTENSIONS`] extension is a key, even when it has no resolved
/// edges (legacy's own `graph: dict[Path, set[Path]] = {path: set() for path in
/// files}` baseline).
#[derive(Debug, Clone, Default)]
pub struct DependencyGraph {
    pub edges: BTreeMap<String, BTreeSet<String>>,
}

impl DependencyGraph {
    pub fn edge_count(&self) -> usize {
        self.edges.values().map(|targets| targets.len()).sum()
    }

    /// How many internal files import each target — the basis of
    /// `16_key_files_report.md`'s "imported by N internal file(s)" boost and
    /// `14_dependency_graph.md`'s "most imported internal files" section.
    pub fn in_degree(&self) -> BTreeMap<String, usize> {
        let mut counts: BTreeMap<String, usize> = BTreeMap::new();
        for targets in self.edges.values() {
            for target in targets {
                *counts.entry(target.clone()).or_insert(0) += 1;
            }
        }
        counts
    }
}

fn js_import_pattern() -> Regex {
    // Legacy `_JS_IMPORT_RE`, ported verbatim.
    Regex::new(
        r#"(?:from\s+['"]([^'"]+)['"]|import\s*\(\s*['"]([^'"]+)['"]\s*\)|require\s*\(\s*['"]([^'"]+)['"]\s*\))"#,
    )
    .expect("fixed, compile-time-verified literal")
}

fn go_import_pattern() -> Regex {
    // Legacy `_GO_IMPORT_RE`, ported verbatim.
    Regex::new(r#"(?m)^\s*(?:import\s+)?["`]([^"`]+)["`]"#)
        .expect("fixed, compile-time-verified literal")
}

fn python_import_pattern() -> Regex {
    Regex::new(r"(?m)^[ \t]*import\s+([\w.]+(?:\s*,\s*[\w.]+)*)")
        .expect("fixed, compile-time-verified literal")
}

fn python_from_import_pattern() -> Regex {
    Regex::new(r"(?m)^[ \t]*from\s+(\.*)\s*([\w.]*)\s+import\b")
        .expect("fixed, compile-time-verified literal")
}

fn split_segments(relative_path: &str) -> Vec<String> {
    relative_path
        .split('\\')
        .filter(|part| !part.is_empty())
        .map(|part| part.to_string())
        .collect()
}

fn join_segments(segments: &[String]) -> String {
    segments.join("\\")
}

fn resolve_python_module(base_segments: Vec<String>, known: &HashSet<String>) -> Option<String> {
    if base_segments.is_empty() {
        return None;
    }
    let base = join_segments(&base_segments);
    let file_candidate = format!("{base}.py");
    if known.contains(&file_candidate) {
        return Some(file_candidate);
    }
    let init_candidate = format!("{base}\\__init__.py");
    if known.contains(&init_candidate) {
        return Some(init_candidate);
    }
    None
}

/// Legacy `_resolve_python_import` with `level=0`: the module path is joined onto the
/// project root, matching Python's own absolute-import resolution when the project
/// root is on `sys.path`.
fn resolve_python_absolute(module: &str, known: &HashSet<String>) -> Option<String> {
    if module.is_empty() {
        return None;
    }
    let segments: Vec<String> = module.split('.').map(|part| part.to_string()).collect();
    resolve_python_module(segments, known)
}

/// Legacy `_resolve_python_import` with `level >= 1`: `level=1` is "current package"
/// (`current.parent`), each additional level walks one more directory up.
fn resolve_python_relative(
    current_relative_path: &str,
    level: usize,
    module: &str,
    known: &HashSet<String>,
) -> Option<String> {
    let mut segments = split_segments(current_relative_path);
    segments.pop();
    for _ in 0..level.saturating_sub(1) {
        segments.pop();
    }
    if !module.is_empty() {
        segments.extend(module.split('.').map(|part| part.to_string()));
    }
    resolve_python_module(segments, known)
}

fn python_edges(
    current_relative_path: &str,
    text: &str,
    known: &HashSet<String>,
) -> BTreeSet<String> {
    let mut edges = BTreeSet::new();

    for captures in python_import_pattern().captures_iter(text) {
        let Some(list) = captures.get(1) else {
            continue;
        };
        for module in list.as_str().split(',') {
            if let Some(target) = resolve_python_absolute(module.trim(), known) {
                edges.insert(target);
            }
        }
    }

    for captures in python_from_import_pattern().captures_iter(text) {
        let dots = captures.get(1).map(|m| m.as_str()).unwrap_or("");
        let module = captures.get(2).map(|m| m.as_str()).unwrap_or("").trim();
        let level = dots.len();
        let target = if level == 0 {
            resolve_python_absolute(module, known)
        } else {
            resolve_python_relative(current_relative_path, level, module, known)
        };
        if let Some(target) = target {
            edges.insert(target);
        }
    }

    edges
}

fn normalize_js_specifier(current_relative_path: &str, specifier: &str) -> Option<Vec<String>> {
    if !specifier.starts_with('.') {
        return None;
    }
    let mut segments = split_segments(current_relative_path);
    segments.pop();
    for part in specifier.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                segments.pop();
            }
            other => segments.push(other.to_string()),
        }
    }
    Some(segments)
}

fn resolve_js_relative(
    current_relative_path: &str,
    specifier: &str,
    known: &HashSet<String>,
) -> Option<String> {
    let segments = normalize_js_specifier(current_relative_path, specifier)?;
    if segments.is_empty() {
        return None;
    }
    let base = join_segments(&segments);
    for extension in JS_RESOLUTION_EXTENSIONS {
        let candidate = if extension.is_empty() {
            base.clone()
        } else {
            format!("{base}.{extension}")
        };
        if known.contains(&candidate) {
            return Some(candidate);
        }
    }
    for extension in &JS_RESOLUTION_EXTENSIONS[1..] {
        let candidate = format!("{base}\\index.{extension}");
        if known.contains(&candidate) {
            return Some(candidate);
        }
    }
    None
}

fn js_edges(current_relative_path: &str, text: &str, known: &HashSet<String>) -> BTreeSet<String> {
    let mut edges = BTreeSet::new();
    for captures in js_import_pattern().captures_iter(text) {
        let Some(specifier) = captures
            .get(1)
            .or_else(|| captures.get(2))
            .or_else(|| captures.get(3))
            .map(|m| m.as_str())
        else {
            continue;
        };
        if let Some(target) = resolve_js_relative(current_relative_path, specifier, known) {
            edges.insert(target);
        }
    }
    edges
}

/// Picks the lexicographically first `.go` file directly inside `dir_segments`
/// (empty means "the project root") — a documented determinism improvement over
/// legacy's own filesystem-order-dependent `Path.glob("*.go")` (module doc comment).
fn go_edges(module_name: &str, text: &str, known: &HashSet<String>) -> BTreeSet<String> {
    let mut edges = BTreeSet::new();
    if module_name.is_empty() {
        return edges;
    }
    for captures in go_import_pattern().captures_iter(text) {
        let Some(spec) = captures.get(1).map(|m| m.as_str()) else {
            continue;
        };
        let Some(rest) = spec.strip_prefix(module_name) else {
            continue;
        };
        let rest = rest.trim_start_matches('/');
        let dir_segments: Vec<String> = rest
            .split('/')
            .filter(|part| !part.is_empty())
            .map(|part| part.to_string())
            .collect();
        let prefix = if dir_segments.is_empty() {
            String::new()
        } else {
            format!("{}\\", join_segments(&dir_segments))
        };
        let candidate = known
            .iter()
            .filter(|path| {
                path.ends_with(".go")
                    && path.starts_with(&prefix)
                    && path[prefix.len()..].find('\\').is_none()
            })
            .min()
            .cloned();
        if let Some(candidate) = candidate {
            edges.insert(candidate);
        }
    }
    edges
}

/// Builds the internal import graph for every source-language file in
/// `ctx.inventory` — see the module doc comment for the exact set of consumers and
/// the documented simplifications from legacy's own implementation.
pub fn collect(ctx: &ReportContext<'_>) -> DependencyGraph {
    let max_bytes = ctx.config.effective_max_text_file_bytes();
    let known: HashSet<String> = ctx
        .inventory
        .files
        .iter()
        .map(|file| file.relative_path.clone())
        .collect();
    let go_module = read_text_unredacted(&ctx.staging_root.join("go.mod"), None)
        .map(|text| parse_go_mod(&text).0)
        .unwrap_or_default();

    let mut edges: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();

    for file in &ctx.inventory.files {
        if !SOURCE_EXTENSIONS.contains(&file.extension.as_str()) {
            continue;
        }
        let resolved = if file.extension == "py" {
            read_text_unredacted(&ctx.resolve(&file.relative_path), max_bytes)
                .map(|text| python_edges(&file.relative_path, &text, &known))
                .unwrap_or_default()
        } else if !codepack_scanner::should_consider_text_file(&crate::paths::to_native_path(
            &file.relative_path,
        )) {
            BTreeSet::new()
        } else {
            match read_text_unredacted(&ctx.resolve(&file.relative_path), max_bytes) {
                Some(text) if JS_LIKE_EXTENSIONS.contains(&file.extension.as_str()) => {
                    js_edges(&file.relative_path, &text, &known)
                }
                Some(text) if file.extension == "go" => go_edges(&go_module, &text, &known),
                _ => BTreeSet::new(),
            }
        };
        edges.insert(file.relative_path.clone(), resolved);
    }

    DependencyGraph { edges }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::Fixture;

    #[test]
    fn resolves_python_relative_and_absolute_imports() {
        let fixture = Fixture::new(|root| {
            std::fs::create_dir_all(root.join("pkg")).unwrap();
            std::fs::write(root.join("pkg").join("__init__.py"), "").unwrap();
            std::fs::write(root.join("pkg").join("helper.py"), "x = 1\n").unwrap();
            std::fs::write(root.join("utils.py"), "y = 2\n").unwrap();
            std::fs::write(
                root.join("pkg").join("main.py"),
                "import utils\nfrom . import helper\nfrom .helper import thing\n",
            )
            .unwrap();
        });
        let ctx = fixture.context("full");

        let graph = collect(&ctx);
        let main_edges = graph.edges.get("pkg\\main.py").unwrap();
        assert!(main_edges.contains("utils.py"));
        assert!(main_edges.contains("pkg\\helper.py"));
    }

    #[test]
    fn resolves_js_relative_imports_including_index_files() {
        let fixture = Fixture::new(|root| {
            std::fs::create_dir_all(root.join("src").join("components")).unwrap();
            std::fs::write(root.join("src").join("components").join("index.ts"), "").unwrap();
            std::fs::write(
                root.join("src").join("app.ts"),
                "import { Button } from './components';\nimport helper from '../src/helper';\n",
            )
            .unwrap();
            std::fs::write(root.join("src").join("helper.ts"), "").unwrap();
        });
        let ctx = fixture.context("full");

        let graph = collect(&ctx);
        let edges = graph.edges.get("src\\app.ts").unwrap();
        assert!(edges.contains("src\\components\\index.ts"));
    }

    #[test]
    fn resolves_go_imports_from_the_module_name_in_go_mod() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("go.mod"), "module example.com/app\n").unwrap();
            std::fs::create_dir_all(root.join("internal").join("util")).unwrap();
            std::fs::write(
                root.join("internal").join("util").join("util.go"),
                "package util\n",
            )
            .unwrap();
            std::fs::write(
                root.join("main.go"),
                "package main\n\nimport (\n\t\"example.com/app/internal/util\"\n)\n",
            )
            .unwrap();
        });
        let ctx = fixture.context("full");

        let graph = collect(&ctx);
        let edges = graph.edges.get("main.go").unwrap();
        assert!(edges.contains("internal\\util\\util.go"));
    }

    #[test]
    fn in_degree_counts_incoming_edges() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("utils.py"), "").unwrap();
            std::fs::write(root.join("a.py"), "import utils\n").unwrap();
            std::fs::write(root.join("b.py"), "import utils\n").unwrap();
        });
        let ctx = fixture.context("full");

        let graph = collect(&ctx);
        let in_degree = graph.in_degree();
        assert_eq!(in_degree.get("utils.py"), Some(&2));
    }

    #[test]
    fn unresolvable_imports_do_not_panic_and_leave_an_empty_edge_set() {
        let fixture = Fixture::new(|root| {
            std::fs::write(root.join("lonely.py"), "import nonexistent_package\n").unwrap();
        });
        let ctx = fixture.context("full");

        let graph = collect(&ctx);
        assert_eq!(graph.edges.get("lonely.py"), Some(&BTreeSet::new()));
    }
}
