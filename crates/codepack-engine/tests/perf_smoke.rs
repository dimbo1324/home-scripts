//! Large-fixture performance smoke test (`task-checklist.md`'s S9 Verification
//! section), `#[ignore]`-gated per `.ai/project/12-domain-rules.md`'s expectation that
//! heavy tests are opt-in, not part of the default fast suite. Run explicitly with:
//!
//! ```text
//! cargo test -p codepack-engine --release -- --ignored large_fixture
//! ```
//!
//! This test's purpose is "does the full eight-step pipeline complete at ~50k files
//! without falling over" — a quadratic-blowup bug, an unbounded in-memory `Vec` where a
//! stream would do, a pathological per-file syscall count — not precise benchmarking.
//! Neither figure below is a tuned performance SLA: this project has never established
//! one.
//!
//! ## Why it measures two sizes rather than one wall clock
//!
//! It used to assert one number: 50k files under 300s, measured at ~155s on the machine
//! of 2026-07-24. On 2026-09-06 it failed at 317.7s, and answering "is this a bug?" took
//! two more measurements, because a single wall clock cannot tell a quadratic blowup from
//! a slower computer. Those measurements: the *same July commit* took 206.8s on the
//! 2026-09-06 machine — a third of the gap is the hardware — and 5k against 50k scaled
//! 11.3x for a 10x file count, which is linear plus a constant, exactly the shape the
//! test wants to see.
//!
//! So the assertion is now the property the test actually claims to check. Two sizes in
//! one run, on one machine, at one moment: the *ratio* is what detects a blowup, and it
//! detects it on any hardware, including hardware fast enough to hide one under an
//! absolute ceiling. The wall clock stays as a backstop for the case where everything
//! scales politely and is simply unusable.
//!
//! The remaining two thirds of the 2026-09-06 gap are real work this pipeline did not do
//! in July: the detector gained provider signatures, entropy and structural parsing,
//! twenty-one further reports began redacting the content they quote (audit No. 20), and
//! the scan cache key gained a detector fingerprint (No. 19). The archive step, which
//! dominates the profile at 59%, got *faster* over the same period — its writer is
//! buffered now (No. 30).

use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use codepack_core::CancellationToken;
use codepack_core::config::Config;
use codepack_storage::open;

const FILE_COUNT: usize = 50_000;
const SMALL_FILE_COUNT: usize = 5_000;
const FILES_PER_DIR: usize = 200;

/// The most a 10x file count may cost in wall clock before the scaling is called
/// non-linear.
///
/// Linear plus per-run overhead measures 8-12x across every run recorded so far:
/// 2026-07-24 saw 12x (12.9s → 155.0s), and 2026-09-06 saw 11.3x (28.1s → 317.7s) and
/// then 8.2x (30.4s → 249.8s) — different hardware, six weeks of changes, and two runs of
/// one binary an hour apart. A quadratic blowup would show roughly 100x. 20 sits far from
/// every honest measurement and far below the defect, so it neither trips on a noisy run
/// nor lets a real blowup through.
const MAX_SCALING_FACTOR: f64 = 20.0;

/// The backstop: not a target, just "the pipeline has not become unusable".
///
/// Measured on 2026-09-06: 317.7s for 50k files, and 249.8s an hour later for the same
/// binary — a 27% spread between two runs on an idle machine, which is the other reason a
/// single wall clock could never have been the real assertion here. The 2x headroom over
/// the slower of the two is the same rule the original 300s was set by (155.0s measured,
/// 300s allowed); the number moved because both the machine and the workload did, and the
/// ratio check above is now what guards the property this file exists to guard.
const BUDGET: Duration = Duration::from_secs(600);

fn build_fixture(root: &Path, file_count: usize) {
    let mut created = 0usize;
    let mut dir_index = 0usize;
    while created < file_count {
        // Nested a few directories deep (not one flat directory of 50k entries, which
        // some filesystems handle poorly) — `dir_index` fans out `a/b/c`-shaped paths.
        let a = dir_index / 400;
        let b = (dir_index / 20) % 20;
        let c = dir_index % 20;
        let dir = root
            .join(format!("d{a}"))
            .join(format!("d{b}"))
            .join(format!("d{c}"));
        fs::create_dir_all(&dir).unwrap();
        for file_in_dir in 0..FILES_PER_DIR {
            if created >= file_count {
                break;
            }
            fs::write(dir.join(format!("f{file_in_dir}.txt")), "line\n").unwrap();
            created += 1;
        }
        dir_index += 1;
    }
}

/// One export of `file_count` files, returning how long the pipeline itself took.
///
/// The fixture is built outside the timer: generating files measures the filesystem, not
/// codepack, and at 50k it is a large part of the wall clock.
fn timed_export(file_count: usize) -> Duration {
    let source = tempfile::tempdir().unwrap();
    build_fixture(source.path(), file_count);

    let output = tempfile::tempdir().unwrap();
    let db_dir = tempfile::tempdir().unwrap();
    let mut conn = open(&db_dir.path().join("codepack.db")).unwrap();
    let config = Config::default();
    let (tx, _rx) = codepack_core::progress_channel();

    let started = Instant::now();
    let outcome = codepack_engine::run_export(
        &mut conn,
        source.path(),
        output.path(),
        &config,
        &HashMap::new(),
        &tx,
        &CancellationToken::new(),
    )
    .unwrap();
    let elapsed = started.elapsed();

    assert!(outcome.successful, "copy_stats = {:?}", outcome.copy_stats);
    assert_eq!(outcome.copy_stats.errors, 0);
    let primary = outcome
        .archive_result
        .primary_result()
        .expect("a successful run always produces a primary archive result");
    assert!(primary.exists());

    eprintln!("perf_smoke: {file_count} files, elapsed = {elapsed:?}");
    elapsed
}

#[test]
#[ignore = "slow: generates and exports fixtures of 5k and 50k files; run with --ignored"]
fn the_pipeline_scales_linearly_and_stays_usable_at_fifty_thousand_files() {
    // Small first: if the pipeline is broken outright, this says so in half a minute
    // rather than after the large fixture has been generated and exported.
    let small = timed_export(SMALL_FILE_COUNT);
    let large = timed_export(FILE_COUNT);

    let factor = large.as_secs_f64() / small.as_secs_f64();
    eprintln!(
        "perf_smoke: {SMALL_FILE_COUNT} -> {FILE_COUNT} files cost {factor:.1}x \
         (limit {MAX_SCALING_FACTOR:.0}x)"
    );

    assert!(
        factor < MAX_SCALING_FACTOR,
        "a 10x file count cost {factor:.1}x the wall clock ({small:?} -> {large:?}), over \
         the {MAX_SCALING_FACTOR:.0}x limit. That is the shape of a per-file cost that \
         grows with the file count — a quadratic scan, an accumulating Vec, a lookup \
         that walks a list. Profile the eight steps before touching this limit"
    );

    assert!(
        large < BUDGET,
        "export of {FILE_COUNT} files took {large:?}, over the {BUDGET:?} backstop. \
         Scaling is fine (measured {factor:.1}x), so this is a constant-factor \
         problem: the pipeline still finishes, it is simply too slow to use"
    );
}
