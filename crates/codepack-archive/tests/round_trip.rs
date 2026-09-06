mod support;

use std::fs;

use codepack_archive::{
    ArchiveFormat, ArchiveOptions, build_final_archives, extract_zip_safely, restore_archive_set,
};
use codepack_core::CancellationToken;

use support::{make_paths, write_file};

#[test]
fn single_zip_round_trip_reproduces_bytes_paths_and_deflate_compression() {
    let temp = tempfile::tempdir().expect("tempdir");
    let paths = make_paths(temp.path(), "demo");
    fs::create_dir_all(&paths.staging_dir).expect("mkdir staging");

    write_file(&paths.staging_dir, "manifest.json", b"{\"a\":1}");
    write_file(&paths.staging_dir, "README.md", b"# Demo\n");
    write_file(&paths.staging_dir, "demo/src/main.rs", b"fn main() {}\n");
    write_file(&paths.staging_dir, "reports/06_security_scan.json", b"[]");

    let options = ArchiveOptions {
        include_project: true,
        part_limit_bytes: 512 * 1024 * 1024,
        format: ArchiveFormat::Zip,
    };
    let cancel = CancellationToken::new();
    let mut hook_calls = 0u32;
    let result = build_final_archives(&paths, &options, &cancel, &mut |_plan, _predicted| {
        hook_calls += 1;
    })
    .expect("build archives");

    assert!(!result.split);
    assert_eq!(result.archives.len(), 1);
    // 4 fixture files + `27_archive_plan.md`/`.json`, which `build_final_archives`
    // writes into `insights_dir` (`staging_dir/reports` here) *before* its final walk
    // — so the plan report about the archive becomes part of the archive itself, the
    // same multi-pass re-walk behavior legacy relies on (`build.rs` doc comment).
    assert_eq!(result.file_count, 6);
    assert!(hook_calls >= 1);

    let zip_path = &result.archives[0];
    assert!(zip_path.exists());

    let file = fs::File::open(zip_path).expect("open zip");
    let mut archive = zip::ZipArchive::new(file).expect("read zip");
    assert_eq!(archive.len(), 6);
    for index in 0..archive.len() {
        let entry = archive.by_index(index).expect("entry");
        assert_eq!(entry.compression(), zip::CompressionMethod::Deflated);
    }

    let destination = temp.path().join("restored");
    let extracted = extract_zip_safely(zip_path, &destination).expect("extract");
    assert_eq!(extracted, 6);

    for relative in [
        "manifest.json",
        "README.md",
        "demo/src/main.rs",
        "reports/06_security_scan.json",
        "reports/27_archive_plan.md",
        "reports/27_archive_plan.json",
    ] {
        let original = fs::read(paths.staging_dir.join(relative)).expect("read original");
        let restored = fs::read(destination.join(relative)).expect("read restored");
        assert_eq!(original, restored, "byte mismatch for {relative}");
    }
}

fn build_split_fixture() -> (
    tempfile::TempDir,
    codepack_core::ExportPaths,
    codepack_core::ArchiveBuildResult,
) {
    let temp = tempfile::tempdir().expect("tempdir");
    let paths = make_paths(temp.path(), "demo");
    fs::create_dir_all(&paths.staging_dir).expect("mkdir staging");

    write_file(&paths.staging_dir, "reports/x1.json", &vec![b'a'; 20_000]);
    write_file(&paths.staging_dir, "reports/x2.json", &vec![b'b'; 20_000]);
    write_file(&paths.staging_dir, "notes.txt", &vec![b'c'; 10_000]);
    write_file(&paths.staging_dir, "README.md", &vec![b'd'; 10_000]);
    write_file(&paths.staging_dir, "demo/src/lib.rs", &vec![b'e'; 20_000]);
    write_file(&paths.staging_dir, "demo/src/main.rs", &vec![b'f'; 20_000]);

    // Below the 8 MB reserve headroom, so target_bytes clamps to ~50 KB rather than
    // the usual 500 MB planning target (BLUEPRINT §A.8's reserve subtraction).
    let options = ArchiveOptions {
        include_project: true,
        part_limit_bytes: 8 * 1024 * 1024 + 50 * 1024,
        format: ArchiveFormat::Zip,
    };
    let cancel = CancellationToken::new();
    let result = build_final_archives(&paths, &options, &cancel, &mut |_plan, _predicted| {})
        .expect("build archives");
    (temp, paths, result)
}

#[test]
fn split_set_produces_multiple_parts_and_a_parseable_manifest() {
    let (temp, _paths, result) = build_split_fixture();

    assert!(result.split);
    assert!(result.archives.len() > 1, "expected multiple parts");
    for archive in &result.archives {
        let name = archive.file_name().unwrap().to_string_lossy();
        assert!(name.contains("_part_"), "unexpected archive name: {name}");
    }

    let output_dir = result.output_dir.clone().expect("output dir");
    let manifest_path = output_dir.join("ARCHIVE_SET_MANIFEST.json");
    let manifest_text = fs::read_to_string(&manifest_path).expect("read manifest");
    let manifest: serde_json::Value = serde_json::from_str(&manifest_text).expect("parse manifest");
    assert_eq!(manifest["split"], true);
    assert_eq!(
        manifest["archives"]
            .as_array()
            .expect("archives array")
            .len(),
        result.archives.len()
    );

    let instructions_path = output_dir.join("RESTORE_INSTRUCTIONS.md");
    let instructions = fs::read_to_string(&instructions_path).expect("read instructions");
    assert!(instructions.contains("Restore Instructions"));

    drop(temp);
}

#[test]
fn restore_archive_set_round_trip_reproduces_every_file() {
    let (temp, paths, result) = build_split_fixture();
    let output_dir = result.output_dir.clone().expect("output dir");

    let destination = temp.path().join("restored");
    let extracted = restore_archive_set(&output_dir, &destination).expect("restore");
    assert_eq!(extracted, u64::from(result.file_count));

    for relative in [
        "reports/x1.json",
        "reports/x2.json",
        "notes.txt",
        "README.md",
        "demo/src/lib.rs",
        "demo/src/main.rs",
    ] {
        let original = fs::read(paths.staging_dir.join(relative)).expect("read original");
        let restored = fs::read(destination.join(relative)).expect("read restored");
        assert_eq!(original, restored, "byte mismatch for {relative}");
    }
}

#[test]
fn single_zip_exceeding_hard_limit_after_write_falls_back_to_split() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut paths = make_paths(temp.path(), "demo");
    // Keep the plan report outside the staged tree for this test: with a 1-byte
    // planning target (see below), even the tiny `27_archive_plan.md`/`.json` report
    // would otherwise get picked up by the second/third `plan_archive` re-walk and
    // force a split before the single-ZIP path this test targets ever runs.
    paths.insights_dir = temp.path().join("insights_outside_staging");
    fs::create_dir_all(&paths.staging_dir).expect("mkdir staging");
    write_file(&paths.staging_dir, "a.txt", b"");

    // `limit_bytes` (100 bytes) is smaller than any real ZIP container's own
    // local-header + central-directory + EOCD overhead, so a single empty-content
    // file still produces a ZIP that exceeds the hard limit once actually written —
    // deterministic without depending on compression ratios.
    let options = ArchiveOptions {
        include_project: true,
        part_limit_bytes: 100,
        format: ArchiveFormat::Zip,
    };
    let cancel = CancellationToken::new();
    let mut hook_calls = 0u32;
    let result = build_final_archives(&paths, &options, &cancel, &mut |_plan, _predicted| {
        hook_calls += 1;
    })
    .expect("build archives");

    assert_eq!(
        hook_calls, 2,
        "expected on_plan_ready before and after the retry"
    );
    assert!(result.split);
    assert!(
        !paths.final_zip.exists(),
        "oversized single zip must be discarded"
    );
    assert_eq!(result.archives.len(), 1);
    assert_eq!(result.file_count, 1);
}

#[test]
fn precancelled_token_yields_a_partial_not_a_complete_result() {
    let temp = tempfile::tempdir().expect("tempdir");
    let paths = make_paths(temp.path(), "demo");
    fs::create_dir_all(&paths.staging_dir).expect("mkdir staging");
    for index in 0..5 {
        write_file(
            &paths.staging_dir,
            &format!("file_{index}.txt"),
            format!("content {index}").as_bytes(),
        );
    }

    let options = ArchiveOptions {
        include_project: true,
        part_limit_bytes: 512 * 1024 * 1024,
        format: ArchiveFormat::Zip,
    };
    let cancel = CancellationToken::new();
    cancel.cancel();
    let result = build_final_archives(&paths, &options, &cancel, &mut |_plan, _predicted| {
        panic!("on_plan_ready must not be called once the token is already cancelled");
    })
    .expect("build archives");

    assert_eq!(
        result.file_count, 0,
        "a pre-cancelled build must never report the full file count"
    );
}

/// The whole point of recording modes: a script goes into a bundle executable and comes
/// back executable.
///
/// Unix only, because the bits do not exist on Windows — a bundle built there carries no
/// mode to restore, and that is stated rather than hidden. This test is what proves the
/// Linux half, and it runs on the `macos-latest` and `ubuntu-latest` CI legs.
#[cfg(unix)]
#[test]
fn an_executable_file_survives_the_archive_and_comes_back_executable() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("tempdir");
    let paths = make_paths(temp.path(), "demo");
    fs::create_dir_all(&paths.staging_dir).expect("mkdir staging");

    write_file(
        &paths.staging_dir,
        "demo/gradlew",
        b"#!/bin/sh\nexec gradle\n",
    );
    write_file(&paths.staging_dir, "demo/README.md", b"# Demo\n");
    let script = paths.staging_dir.join("demo/gradlew");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod");

    let options = ArchiveOptions {
        include_project: true,
        part_limit_bytes: 512 * 1024 * 1024,
        format: ArchiveFormat::Zip,
    };
    let cancel = CancellationToken::new();
    let result = build_final_archives(&paths, &options, &cancel, &mut |_plan, _predicted| {})
        .expect("build archives");

    let destination = temp.path().join("restored");
    extract_zip_safely(&result.archives[0], &destination).expect("extract");

    let restored_script = destination.join("demo/gradlew");
    let mode = fs::metadata(&restored_script)
        .expect("stat")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o755, "gradlew came back as {mode:o} and cannot run");

    // And an ordinary file is not made executable on the way through.
    let restored_readme = destination.join("demo/README.md");
    let readme_mode = fs::metadata(&restored_readme)
        .expect("stat")
        .permissions()
        .mode();
    assert_eq!(
        readme_mode & 0o111,
        0,
        "README.md came back executable: {readme_mode:o}"
    );
}
