//! Path-traversal-safe ZIP extraction (invariant I7), ported from legacy's bundled
//! `restore_archives.py` script into a library function: `restore_archive_set` reads
//! `ARCHIVE_SET_MANIFEST.json` and extracts every listed part.

use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{ArchiveError, Result};

/// Validates `member_name` lexically and joins it onto `destination`.
///
/// The rule itself is [`codepack_core::safe_join`]; this keeps the archive crate's own
/// name and error for it, because "unsafe archive member path" is what a caller here
/// needs to read. The rule moved down to `codepack-core` when a third caller appeared
/// that is not about archives at all: paths taken from someone else's git tree
/// (audit No. 10).
pub fn safe_member_target(destination: &Path, member_name: &str) -> Result<PathBuf> {
    codepack_core::safe_join(destination, Path::new(member_name)).map_err(|_| {
        ArchiveError::UnsafeMemberPath {
            member: member_name.to_string(),
        }
    })
}

/// What an archive is allowed to expand into.
///
/// ## Why this exists
///
/// `codepack verify` is the one command whose input is untrusted by design — it re-scans
/// a bundle its user *received*. Extraction streamed every member with no ceiling, so an
/// archive of a few kilobytes could expand to fill the disk. Path traversal was already
/// handled; sheer volume was not.
///
/// ## Why the declared size is not the check
///
/// A zip's header states each member's uncompressed size, and that number is written by
/// whoever built the archive — that is, by the attacker. It is used below only as a
/// cheap early refusal. The ceiling that matters is enforced on the bytes actually
/// written, by reading each member through a limited reader.
///
/// The defaults are deliberately generous: a real bundle carries a copy of a project and
/// a full text dump of it, and refusing a legitimate export would be a worse failure
/// than the one being prevented. A caller with a different tolerance passes its own.
#[derive(Debug, Clone, Copy)]
pub struct ExtractLimits {
    /// Across the whole archive.
    pub max_total_bytes: u64,
    /// For any single member.
    pub max_entry_bytes: u64,
    /// Members, of any size. Guards the other shape of the same attack: millions of
    /// empty files, which costs inodes and time rather than bytes.
    pub max_entries: usize,
    /// Path segments in one member's name. A member called `a/a/…/a/f.txt` costs almost
    /// nothing to send and creates an arbitrarily deep tree on disk, which is a stack
    /// overflow in whatever walks it afterwards — `codepack verify` walks it immediately.
    /// Bytes and member counts do not see this shape at all.
    pub max_depth: usize,
}

impl Default for ExtractLimits {
    fn default() -> Self {
        Self {
            max_total_bytes: 8 * 1024 * 1024 * 1024,
            max_entry_bytes: 2 * 1024 * 1024 * 1024,
            max_entries: 200_000,
            // Deeper than any real project. The deepest thing a bundle legitimately
            // carries is a `node_modules` tree, and those are tens of levels, not
            // hundreds.
            max_depth: 64,
        }
    }
}

impl ExtractLimits {
    fn exceeded(archive: &Path, limit: &'static str, allowed: String) -> ArchiveError {
        ArchiveError::ExtractionTooLarge {
            archive: archive.to_path_buf(),
            limit,
            allowed,
        }
    }

    fn budget(self) -> ExtractBudget {
        ExtractBudget {
            limits: self,
            spent_bytes: 0,
            spent_entries: 0,
        }
    }
}

/// What an [`ExtractLimits`] has left, carried **across** archives.
///
/// A split bundle is one logical archive delivered as many files, so its budget has to
/// be one too. Extracting each part with a fresh `ExtractLimits::default()` meant a
/// 50-part set could expand to 400 GiB with every individual call comfortably "within
/// budget" — the zip-bomb ceiling simply did not apply to the composite form.
#[derive(Debug)]
struct ExtractBudget {
    limits: ExtractLimits,
    spent_bytes: u64,
    spent_entries: usize,
}

impl ExtractBudget {
    /// Claims `count` members up front, before anything is read.
    fn take_entries(&mut self, archive: &Path, count: usize) -> Result<()> {
        self.spent_entries = self.spent_entries.saturating_add(count);
        if self.spent_entries > self.limits.max_entries {
            return Err(ExtractLimits::exceeded(
                archive,
                "member-count",
                self.limits.max_entries.to_string(),
            ));
        }
        Ok(())
    }

    /// Charges bytes actually written to disk — never a size a header claimed.
    fn take_bytes(&mut self, archive: &Path, written: u64) -> Result<()> {
        self.spent_bytes = self.spent_bytes.saturating_add(written);
        if self.spent_bytes > self.limits.max_total_bytes {
            return Err(ExtractLimits::exceeded(
                archive,
                "total-size",
                self.limits.max_total_bytes.to_string(),
            ));
        }
        Ok(())
    }
}

/// [`extract_zip_safely`] with a caller-chosen budget.
pub fn extract_zip_with_limits(
    archive_path: &Path,
    destination: &Path,
    limits: ExtractLimits,
) -> Result<u64> {
    extract_zip_inner(archive_path, destination, &mut limits.budget())
}

/// Extracts every entry of `archive_path` into `destination`, streaming file contents
/// rather than loading whole files into memory. Every entry is checked by **both**
/// `ZipFile::enclosed_name()` (the `zip` crate's own path-safety accessor) and the
/// independent lexical `safe_member_target` check; if either rejects an entry, the
/// whole extraction aborts immediately with an error — fail-closed, matching legacy's
/// abort-on-first-bad-entry behavior rather than skip-and-continue. A legitimate entry
/// written earlier in the same archive, before the bad one, stays on disk: this is the
/// honest, ported partial-write-before-abort behavior, not a gap.
pub fn extract_zip_safely(archive_path: &Path, destination: &Path) -> Result<u64> {
    extract_zip_inner(
        archive_path,
        destination,
        &mut ExtractLimits::default().budget(),
    )
}

fn extract_zip_inner(
    archive_path: &Path,
    destination: &Path,
    budget: &mut ExtractBudget,
) -> Result<u64> {
    let file = std::fs::File::open(archive_path).map_err(|source| ArchiveError::Read {
        path: archive_path.to_path_buf(),
        source,
    })?;
    let mut archive = zip::ZipArchive::new(file).map_err(|source| ArchiveError::Zip {
        path: archive_path.to_path_buf(),
        source,
    })?;
    std::fs::create_dir_all(destination).map_err(|source| ArchiveError::Write {
        path: destination.to_path_buf(),
        source,
    })?;

    budget.take_entries(archive_path, archive.len())?;

    let limits = budget.limits;
    // Counted as `u64` and added saturatingly: a member count is bounded by the budget,
    // but the arithmetic should not be the thing that decides that. An overflow here is
    // a panic in debug and a wrong answer in release.
    let mut extracted = 0u64;
    for index in 0..archive.len() {
        let mut zip_entry = archive
            .by_index(index)
            .map_err(|source| ArchiveError::Zip {
                path: archive_path.to_path_buf(),
                source,
            })?;
        let member_name = zip_entry.name().to_string();

        if Path::new(&member_name).components().count() > limits.max_depth {
            return Err(ExtractLimits::exceeded(
                archive_path,
                "member-depth",
                limits.max_depth.to_string(),
            ));
        }

        let enclosed_name = zip_entry.enclosed_name();
        let safe_target = safe_member_target(destination, &member_name);
        let target = match (enclosed_name, safe_target) {
            (Some(_), Ok(target)) => target,
            _ => {
                return Err(ArchiveError::UnsafeMemberPath {
                    member: member_name,
                });
            }
        };

        if zip_entry.is_dir() {
            std::fs::create_dir_all(&target).map_err(|source| ArchiveError::Write {
                path: target.clone(),
                source,
            })?;
            continue;
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent).map_err(|source| ArchiveError::Write {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        // The header's own claim, used only to refuse early. It is written by whoever
        // built the archive, so it is never the check that matters.
        if zip_entry.size() > limits.max_entry_bytes {
            return Err(ExtractLimits::exceeded(
                archive_path,
                "per-member",
                limits.max_entry_bytes.to_string(),
            ));
        }

        let mut output = std::fs::File::create(&target).map_err(|source| ArchiveError::Write {
            path: target.clone(),
            source,
        })?;
        // Read one byte past the ceiling: if the member yields it, the member is over the
        // limit however its header described itself.
        let allowance = limits.max_entry_bytes.saturating_add(1);
        let written = std::io::copy(
            &mut std::io::Read::take(&mut zip_entry, allowance),
            &mut output,
        )
        .map_err(|source| ArchiveError::Write {
            path: target.clone(),
            source,
        })?;
        if written > limits.max_entry_bytes {
            return Err(ExtractLimits::exceeded(
                archive_path,
                "per-member",
                limits.max_entry_bytes.to_string(),
            ));
        }
        budget.take_bytes(archive_path, written)?;
        extracted = extracted.saturating_add(1);
    }

    Ok(extracted)
}

#[derive(Deserialize)]
struct ArchiveSetManifest {
    archives: Vec<String>,
}

/// How many parts one split bundle may claim to have.
///
/// The parts are listed in a manifest written by whoever produced the bundle, so the
/// count is their number, not ours. A real split set is tens of parts: `build_final_archives`
/// splits at a configured part size, and 4096 parts of even the smallest sensible size
/// is far beyond any bundle a person actually hands over. The cap exists so a manifest
/// cannot make this function open an unbounded number of files before the byte budget
/// has anything to say.
const MAX_ARCHIVE_SET_PARTS: usize = 4096;

/// Reads `ARCHIVE_SET_MANIFEST.json` inside `archive_set_dir` and extracts every listed
/// part (in manifest order) into `destination`, returning the total file count across
/// all parts.
///
/// ## The manifest is untrusted input
///
/// Every caller of this function — `codepack verify`, `handoff`, and the desktop's
/// bundle viewer — is looking at a bundle that arrived from somewhere else. The names in
/// `archives` are therefore strings from a stranger, and `Path::join` with an absolute
/// path discards the base entirely: an entry of `C:/Users/victim/secret.zip` would have
/// this function open that file and unpack its contents into `destination`. `../../x.zip`
/// reaches the same place by a different spelling. Each name now goes through
/// [`safe_member_target`] — the same lexical check this module already applies to the
/// names of members *inside* an archive.
///
/// The extraction budget spans the whole set rather than restarting per part; see
/// [`ExtractBudget`].
pub fn restore_archive_set(archive_set_dir: &Path, destination: &Path) -> Result<u64> {
    restore_archive_set_with_limits(archive_set_dir, destination, ExtractLimits::default())
}

/// [`restore_archive_set`] with a caller-chosen budget. Private: the only caller that
/// wants a different one is this module's own test for the set-wide budget, which cannot
/// otherwise be written without fabricating gigabytes.
fn restore_archive_set_with_limits(
    archive_set_dir: &Path,
    destination: &Path,
    limits: ExtractLimits,
) -> Result<u64> {
    let manifest_path = archive_set_dir.join("ARCHIVE_SET_MANIFEST.json");
    let manifest_bytes = std::fs::read(&manifest_path).map_err(|source| ArchiveError::Read {
        path: manifest_path.clone(),
        source,
    })?;
    let manifest: ArchiveSetManifest = serde_json::from_slice(&manifest_bytes)?;

    if manifest.archives.len() > MAX_ARCHIVE_SET_PARTS {
        return Err(ExtractLimits::exceeded(
            &manifest_path,
            "archive-set-parts",
            MAX_ARCHIVE_SET_PARTS.to_string(),
        ));
    }

    let mut budget = limits.budget();
    let mut total = 0u64;
    for archive_name in &manifest.archives {
        // Resolved against the set directory the caller named, never against whatever
        // the manifest would like the base to be.
        let archive_path = safe_member_target(archive_set_dir, archive_name)?;
        total = total.saturating_add(extract_zip_inner(&archive_path, destination, &mut budget)?);
    }
    Ok(total)
}

/// The file members of a zip archive, by name.
///
/// Reading a produced bundle without unpacking it: the export deletes its staging folder
/// as soon as the archive is written, so the archive is the only copy left. Directory
/// entries are skipped — a caller wants the artifacts, not the shape of the tree.
pub fn list_zip_entries(archive_path: &Path) -> Result<Vec<String>> {
    let file = std::fs::File::open(archive_path).map_err(|source| ArchiveError::Read {
        path: archive_path.to_path_buf(),
        source,
    })?;
    let mut archive = zip::ZipArchive::new(file).map_err(|source| ArchiveError::Zip {
        path: archive_path.to_path_buf(),
        source,
    })?;

    let mut names = Vec::with_capacity(archive.len());
    for index in 0..archive.len() {
        let member = archive
            .by_index(index)
            .map_err(|source| ArchiveError::Zip {
                path: archive_path.to_path_buf(),
                source,
            })?;
        if member.is_file() {
            names.push(member.name().to_string());
        }
    }
    Ok(names)
}

/// One member of a zip archive, as text.
///
/// Nothing is written to disk, so the path-traversal question [`safe_member_target`]
/// answers does not arise: a member is read into memory under the name the caller asked
/// for, and a name that is not in the archive is an error rather than a guess.
pub fn read_zip_entry_to_string(archive_path: &Path, entry: &str) -> Result<String> {
    let file = std::fs::File::open(archive_path).map_err(|source| ArchiveError::Read {
        path: archive_path.to_path_buf(),
        source,
    })?;
    let mut archive = zip::ZipArchive::new(file).map_err(|source| ArchiveError::Zip {
        path: archive_path.to_path_buf(),
        source,
    })?;
    let mut member = archive.by_name(entry).map_err(|source| ArchiveError::Zip {
        path: archive_path.to_path_buf(),
        source,
    })?;

    // Bounded for the same reason extraction is, and on the same terms: this reads into
    // memory, so an unbounded member is an out-of-memory abort rather than a full disk.
    let limits = ExtractLimits::default();
    let allowance = limits.max_entry_bytes.saturating_add(1);
    let mut text = String::new();
    let read =
        std::io::Read::read_to_string(&mut std::io::Read::take(&mut member, allowance), &mut text)
            .map_err(|source| ArchiveError::Read {
                path: archive_path.to_path_buf(),
                source,
            })?;
    if read as u64 > limits.max_entry_bytes {
        return Err(ExtractLimits::exceeded(
            archive_path,
            "per-member",
            limits.max_entry_bytes.to_string(),
        ));
    }
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_parent_dir_traversal() {
        let dest = Path::new("/dest");
        assert!(safe_member_target(dest, "../../evil.txt").is_err());
    }

    #[test]
    fn rejects_embedded_parent_dir_after_a_normal_segment() {
        let dest = Path::new("/dest");
        assert!(safe_member_target(dest, "foo/../../bar").is_err());
    }

    #[test]
    fn rejects_absolute_unix_path() {
        let dest = Path::new("/dest");
        assert!(safe_member_target(dest, "/etc/passwd").is_err());
    }

    #[test]
    fn accepts_a_plain_relative_path() {
        let dest = Path::new("/dest");
        let target = safe_member_target(dest, "src/main.rs").expect("safe target");
        assert_eq!(target, Path::new("/dest/src/main.rs"));
    }

    #[test]
    fn rejects_current_dir_component_too() {
        let dest = Path::new("/dest");
        assert!(safe_member_target(dest, "./a.txt").is_err());
    }

    // --- The decompression budget ---------------------------------------------------
    //
    // `codepack verify` re-scans a bundle its user *received*, which makes it the one
    // input in this product that is untrusted by design. Path traversal was already
    // refused; sheer expanded volume was not, so a small archive could fill the disk.

    /// Writes a zip with the given members. Deflate, so a highly repetitive member
    /// compresses the way a bomb's does — the archive on disk stays tiny.
    fn archive_of(dir: &Path, members: &[(&str, usize)]) -> PathBuf {
        use std::io::Write as _;

        let path = dir.join("bundle.zip");
        let file = std::fs::File::create(&path).expect("create the fixture archive");
        let mut zip = zip::ZipWriter::new(file);
        let options: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default();
        for (name, size) in members {
            zip.start_file(*name, options).expect("start a member");
            zip.write_all(&vec![b'a'; *size]).expect("write a member");
        }
        zip.finish().expect("finish the archive");
        path
    }

    // --- A split set is one archive, and its manifest comes from a stranger -----------
    //
    // Audit No. 8. Two independent defects in `restore_archive_set`: the budget restarted
    // for every part, and the part names were joined to the set directory without any
    // check at all.

    /// Writes an `ARCHIVE_SET_MANIFEST.json` listing exactly the names given.
    fn manifest_of(dir: &Path, names: &[&str]) -> PathBuf {
        let body = serde_json::json!({ "archives": names });
        let path = dir.join("ARCHIVE_SET_MANIFEST.json");
        std::fs::write(&path, serde_json::to_vec(&body).unwrap()).expect("write the manifest");
        path
    }

    /// Writes one part archive under `dir` with the given member sizes.
    fn part_of(dir: &Path, name: &str, members: &[(&str, usize)]) -> PathBuf {
        use std::io::Write as _;

        let path = dir.join(name);
        let file = std::fs::File::create(&path).expect("create the part");
        let mut zip = zip::ZipWriter::new(file);
        let options: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default();
        for (member, size) in members {
            zip.start_file(*member, options).expect("start a member");
            zip.write_all(&vec![b'a'; *size]).expect("write a member");
        }
        zip.finish().expect("finish the part");
        path
    }

    #[test]
    fn a_manifest_naming_an_absolute_path_is_refused() {
        let set_dir = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        // A real archive, sitting somewhere the manifest has no business reaching.
        part_of(elsewhere.path(), "secret.zip", &[("private.txt", 16)]);
        let absolute = elsewhere.path().join("secret.zip").display().to_string();
        manifest_of(set_dir.path(), &[absolute.as_str()]);
        let destination = tempfile::tempdir().unwrap();

        let error = restore_archive_set(set_dir.path(), destination.path())
            .expect_err("an absolute part name discards the set directory entirely");
        assert!(
            matches!(error, ArchiveError::UnsafeMemberPath { .. }),
            "{error:?}"
        );
        assert_eq!(std::fs::read_dir(destination.path()).unwrap().count(), 0);
    }

    #[test]
    fn a_manifest_climbing_out_of_the_set_directory_is_refused() {
        let parent = tempfile::tempdir().unwrap();
        let set_dir = parent.path().join("set");
        std::fs::create_dir_all(&set_dir).unwrap();
        part_of(parent.path(), "outside.zip", &[("private.txt", 16)]);
        manifest_of(&set_dir, &["../outside.zip"]);
        let destination = tempfile::tempdir().unwrap();

        let error = restore_archive_set(&set_dir, destination.path())
            .expect_err("`..` in a part name must be refused");
        assert!(
            matches!(error, ArchiveError::UnsafeMemberPath { .. }),
            "{error:?}"
        );
        assert_eq!(std::fs::read_dir(destination.path()).unwrap().count(), 0);
    }

    /// The budget failure the audit describes: every part passes on its own, the set
    /// does not. Before the fix each part got a fresh allowance, so this extracted
    /// happily.
    #[test]
    fn parts_that_each_fit_the_budget_can_still_exceed_it_together() {
        let set_dir = tempfile::tempdir().unwrap();
        for index in 0..5 {
            part_of(
                set_dir.path(),
                &format!("part{index}.zip"),
                &[("blob.txt", 1000)],
            );
        }
        let names: Vec<String> = (0..5).map(|index| format!("part{index}.zip")).collect();
        let borrowed: Vec<&str> = names.iter().map(String::as_str).collect();
        manifest_of(set_dir.path(), &borrowed);
        let destination = tempfile::tempdir().unwrap();

        // 4096 bytes total, and each part carries 1000 — the fourth part is where the
        // set crosses the line, and no single part ever does.
        let error =
            restore_archive_set_with_limits(set_dir.path(), destination.path(), tiny_limits())
                .expect_err("the budget spans the set, not one part");
        assert!(error.to_string().contains("total-size"), "{error}");
    }

    #[test]
    fn a_manifest_claiming_an_absurd_number_of_parts_is_refused_before_any_file_is_opened() {
        let set_dir = tempfile::tempdir().unwrap();
        let names: Vec<String> = (0..MAX_ARCHIVE_SET_PARTS + 1)
            .map(|index| format!("part{index}.zip"))
            .collect();
        let borrowed: Vec<&str> = names.iter().map(String::as_str).collect();
        manifest_of(set_dir.path(), &borrowed);
        let destination = tempfile::tempdir().unwrap();

        let error = restore_archive_set(set_dir.path(), destination.path())
            .expect_err("the part count is the manifest author's number, not ours");
        assert!(error.to_string().contains("archive-set-parts"), "{error}");
        // Not one of the named parts exists, so a refusal that came later would have
        // surfaced as a read error instead — this proves the cap is checked first.
        assert_eq!(std::fs::read_dir(destination.path()).unwrap().count(), 0);
    }

    /// The ordinary case still works: a set of well-named parts restores.
    #[test]
    fn a_well_formed_set_still_restores_every_part() {
        let set_dir = tempfile::tempdir().unwrap();
        part_of(set_dir.path(), "part0.zip", &[("a.txt", 10)]);
        part_of(set_dir.path(), "part1.zip", &[("nested/b.txt", 20)]);
        manifest_of(set_dir.path(), &["part0.zip", "part1.zip"]);
        let destination = tempfile::tempdir().unwrap();

        let extracted =
            restore_archive_set(set_dir.path(), destination.path()).expect("a normal set restores");
        assert_eq!(extracted, 2);
        assert!(destination.path().join("nested/b.txt").is_file());
    }

    /// The shape neither the byte budget nor the member count can see: one member, a
    /// handful of bytes on the wire, and an arbitrarily deep tree on disk. Whatever
    /// walks that tree next recurses once per level (audit No. 9).
    #[test]
    fn a_member_nested_past_the_depth_ceiling_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let deep = format!("{}/f.txt", ["a"; 8].join("/"));
        let archive = archive_of(dir.path(), &[(deep.as_str(), 1)]);
        let destination = tempfile::tempdir().unwrap();

        let error = extract_zip_with_limits(&archive, destination.path(), tiny_limits())
            .expect_err("depth must be bounded too");
        let rendered = error.to_string();
        assert!(rendered.contains("member-depth"), "{rendered}");
        assert!(
            rendered.contains('4'),
            "the message must name the ceiling: {rendered}"
        );
    }

    /// And an ordinary nesting depth still extracts, or the ceiling would be refusing
    /// real bundles.
    #[test]
    fn ordinary_nesting_is_untouched_by_the_depth_ceiling() {
        let dir = tempfile::tempdir().unwrap();
        let archive = archive_of(dir.path(), &[("src/reports/insights/a.json", 10)]);
        let destination = tempfile::tempdir().unwrap();

        let extracted =
            extract_zip_with_limits(&archive, destination.path(), tiny_limits()).expect("ordinary");
        assert_eq!(extracted, 1);
    }

    fn tiny_limits() -> ExtractLimits {
        ExtractLimits {
            max_total_bytes: 4096,
            max_entry_bytes: 1024,
            max_entries: 8,
            max_depth: 4,
        }
    }

    #[test]
    fn an_ordinary_archive_extracts_under_the_default_budget() {
        let dir = tempfile::tempdir().unwrap();
        let archive = archive_of(dir.path(), &[("a.txt", 10), ("nested/b.txt", 20)]);
        let destination = tempfile::tempdir().unwrap();

        let extracted = extract_zip_safely(&archive, destination.path()).expect("extracts");
        assert_eq!(extracted, 2);
        assert!(destination.path().join("nested/b.txt").is_file());
    }

    #[test]
    fn a_member_past_the_per_member_ceiling_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let archive = archive_of(dir.path(), &[("huge.txt", 4096)]);
        let destination = tempfile::tempdir().unwrap();

        let error = extract_zip_with_limits(&archive, destination.path(), tiny_limits())
            .expect_err("a member over the ceiling must be refused");
        let rendered = error.to_string();
        assert!(rendered.contains("per-member"), "{rendered}");
        assert!(
            rendered.contains("1024"),
            "the message must name the ceiling: {rendered}"
        );
    }

    /// The other shape of the same attack: every member is individually acceptable and
    /// the total is not.
    #[test]
    fn members_that_are_each_small_enough_can_still_exceed_the_total() {
        let dir = tempfile::tempdir().unwrap();
        let archive = archive_of(
            dir.path(),
            &[
                ("a.txt", 1000),
                ("b.txt", 1000),
                ("c.txt", 1000),
                ("d.txt", 1000),
                ("e.txt", 1000),
            ],
        );
        let destination = tempfile::tempdir().unwrap();

        let error = extract_zip_with_limits(&archive, destination.path(), tiny_limits())
            .expect_err("the total must be enforced too");
        assert!(error.to_string().contains("total-size"), "{error}");
    }

    /// And the third shape: nothing large, just an unreasonable number of members.
    #[test]
    fn too_many_members_are_refused_before_anything_is_written() {
        let dir = tempfile::tempdir().unwrap();
        let members: Vec<(String, usize)> =
            (0..20).map(|index| (format!("f{index}.txt"), 1)).collect();
        let borrowed: Vec<(&str, usize)> = members
            .iter()
            .map(|(name, size)| (name.as_str(), *size))
            .collect();
        let archive = archive_of(dir.path(), &borrowed);
        let destination = tempfile::tempdir().unwrap();

        let error = extract_zip_with_limits(&archive, destination.path(), tiny_limits())
            .expect_err("the member count must be enforced");
        assert!(error.to_string().contains("member-count"), "{error}");
        // Refused before the loop, so nothing landed.
        assert_eq!(std::fs::read_dir(destination.path()).unwrap().count(), 0);
    }

    /// A compressed archive of a few hundred bytes expanding to a megabyte is the
    /// miniature of the real attack; the ratio is what makes it cheap to send.
    #[test]
    fn a_small_archive_that_expands_enormously_is_stopped() {
        let dir = tempfile::tempdir().unwrap();
        let archive = archive_of(dir.path(), &[("bomb.txt", 1024 * 1024)]);
        let on_disk = std::fs::metadata(&archive).unwrap().len();
        assert!(
            on_disk < 16 * 1024,
            "the fixture should be tiny on disk to be worth calling a bomb: {on_disk}"
        );

        let destination = tempfile::tempdir().unwrap();
        let error = extract_zip_with_limits(&archive, destination.path(), tiny_limits())
            .expect_err("a bomb must not expand");
        assert!(matches!(error, ArchiveError::ExtractionTooLarge { .. }));
    }

    #[test]
    fn reading_a_member_into_memory_is_bounded_too() {
        let dir = tempfile::tempdir().unwrap();
        let archive = archive_of(dir.path(), &[("small.txt", 10)]);

        // The published reader uses the default ceiling, so a small member still reads.
        let text = read_zip_entry_to_string(&archive, "small.txt").expect("reads");
        assert_eq!(text.len(), 10);
    }

    #[test]
    fn listing_names_only_the_files() {
        let dir = tempfile::tempdir().unwrap();
        let archive = archive_of(dir.path(), &[("a.txt", 1), ("nested/b.txt", 1)]);

        let mut names = list_zip_entries(&archive).expect("lists");
        names.sort();
        assert_eq!(names, vec!["a.txt".to_string(), "nested/b.txt".to_string()]);
    }

    #[test]
    fn the_default_budget_is_generous_enough_for_a_real_bundle() {
        // A guard against tightening these into a limit that refuses legitimate exports:
        // a bundle carries a copy of a project and a full text dump of it.
        let limits = ExtractLimits::default();
        assert!(limits.max_total_bytes >= 8 * 1024 * 1024 * 1024);
        assert!(limits.max_entry_bytes >= 1024 * 1024 * 1024);
        assert!(limits.max_entries >= 100_000);
    }
}

#[cfg(test)]
mod ambiguous_member_names {
    //! Member names where the safe answer is not obvious.
    //!
    //! A zip stores names as text, and what counts as a separator, a reserved word or an
    //! empty segment differs by platform. Each test below pins the decision this crate
    //! makes rather than leaving it to whoever reads `safe_member_target` next.

    use super::*;

    /// The specification says `/`. Windows also treats `\` as one, so a member named
    /// `a\..\..\evil` would traverse on Windows while looking like a single innocent
    /// file name to a `/`-only check.
    ///
    /// `Path::components` is platform-dependent here, which is the whole difficulty: on
    /// Windows it splits the backslash and the traversal is caught; on Unix the name is
    /// one component and lands as a literal file inside the destination. Either way it
    /// does not escape, and that is what this asserts — the outcome, not the mechanism.
    #[test]
    fn a_backslash_in_a_member_name_never_escapes_the_destination() {
        let destination = Path::new("/dest");
        for name in [r"a\..\..\evil.txt", r"..\..\evil.txt", r"a\b\..\..\..\evil"] {
            match safe_member_target(destination, name) {
                Err(_) => {}
                Ok(target) => assert!(
                    target.starts_with(destination),
                    "{name} resolved outside the destination: {target:?}"
                ),
            }
        }
    }

    /// A name that is only separators, or empty, has no components at all. Joining
    /// nothing onto the destination yields the destination itself — a directory, which
    /// the extractor would then try to open as a file. Refusing is not required for
    /// safety here, but the target must at least stay inside.
    #[test]
    fn a_degenerate_name_stays_inside_the_destination() {
        let destination = Path::new("/dest");
        for name in ["", "/", "//", "./"] {
            if let Ok(target) = safe_member_target(destination, name) {
                assert!(target.starts_with(destination), "{name:?} -> {target:?}");
            }
        }
    }

    /// Windows reserved device names are not a traversal, and this crate does not treat
    /// them as one: extraction fails on the write, honestly, rather than being refused
    /// here on a platform where the name is perfectly ordinary. Pinned so nobody
    /// "fixes" it into a refusal that would reject a legitimate Unix-authored bundle.
    #[test]
    fn a_windows_device_name_is_not_treated_as_traversal() {
        let destination = Path::new("/dest");
        for name in ["CON", "nul.txt", "aux/readme.md"] {
            let target = safe_member_target(destination, name).expect("not a traversal");
            assert!(target.starts_with(destination));
        }
    }

    /// A name whose every segment is legal but which nests very deeply is not an escape,
    /// and is accepted — the depth ceiling that matters is the byte budget, not the path.
    #[test]
    // Depth is not this function's question — it answers "does this escape". The
    // ceiling on depth is `ExtractLimits::max_depth`, enforced during extraction, and it
    // exists because an arbitrarily deep tree overflows the stack of whatever walks it
    // next (audit No. 9).
    fn deep_nesting_does_not_escape_which_is_all_this_function_decides() {
        let destination = Path::new("/dest");
        let deep = vec!["a"; 64].join("/");
        let target = safe_member_target(destination, &deep).expect("legal, if silly");
        assert!(target.starts_with(destination));
    }

    /// Non-ASCII names are ordinary. The product ships Russian-named artifacts, so a
    /// check that quietly assumed ASCII would refuse this crate's own output.
    #[test]
    fn a_non_ascii_member_name_is_ordinary() {
        let destination = Path::new("/dest");
        let target = safe_member_target(destination, "reports/отчёт.md").expect("ordinary");
        assert!(target.ends_with("отчёт.md"));
    }

    /// A member that is a directory entry contributes no bytes, so it must not be
    /// counted against the budget — an archive of many nested directories is not a bomb.
    #[test]
    fn directory_entries_do_not_consume_the_byte_budget() {
        use std::io::Write as _;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dirs.zip");
        let file = std::fs::File::create(&path).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options: zip::write::FileOptions<'_, ()> = zip::write::FileOptions::default();
        for index in 0..6 {
            zip.add_directory(format!("nested{index}/"), options)
                .unwrap();
        }
        zip.start_file("a.txt", options).unwrap();
        zip.write_all(b"small").unwrap();
        zip.finish().unwrap();

        let destination = tempfile::tempdir().unwrap();
        let limits = ExtractLimits {
            max_total_bytes: 16,
            max_entry_bytes: 16,
            max_entries: 32,
            max_depth: 8,
        };
        let extracted = extract_zip_with_limits(&path, destination.path(), limits)
            .expect("directories cost no bytes");
        assert_eq!(extracted, 1, "only the file counts as extracted");
    }
}
