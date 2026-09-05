//! Path-traversal-safe ZIP extraction (invariant I7), ported from legacy's bundled
//! `restore_archives.py` script into a library function: `restore_archive_set` reads
//! `ARCHIVE_SET_MANIFEST.json` and extracts every listed part.

use std::path::{Component, Path, PathBuf};

use serde::Deserialize;

use crate::error::{ArchiveError, Result};

/// Validates `member_name` lexically — no `std::fs::canonicalize`, which requires the
/// path to already exist and would defeat pre-write validation for a path that does
/// not exist yet. Only `Component::Normal` segments are accepted; `ParentDir`,
/// `RootDir`, `Prefix` (Windows drive/UNC), and even `CurDir` are all rejected, matching
/// the "only normal segments allowed" contract exactly (real ZIP member names never
/// legitimately need a `.`/`..` component).
pub fn safe_member_target(destination: &Path, member_name: &str) -> Result<PathBuf> {
    let mut relative = PathBuf::new();
    for component in Path::new(member_name).components() {
        match component {
            Component::Normal(part) => relative.push(part),
            _ => {
                return Err(ArchiveError::UnsafeMemberPath {
                    member: member_name.to_string(),
                });
            }
        }
    }
    Ok(destination.join(relative))
}

/// Extracts every entry of `archive_path` into `destination`, streaming file contents
/// rather than loading whole files into memory. Every entry is checked by **both**
/// `ZipFile::enclosed_name()` (the `zip` crate's own path-safety accessor) and the
/// independent lexical `safe_member_target` check; if either rejects an entry, the
/// whole extraction aborts immediately with an error — fail-closed, matching legacy's
/// abort-on-first-bad-entry behavior rather than skip-and-continue. A legitimate entry
/// written earlier in the same archive, before the bad one, stays on disk: this is the
/// honest, ported partial-write-before-abort behavior, not a gap.
pub fn extract_zip_safely(archive_path: &Path, destination: &Path) -> Result<u32> {
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

    let mut extracted = 0u32;
    for index in 0..archive.len() {
        let mut zip_entry = archive
            .by_index(index)
            .map_err(|source| ArchiveError::Zip {
                path: archive_path.to_path_buf(),
                source,
            })?;
        let member_name = zip_entry.name().to_string();

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
        let mut output = std::fs::File::create(&target).map_err(|source| ArchiveError::Write {
            path: target.clone(),
            source,
        })?;
        std::io::copy(&mut zip_entry, &mut output).map_err(|source| ArchiveError::Write {
            path: target.clone(),
            source,
        })?;
        extracted += 1;
    }

    Ok(extracted)
}

#[derive(Deserialize)]
struct ArchiveSetManifest {
    archives: Vec<String>,
}

/// Reads `ARCHIVE_SET_MANIFEST.json` inside `archive_set_dir` and extracts every listed
/// part (in manifest order) into `destination`, returning the total file count across
/// all parts.
pub fn restore_archive_set(archive_set_dir: &Path, destination: &Path) -> Result<u32> {
    let manifest_path = archive_set_dir.join("ARCHIVE_SET_MANIFEST.json");
    let manifest_bytes = std::fs::read(&manifest_path).map_err(|source| ArchiveError::Read {
        path: manifest_path.clone(),
        source,
    })?;
    let manifest: ArchiveSetManifest = serde_json::from_slice(&manifest_bytes)?;

    let mut total = 0u32;
    for archive_name in &manifest.archives {
        let archive_path = archive_set_dir.join(archive_name);
        total += extract_zip_safely(&archive_path, destination)?;
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

    let mut text = String::new();
    std::io::Read::read_to_string(&mut member, &mut text).map_err(|source| ArchiveError::Read {
        path: archive_path.to_path_buf(),
        source,
    })?;
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
}
