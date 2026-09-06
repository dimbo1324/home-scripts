//! Watch mode: telling the UI when the project changed underneath it.
//!
//! This does **not** re-export on every keystroke. It emits `watch:changed`, and the UI
//! decides what to do with that — refresh the preview, or (if the user asked for it)
//! update the clipboard. Re-running a full export automatically would write archives
//! nobody asked for, which is the opposite of a tool built around deliberate handoff.
//!
//! Only the project root is watched, and only for content changes. Ignored directories
//! are filtered here rather than at the OS level because `notify` has no portable way to
//! exclude a subtree, and `node_modules` churning during an install would otherwise
//! drown the channel.

use std::path::Path;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use codepack_core::config::Config;
use notify::{Event, RecursiveMode, Watcher};
use tauri::{AppHandle, Emitter, State};

use crate::dto::WatchChangedEvent;
use crate::error::{CommandError, CommandResult};
use crate::state::AppState;

pub const CHANGED_EVENT: &str = "watch:changed";

/// How long the changes must go quiet before the UI is told.
///
/// Saving a file in an editor produces several events in quick succession (write,
/// rename, attribute change), and a build produces hundreds. Coalescing them into one
/// notification is the difference between a useful signal and a flood.
const DEBOUNCE: Duration = Duration::from_millis(400);

/// Most paths one notification carries.
///
/// A dependency install churns tens of thousands of files. Ignored directories catch most
/// of that, but not a `git checkout` of a large branch — and an unbounded buffer would
/// grow until the quiet arrived. Past this the notification says how many there were
/// rather than which, which is all a person can use at that scale anyway.
const MAX_PENDING_PATHS: usize = 10_000;

/// What has changed since the last notification.
#[derive(Default)]
struct Pending {
    paths: Vec<String>,
    /// True once [`MAX_PENDING_PATHS`] was reached and paths started being dropped, so
    /// the UI can say "too many to list" instead of quietly showing a partial list.
    truncated: bool,
    /// Set when the watch is being torn down, so the aggregator thread ends.
    stopped: bool,
}

/// Collects change notifications and releases them once they go quiet.
///
/// ## Why a thread rather than a timestamp
///
/// This used to be a throttle wearing a debounce's name: the callback emitted if
/// `DEBOUNCE` had passed since the last emission and otherwise dropped the paths into a
/// buffer and returned. Nothing ever drained that buffer on its own — there was no timer
/// — so the accumulated paths waited for the *next* change to push them out, and if none
/// came they waited forever.
///
/// That is the common case, not an edge one: a save produces three or four events in
/// fifty milliseconds, the first is emitted and the rest sit in the buffer. The UI then
/// shows a project state missing the very last thing the user did. It looks like it works
/// almost always, which is what makes it hard to notice (audit No. 17).
///
/// A trailing-edge debounce needs something that wakes up when *nothing* happens, so
/// there is a thread: the callback only records and signals, and the thread waits with a
/// timeout and emits when the quiet actually arrives. It also keeps the file-system
/// callback free of work, which is its own reason.
struct Coalescer {
    state: Arc<(Mutex<Pending>, Condvar)>,
}

impl Coalescer {
    /// Starts the aggregator thread. `emit` is called from it, once per burst.
    fn start(
        emit: impl Fn(Vec<String>, bool) + Send + 'static,
    ) -> (Self, std::thread::JoinHandle<()>) {
        let state = Arc::new((Mutex::new(Pending::default()), Condvar::new()));
        let thread_state = Arc::clone(&state);

        let handle = std::thread::spawn(move || {
            let (mutex, condvar) = &*thread_state;
            loop {
                let mut pending = lock(mutex);
                // Nothing to do: sleep until something arrives or the watch stops.
                while pending.paths.is_empty() && !pending.stopped {
                    pending = condvar.wait(pending).unwrap_or_else(|e| e.into_inner());
                }
                if pending.stopped {
                    // Whatever arrived in the same instant as the stop is dropped
                    // deliberately: the watch is going away and nobody is listening.
                    return;
                }

                // Something is pending. Wait for the quiet, restarting the wait each time
                // more arrives — this is the trailing edge.
                loop {
                    let before = pending.paths.len();
                    let (next, timeout) = condvar
                        .wait_timeout(pending, DEBOUNCE)
                        .unwrap_or_else(|e| e.into_inner());
                    pending = next;
                    if pending.stopped {
                        return;
                    }
                    if timeout.timed_out() || pending.paths.len() == before {
                        break;
                    }
                }

                let paths = std::mem::take(&mut pending.paths);
                let truncated = std::mem::take(&mut pending.truncated);
                // Released before emitting: the callback must never be blocked behind a
                // consumer, and `emit` reaches Tauri.
                drop(pending);
                if !paths.is_empty() {
                    emit(paths, truncated);
                }
            }
        });

        (Self { state }, handle)
    }

    /// Records paths and wakes the aggregator. Called from the file-system callback, so
    /// it does no work beyond this.
    fn push(&self, paths: impl IntoIterator<Item = String>) {
        let (mutex, condvar) = &*self.state;
        let mut pending = lock(mutex);
        for path in paths {
            if pending.paths.len() >= MAX_PENDING_PATHS {
                pending.truncated = true;
                break;
            }
            pending.paths.push(path);
        }
        condvar.notify_all();
    }

    /// Ends the aggregator thread.
    fn stop(&self) {
        let (mutex, condvar) = &*self.state;
        lock(mutex).stopped = true;
        condvar.notify_all();
    }
}

/// Takes the lock, recovering from poisoning.
///
/// The same argument `state.rs` records for its own mutexes: what this guards is a list
/// of paths to notify about, and a panic elsewhere cannot make it *wrong* — only, at
/// worst, short by one. Turning that into a dead watch for the rest of the process would
/// be strictly worse.
fn lock(mutex: &Mutex<Pending>) -> std::sync::MutexGuard<'_, Pending> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// What `WatchState` holds: the watcher, and the aggregator that belongs to it.
///
/// One value so the two cannot outlive each other. `stop_watch` and closing the window
/// both drop this, and the `Drop` below is what ends the thread — the audit's point that
/// the aggregator must be tied to the same ownership as the watcher itself.
struct ActiveWatch {
    coalescer: Coalescer,
    aggregator: Option<std::thread::JoinHandle<()>>,
    /// Dropping this stops the file-system notifications. Declared after the coalescer so
    /// nothing new arrives while the thread is being wound down.
    _watcher: Box<dyn std::any::Any + Send>,
}

impl Drop for ActiveWatch {
    fn drop(&mut self) {
        self.coalescer.stop();
        if let Some(handle) = self.aggregator.take() {
            // Joined rather than detached: a thread still holding an `AppHandle` after the
            // window is gone is how a shutdown turns into a hang.
            let _ = handle.join();
        }
    }
}

/// Starts watching `project_root`. Replaces any previous watch.
#[tauri::command]
pub fn start_watch(
    app: AppHandle,
    state: State<'_, AppState>,
    project_root: String,
    config: Config,
) -> CommandResult<()> {
    let root = super::resolve_project_root(&project_root)?;

    let ignored = ignored_directory_names(&root, &config);
    let watch_root = root.clone();

    let (coalescer, aggregator) = Coalescer::start(move |changed_paths, truncated| {
        let _ = app.emit(
            CHANGED_EVENT,
            WatchChangedEvent {
                changed_paths,
                truncated,
            },
        );
    });

    let sink = Coalescer {
        state: Arc::clone(&coalescer.state),
    };
    let mut watcher = notify::recommended_watcher(move |result: notify::Result<Event>| {
        let Ok(event) = result else {
            // A watch error (a directory disappearing mid-walk, a permission change) is
            // not worth interrupting the user over: the watch keeps running, and the
            // next real change still reports.
            return;
        };
        if !event.kind.is_create() && !event.kind.is_modify() && !event.kind.is_remove() {
            return;
        }

        // Recorded, not emitted. Deciding when to speak is the aggregator's job, and a
        // file-system callback should return promptly.
        sink.push(
            event
                .paths
                .iter()
                .filter(|path| !is_ignored(path, &watch_root, &ignored))
                .map(|path| path.display().to_string()),
        );
    })
    .map_err(CommandError::new)?;

    watcher
        .watch(&root, RecursiveMode::Recursive)
        .map_err(CommandError::new)?;

    state.watch.replace(Box::new(ActiveWatch {
        coalescer,
        aggregator: Some(aggregator),
        _watcher: Box::new(watcher),
    }));
    Ok(())
}

/// Stops watching. Idempotent: stopping when nothing is watched is not an error.
#[tauri::command]
pub fn stop_watch(state: State<'_, AppState>) -> CommandResult<()> {
    state.watch.clear();
    Ok(())
}

/// The directory names a change inside is not worth reporting.
///
/// The same set the scanner prunes with, so the watch agrees with the export about what
/// counts as part of the project.
fn ignored_directory_names(root: &Path, config: &Config) -> Vec<String> {
    let mut names: Vec<String> = codepack_scanner::IGNORED_DIR_NAMES
        .iter()
        .map(|name| name.to_lowercase())
        .collect();
    names.extend(
        config
            .extra_ignored_dirs
            .iter()
            .map(|name| name.to_lowercase()),
    );
    names.extend(
        codepack_scanner::merged_extra_ignored_dirs(&codepack_scanner::detect_stacks(root))
            .into_iter()
            .map(|name| name.to_lowercase()),
    );
    names
}

/// True when any path segment below `root` is an ignored directory name.
fn is_ignored(path: &Path, root: &Path, ignored: &[String]) -> bool {
    let Ok(relative) = path.strip_prefix(root) else {
        // Outside the watched tree: `notify` can report the root itself on some
        // platforms, and that is never an interesting change.
        return true;
    };
    relative.components().any(|component| {
        let name = component.as_os_str().to_string_lossy().to_lowercase();
        ignored.iter().any(|ignored_name| ignored_name == &name)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- The debounce (audit No. 17) --------------------------------------------------
    //
    // The old code was a leading-edge throttle: it emitted the first event of a burst and
    // left the rest in a buffer nothing drained. There was no test, which is why the
    // defect survived — so these describe the behaviour rather than the implementation.

    /// One burst of N changes must produce exactly one notification carrying all N.
    #[test]
    fn a_burst_produces_one_notification_carrying_every_path() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        let (coalescer, aggregator) = Coalescer::start(move |paths, truncated| {
            recorder
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((paths, truncated));
        });

        // What an editor save looks like: several events within a few milliseconds.
        for index in 0..4 {
            coalescer.push([format!("/project/src/file{index}.rs")]);
            std::thread::sleep(Duration::from_millis(10));
        }

        // Past the quiet period, with room for the thread to be scheduled.
        std::thread::sleep(DEBOUNCE * 3);
        coalescer.stop();
        let _ = aggregator.join();

        let seen = seen.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(seen.len(), 1, "one burst is one notification: {seen:?}");
        assert_eq!(seen[0].0.len(), 4, "every path in the burst: {seen:?}");
        assert!(!seen[0].1, "nothing was dropped");
    }

    /// The defect itself: the *last* change of a burst must arrive even when nothing
    /// follows it. The old throttle left it in a buffer until the next change, which
    /// might never come.
    #[test]
    fn the_final_change_of_a_burst_is_not_left_behind() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        let (coalescer, aggregator) = Coalescer::start(move |paths, _| {
            recorder
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .extend(paths);
        });

        coalescer.push(["/project/first.rs".to_string()]);
        std::thread::sleep(Duration::from_millis(20));
        coalescer.push(["/project/last.rs".to_string()]);

        std::thread::sleep(DEBOUNCE * 3);
        coalescer.stop();
        let _ = aggregator.join();

        let seen = seen.lock().unwrap_or_else(|e| e.into_inner());
        assert!(
            seen.iter().any(|path| path.ends_with("last.rs")),
            "the last change of a burst never reached the UI: {seen:?}"
        );
    }

    /// Two bursts separated by more than the quiet period are two notifications, not one
    /// — otherwise the debounce would swallow a genuinely separate edit.
    #[test]
    fn two_separated_bursts_are_two_notifications() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        let (coalescer, aggregator) = Coalescer::start(move |paths, _| {
            recorder
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(paths);
        });

        coalescer.push(["/project/a.rs".to_string()]);
        std::thread::sleep(DEBOUNCE * 3);
        coalescer.push(["/project/b.rs".to_string()]);
        std::thread::sleep(DEBOUNCE * 3);

        coalescer.stop();
        let _ = aggregator.join();

        let seen = seen.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(seen.len(), 2, "{seen:?}");
    }

    /// A checkout of a large branch must not grow the buffer without limit; past the cap
    /// the notification says so rather than showing a partial list as if it were whole.
    #[test]
    fn an_enormous_burst_is_capped_and_says_that_it_was() {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let recorder = Arc::clone(&seen);
        let (coalescer, aggregator) = Coalescer::start(move |paths, truncated| {
            recorder
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((paths.len(), truncated));
        });

        coalescer.push((0..MAX_PENDING_PATHS + 500).map(|index| format!("/project/f{index}")));

        std::thread::sleep(DEBOUNCE * 3);
        coalescer.stop();
        let _ = aggregator.join();

        let seen = seen.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, MAX_PENDING_PATHS);
        assert!(seen[0].1, "the truncation must be reported, not hidden");
    }

    /// Stopping ends the aggregator thread. `ActiveWatch::drop` relies on this: a thread
    /// still holding an `AppHandle` after the window closes is how shutdown hangs.
    #[test]
    fn stopping_ends_the_aggregator_thread() {
        let (coalescer, aggregator) = Coalescer::start(|_, _| {});
        coalescer.push(["/project/a.rs".to_string()]);
        coalescer.stop();

        // `join` returning at all is the assertion; a leaked thread would hang here.
        assert!(aggregator.join().is_ok());
    }

    #[test]
    fn a_change_inside_an_ignored_directory_is_not_reported() {
        // A dependency install churns thousands of files; reporting them would make the
        // signal useless.
        let root = Path::new("/project");
        let ignored = vec!["node_modules".to_string(), "target".to_string()];

        assert!(is_ignored(
            Path::new("/project/node_modules/react/index.js"),
            root,
            &ignored
        ));
        assert!(is_ignored(
            Path::new("/project/target/debug/app"),
            root,
            &ignored
        ));
    }

    #[test]
    fn a_change_to_a_real_source_file_is_reported() {
        let root = Path::new("/project");
        let ignored = vec!["node_modules".to_string()];
        assert!(!is_ignored(
            Path::new("/project/src/main.rs"),
            root,
            &ignored
        ));
        assert!(!is_ignored(Path::new("/project/README.md"), root, &ignored));
    }

    #[test]
    fn matching_is_case_insensitive_because_two_of_the_three_platforms_are() {
        let root = Path::new("/project");
        let ignored = vec!["node_modules".to_string()];
        assert!(is_ignored(
            Path::new("/project/Node_Modules/pkg/index.js"),
            root,
            &ignored
        ));
    }

    #[test]
    fn a_path_outside_the_watched_tree_is_ignored_rather_than_reported() {
        let root = Path::new("/project");
        assert!(is_ignored(Path::new("/elsewhere/file.rs"), root, &[]));
    }

    #[test]
    fn the_ignore_set_includes_the_scanners_own_defaults() {
        // The watch must agree with the export about what counts as project content.
        let dir = tempfile::tempdir().unwrap();
        let names = ignored_directory_names(dir.path(), &Config::default());
        assert!(names.iter().any(|name| name == "node_modules"));
        assert!(names.iter().any(|name| name == ".git"));
    }

    #[test]
    fn a_user_configured_extra_directory_is_honoured() {
        let dir = tempfile::tempdir().unwrap();
        let config = Config {
            extra_ignored_dirs: vec!["Vendor".to_string()],
            ..Config::default()
        };
        let names = ignored_directory_names(dir.path(), &config);
        assert!(names.iter().any(|name| name == "vendor"));
    }

    #[test]
    fn a_stack_detected_directory_is_honoured() {
        // A Rust project's `target` is not listed in the base defaults; the stack
        // detector is what adds it.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("Cargo.toml"), "[package]\nname=\"x\"\n").unwrap();
        let names = ignored_directory_names(dir.path(), &Config::default());
        assert!(
            names.iter().any(|name| name == "target"),
            "stack-detected directories are missing: {names:?}"
        );
    }
}
