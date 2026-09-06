//! The codepack desktop shell.
//!
//! ## What this crate is, and is not
//!
//! It is a **front end**, the second one after `codepack-cli`. Every decision about what
//! an export means — which files, which safe mode, what a preset sets — lives in the
//! domain crates and is reached through `codepack-engine`. This crate resolves inputs,
//! calls that, and shapes the answer for a webview. When the GUI and the CLI are asked
//! the same question they run the same code, which is the only way they stay honest with
//! each other.
//!
//! It is deliberately *not* built on top of `codepack-cli`: BLUEPRINT §C.2 puts the
//! Tauri shell and the CLI side by side over the engine, not in a chain. Shelling out to
//! a binary to render a tree would mean parsing text this process could have had as a
//! struct, and would make the GUI depend on the CLI's output format staying stable.
//!
//! ## The isolation boundary
//!
//! The webview is granted no filesystem permission at all
//! (`capabilities/default.json`). It cannot read a file, list a directory, or spawn a
//! process. Everything it needs happens in a `#[tauri::command]` here, and the two
//! places the *user* reaches the filesystem — picking a folder, opening a result — go
//! through the OS's own dialog and handler via the `dialog`/`opener` plugins. That is
//! ROADMAP §3's isolation requirement enforced by capability rather than by convention.
//!
//! The content-security policy in `tauri.conf.json` carries the same idea for the
//! network: it lists no remote origin, so invariant I1 ("analysis is local, always")
//! holds even if a future page tried to `fetch` something.
//!
//! ## One process per machine
//!
//! The application is single-instance. Launching it again does not start a second process:
//! the new one exits immediately and hands the activation to the running one, which raises
//! its window. This is not cosmetic — a second instance would build a second tray icon
//! (cluttering the notification area with duplicates of the same app) and open a second
//! connection to the same SQLite history database.

pub mod commands;
pub mod dto;
pub mod error;
pub mod state;
pub mod tree;

use tauri::Manager;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::TrayIconBuilder;

use state::AppState;

/// Builds and runs the application.
///
/// Split out of `main` so the binary is a one-liner and this stays testable as a
/// library — the command functions are unit-tested directly, without a webview.
pub fn run() {
    tauri::Builder::default()
        // Registered first, as the plugin requires: it has to claim the single-instance
        // lock before anything else in this process starts allocating windows or tray
        // icons, because a second launch must be turned away before it builds any of that.
        .plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| {
            raise_existing_window(app);
        }))
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .manage(AppState::default())
        .setup(|app| {
            install_tray(app.handle())?;
            Ok(())
        })
        .on_window_event(|window, event| {
            // A background export holding a half-built staging directory must be told to
            // stop when the window goes away, or it would keep writing into a directory
            // nobody is going to look at. The pipeline's own cleanup then removes it.
            if matches!(event, tauri::WindowEvent::Destroyed) {
                let state = window.state::<AppState>();
                state.runs.cancel_all();
                state.watch.clear();
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_info::get_app_info,
            commands::settings::load_global_settings,
            commands::settings::save_global_settings,
            commands::settings::export_global_settings,
            commands::settings::import_global_settings,
            commands::settings::apply_preset,
            commands::settings::apply_profile,
            commands::project::open_project,
            commands::project::preview_project,
            commands::project::scan_project,
            commands::project::explain_file,
            commands::export::start_export,
            commands::export::cancel_export,
            commands::export::read_project_profile,
            commands::export::open_dashboard,
            commands::export::open_project_overview,
            commands::export::open_onboarding_guide,
            commands::export::open_review_checklist,
            commands::ai::list_local_agents,
            commands::ai::prepare_handoff,
            commands::sanitize::start_sanitize,
            commands::sanitize::cancel_sanitize,
            commands::history::fetch_history,
            commands::watch::start_watch,
            commands::watch::stop_watch,
            commands::window::set_ui_zoom,
        ])
        .run(tauri::generate_context!())
        .expect("the Tauri context is generated at build time and cannot fail to load");
}

/// Brings the already-running instance's window back to the user.
///
/// Shared by the single-instance callback and the tray's "Show" item, because "the user
/// asked for this application" has exactly one correct answer regardless of how they
/// asked. All three calls are needed and in this order: a window can be hidden, minimised,
/// *and* behind another window at the same time, and skipping any one of them produces the
/// bug where clicking the shortcut appears to do nothing.
///
/// Every result is discarded on purpose — each of these fails only if the window has
/// already been destroyed, in which case there is nothing left to raise and nothing
/// useful to report.
fn raise_existing_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
    }
}

/// The system tray: show the window, or quit.
///
/// Deliberately minimal. Legacy's tray offered a "quick export" that ran with whatever
/// settings happened to be saved — a one-click way to write a bundle without seeing the
/// preview, from a product whose entire purpose is looking before you share. Showing the
/// window is the honest version of that shortcut.
fn install_tray(app: &tauri::AppHandle) -> tauri::Result<()> {
    let show = MenuItem::with_id(app, "show", "Show codepack", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&show, &quit])?;

    TrayIconBuilder::with_id("main")
        .icon(app.default_window_icon().cloned().ok_or_else(|| {
            tauri::Error::AssetNotFound("the bundled window icon is missing".to_string())
        })?)
        .tooltip("codepack")
        .menu(&menu)
        .show_menu_on_left_click(true)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "show" => raise_existing_window(app),
            "quit" => {
                // Stop any running export first: `app.exit` does not unwind the
                // background threads, and an export killed mid-archive would leave the
                // staging directory behind.
                app.state::<AppState>().runs.cancel_all();
                app.exit(0);
            }
            _ => {}
        })
        .build(app)?;
    Ok(())
}
