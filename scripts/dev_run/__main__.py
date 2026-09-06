"""Build the desktop app, run it for manual testing, then optionally tidy up.

The loop this exists for: change something, look at it, close the window, decide whether
to clean. It runs the **real binary**, which is a different question from
``pnpm desktop:dev`` — that starts a Vite dev server with hot reload and is the better
tool while iterating on the UI. Use this one to check what a user would actually get.

The script blocks until the window closes, then reports how long the session lasted and
what the app exited with, because a crash on close is easy to miss otherwise.
"""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path

from scripts._toolkit.config import load_config, repo_root
from scripts._toolkit.console import fail, heading, info, ok, step, warn
from scripts._toolkit.processes import run

SCRIPT_DIR = Path(__file__).resolve().parent


def main(argv: list[str]) -> int:
    config = load_config(SCRIPT_DIR, "run.json")
    modes = config["modes"]
    cleanup_choices = config["cleanup"]["choices"]

    parser = argparse.ArgumentParser(
        prog="dev-run",
        description="Build and launch the desktop app for manual testing.",
    )
    parser.add_argument(
        "--mode",
        choices=sorted(modes),
        default=config["default_mode"],
        help="; ".join(f"{name}: {entry['label']}" for name, entry in modes.items()),
    )
    parser.add_argument(
        "--cleanup",
        choices=sorted(cleanup_choices),
        default=config["cleanup"]["default"],
        help="; ".join(f"{name}: {text}" for name, text in cleanup_choices.items()),
    )
    parser.add_argument(
        "--skip-frontend",
        action="store_true",
        help="reuse the existing frontend bundle instead of rebuilding it",
    )
    args = parser.parse_args(argv)

    root = repo_root()

    mode = modes[args.mode]
    heading(f"dev-run — {mode['label']}")

    if not args.skip_frontend:
        step("frontend bundle")
        # Built first and unconditionally: the Rust binary embeds it at compile time, so
        # a stale bundle would silently produce an app that does not contain the change
        # you are about to test -- the single most confusing failure in this loop.
        result = run(list(config["frontend_build_argv"]), root)
        if not result.ok:
            fail(f"frontend build failed with exit {result.returncode}")
            return result.returncode

    step("desktop binary")
    result = run(list(mode["build_argv"]), root)
    if not result.ok:
        fail(f"build failed with exit {result.returncode}")
        return result.returncode

    # The config names the binary without a suffix: cargo appends `.exe` on Windows and
    # nothing elsewhere, and hardcoding one was half of why this script called itself
    # Windows-only.
    binary = root / (mode["binary"] + (".exe" if sys.platform.startswith("win32") else ""))
    if not binary.is_file():
        fail(f"build succeeded but {binary} is missing")
        return 1

    step("running — close the window to continue")
    info(str(binary))
    started = time.monotonic()
    try:
        completed = subprocess.run([str(binary)], cwd=root, check=False)
        app_exit = completed.returncode
    except KeyboardInterrupt:
        # Ctrl+C here is a normal way to end a manual test, not an error.
        app_exit = 130
        warn("interrupted")
    elapsed = time.monotonic() - started

    heading("session finished")
    info(f"duration: {elapsed:.0f}s")
    if app_exit == 0:
        ok("app exited cleanly")
    else:
        warn(f"app exited with code {app_exit}")

    if args.cleanup != "none":
        step(f"cleanup: {cleanup_choices[args.cleanup]}")
        cleanup = config["cleanup"]
        # Delegated to clean-project rather than reimplemented: there must be exactly
        # one piece of code in this repository that deletes files, and it is the one
        # with the protected-path list.
        cleanup_result = run(
            [
                sys.executable,
                "-m",
                cleanup["module"],
                *cleanup["argv"][args.cleanup],
            ],
            root,
        )
        if not cleanup_result.ok:
            warn(f"cleanup exited with {cleanup_result.returncode}")

    return app_exit


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
