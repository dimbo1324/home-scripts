"""Report what this machine can and cannot do — read-only, always exit-code honest.

Small enough to stay one module. What it probes lives in ``config/tools.json``; adding
a tool is a JSON edit.
"""

from __future__ import annotations

import argparse
import os
import platform
import sys
from pathlib import Path

from scripts._toolkit.config import load_config, repo_root
from scripts._toolkit.console import fail, heading, info, ok, step, warn
from scripts._toolkit.processes import TIMED_OUT, capture, find_tool

SCRIPT_DIR = Path(__file__).resolve().parent


def _first_line(text: str) -> str:
    for line in text.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return "(no version output)"


def _git_config(root: Path, key: str) -> str | None:
    """The value of a git setting, or ``None`` if it is unset.

    ``git config --get`` exits 1 for an unset key, which is not an error here.
    """
    code, output = capture(["git", "config", "--get", key], root)
    if code != 0:
        return None
    return output.strip() or None


def _check_linux_desktop_runtime(root: Path) -> None:
    """Warn about the runtime libraries the desktop shell needs on Linux.

    Warnings, never failures: the CLI, the tests and the quality gate all work without a
    webview, and refusing to give a verdict because a headless machine has no GTK stack
    would make this command useless exactly where it is most often run.

    `ldconfig -p` rather than `pkg-config`: the runtime library is what a built binary
    loads, and the `-dev` package that carries the `.pc` file is not installed on a
    machine that only runs the app.
    """
    listing = ""
    if find_tool("ldconfig"):
        code, output = capture(["ldconfig", "-p"], root, timeout=20)
        if code == 0:
            listing = output

    if not listing:
        info("cannot read the shared-library cache; skipping the webview check")
    elif "libwebkit2gtk-4.1" in listing:
        ok("WebKitGTK 4.1 present: the desktop shell can run here")
    else:
        warn(
            "libwebkit2gtk-4.1 not found — the desktop shell will not start. "
            "Debian/Ubuntu: libwebkit2gtk-4.1-0, Fedora: webkit2gtk4.1. "
            "The CLI needs none of this."
        )

    if find_tool("xdg-open"):
        ok("xdg-open present: 'open containing folder' will work")
    else:
        warn("xdg-open not found (package xdg-utils) — opening a bundle's folder will fail")


def _check_git_settings(root: Path) -> list[str]:
    """Report git settings the scripts depend on. Returns the problems found.

    These are checked because their absence breaks a script in a way that does not look
    like a git problem: an inactive hook path means commits silently go unformatted, and
    on Windows an unset ``core.longpaths`` makes ``git status`` warn, which makes
    ``clean-project`` refuse to plan anything at all.
    """
    problems: list[str] = []

    hooks_path = _git_config(root, "core.hooksPath")
    if hooks_path is None:
        warn("core.hooksPath  unset — the tracked pre-commit hook is NOT active")
        info("run: install-hooks")
        problems.append("core.hooksPath")
    elif Path(hooks_path).name != ".githooks":
        warn(f"core.hooksPath  points at {hooks_path!r}, not the tracked .githooks")
        info("run: install-hooks")
        problems.append("core.hooksPath")
    else:
        ok(f"core.hooksPath  {hooks_path}")

    if os.name == "nt":
        long_paths = _git_config(root, "core.longpaths")
        if long_paths != "true":
            warn("core.longpaths  not enabled — git cannot read deeply nested paths")
            info("run: git config core.longpaths true")
            info("Without it, clean-project refuses to plan: it cannot see the whole tree.")
            problems.append("core.longpaths")
        else:
            ok("core.longpaths  true")

    return problems


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="doctor",
        description="Check that the tools the other scripts need are present.",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="also fail when an optional tool is missing",
    )
    args = parser.parse_args(argv)

    root = repo_root()
    config = load_config(SCRIPT_DIR, "tools.json")

    heading("codepack — environment check")
    info(f"repository   {root}")
    info(f"python       {sys.version.split()[0]}  ({sys.executable})")
    info(f"platform     {platform.platform()}")
    info(f"sys.platform {sys.platform}")

    missing_required: list[str] = []
    missing_optional: list[str] = []

    step("tools")
    for entry in config["tools"]:
        name = entry["name"]
        resolved = find_tool(name)
        if resolved is None:
            (missing_required if entry["required"] else missing_optional).append(name)
            label = "required" if entry["required"] else "optional"
            warn(f"{name:<12} MISSING ({label}) — needed for {entry['needed_for']}")
            continue
        code, output = capture([name, *entry["version_args"]], root)
        # A tool that resolves but cannot report a version is still a problem worth
        # seeing: that is what a broken shim or a half-finished install looks like.
        if code == TIMED_OUT:
            # The Windows Store's `python` stub is the classic: it resolves, opens a shop
            # window, and never answers. Without a timeout this hung the whole check.
            warn(f"{name:<12} did not answer `--version` in time ({resolved})")
            continue
        if code != 0:
            warn(f"{name:<12} found but `{name} --version` failed ({resolved})")
            continue
        ok(f"{name:<12} {_first_line(output)}")

    step("paths")
    for entry in config["paths"]:
        target = root / entry["path"]
        if target.exists():
            ok(f"{entry['label']}")
        else:
            warn(f"{entry['label']} missing — {entry['hint']}")

    step("git settings")
    git_problems = _check_git_settings(root)

    step("platform notes")
    # Nothing in the catalog is Windows-only any more: `build-installer` bundles for the
    # host it runs on and `dev-run` launches the shell on WebKitGTK as readily as on
    # WebView2. The list is kept because that can change again, and a script that
    # genuinely cannot work somewhere should say so here rather than fail halfway.
    windows_only = config["windows_only_scripts"]
    if os.name == "nt" or not windows_only:
        ok(f"every script in the catalog is usable on {sys.platform}")
    else:
        for name in windows_only:
            warn(f"{name} is Windows-only and cannot run on {sys.platform}")
        info("Everything else in the catalog works here; see docs/__arch__/open-questions.md")

    if sys.platform.startswith("linux"):
        # The two things the desktop shell needs on Linux that the Rust toolchain does
        # not bring: the webview itself, and the helper the app opens folders with. Both
        # are declared as package dependencies in tauri.conf.json, so this matters to
        # somebody running from a checkout rather than to somebody installing a .deb.
        _check_linux_desktop_runtime(root)

    heading("verdict")
    if missing_required:
        fail(f"missing required tool(s): {', '.join(missing_required)}")
        return 1
    if missing_optional and args.strict:
        fail(f"missing optional tool(s) with --strict: {', '.join(missing_optional)}")
        return 1
    if missing_optional:
        warn(f"optional tool(s) absent: {', '.join(missing_optional)}")
        info("Not a failure — the affected steps will say so when they run.")
    if git_problems:
        # Not a failing exit: the tools work and the project builds. It is a warning
        # because each of these breaks something quietly — an unformatted commit, or a
        # clean-project that refuses without the reader knowing why — and a warning that
        # names the fix is the whole reason this section exists.
        warn(f"git setting(s) to fix: {', '.join(git_problems)}")
    ok("environment is usable")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
