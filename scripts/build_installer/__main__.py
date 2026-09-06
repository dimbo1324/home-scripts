"""Build the distributable installer for the host this runs on.

Windows gets the NSIS ``.exe``; Linux gets ``.deb``, ``.rpm`` and ``.AppImage``. What
each platform produces, and where, is data in ``config/build.json`` — the script only
runs ``cargo xtask package`` and reports what it then finds on disk.

On a platform codepack does not bundle for, it refuses immediately with the reason
instead of starting a long release build that would fail somewhere inside the bundler. A
tool that wastes ten minutes before admitting it cannot do the job is worse than one that
says so up front.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from scripts._toolkit.config import load_config, repo_root
from scripts._toolkit.console import fail, heading, info, ok, warn
from scripts._toolkit.steps import run_steps

SCRIPT_DIR = Path(__file__).resolve().parent


def _human_mib(size: int) -> str:
    return f"{size / (1024 * 1024):.1f} MiB"


def platform_entry(config: dict, platform: str) -> dict | None:
    """The artifact table for ``platform``, or ``None`` if codepack does not bundle for it.

    Matched by prefix because ``sys.platform`` is ``linux`` on modern Python but
    ``linux2`` on older ones, and ``win32`` on 64-bit Windows.
    """
    for key, entry in config["platforms"].items():
        if platform.startswith(key):
            return entry
    return None


def refusal_for(config: dict, platform: str) -> str:
    for key, message in config["refusals"].items():
        if platform.startswith(key):
            return message
    return config["default_refusal"]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="build-installer",
        description="Build the distributable installer for this platform.",
    )
    parser.add_argument(
        "--allow-other-platform",
        action="store_true",
        help="attempt the build anyway on a platform with no declared bundle target",
    )
    args = parser.parse_args(argv)

    root = repo_root()
    config = load_config(SCRIPT_DIR, "build.json")

    entry = platform_entry(config, sys.platform)
    if entry is None and not args.allow_other_platform:
        heading("build-installer — not available on this platform")
        info(refusal_for(config, sys.platform))
        info("")
        info("Pass --allow-other-platform to try regardless.")
        return 1

    exit_code = run_steps(config["steps"], root, title="build-installer")
    if exit_code != 0:
        return exit_code

    if entry is None:
        warn("built on a platform with no declared artifacts; nothing to report")
        return 0

    heading(entry["label"])
    found = 0
    for artifact in entry["artifacts"]:
        directory = root / artifact["dir"]
        if not directory.is_dir():
            # Not fatal on its own: a platform produces several formats and one of them
            # may be unavailable in a stripped-down environment. Whether that is a
            # failure is decided below, once every format has been looked at.
            info(f"no {directory} (this format was not produced)")
            continue
        matches = sorted(directory.glob(artifact["glob"]))
        if not matches:
            info(f"no {artifact['glob']} in {directory}")
            continue
        for match in matches:
            ok(f"{match}  ({_human_mib(match.stat().st_size)})")
            found += 1

    if found == 0:
        # The build reported success and left nothing behind, which means the bundler
        # wrote somewhere this table does not know about. Say which directories were
        # checked rather than claim an installer exists.
        fail("the build succeeded but produced no artifact in any expected directory:")
        for artifact in entry["artifacts"]:
            fail(f"  {root / artifact['dir']}/{artifact['glob']}")
        return 1

    for note in entry.get("notes", []):
        warn(note)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
