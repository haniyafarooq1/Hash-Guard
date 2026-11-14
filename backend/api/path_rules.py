"""Filesystem path rules for the scan API (backend/api/path_rules.py).

The API must never turn into an arbitrary filesystem scanner: every
requested path is resolved and checked against an allow-list of roots
BEFORE it reaches the detection modules, and baseline files can only be
created or replaced in controlled locations.

Rules enforced here
-------------------
* The monitored ``directory`` must exist, be a real directory, and lie
  inside one of the allowed roots (after resolving symlinks, so a link
  cannot escape the allow-list).
* The ``baseline_file`` must be a ``.json`` file whose parent directory
  lies inside the allowed roots.
* ``POST /api/scan`` requires the baseline file to already exist.
* ``POST /api/baseline/create`` refuses to overwrite an existing
  baseline unless the request explicitly passes ``overwrite=true``.

Configuration
-------------
The ``HASHGUARD_ALLOWED_ROOTS`` environment variable holds the allowed
roots, separated by ``os.pathsep`` (``:`` on POSIX, ``;`` on Windows).
When it is unset or empty the defaults are the process working
directory (the project root when started as documented) and the system
temporary directory.
"""

import os
import tempfile
from pathlib import Path

ALLOWED_ROOTS_ENV = "HASHGUARD_ALLOWED_ROOTS"

_allowed_roots_override = None


class PathRuleError(ValueError):
    """A requested path violates the API path rules.

    Carries the HTTP status code the API should answer with.
    """

    def __init__(self, message, status_code=400):
        super().__init__(message)
        self.status_code = status_code


def _configured_roots():
    """Resolve the allowed roots from the environment (no override)."""
    env_value = os.environ.get(ALLOWED_ROOTS_ENV, "")
    roots = []
    if env_value.strip():
        for part in env_value.split(os.pathsep):
            part = part.strip()
            if part:
                roots.append(Path(part).resolve())
    if roots:
        return roots
    return [
        Path.cwd().resolve(),
        Path(tempfile.gettempdir()).resolve(),
    ]


def set_allowed_roots(roots):
    """Override the allowed roots (used by the test suite).

    ``roots`` is a list of paths; ``None`` restores the default
    resolution from the environment.
    """
    global _allowed_roots_override
    if roots is None:
        _allowed_roots_override = None
    else:
        _allowed_roots_override = [Path(root).resolve() for root in roots]


def reset_allowed_roots():
    """Restore the default allowed-roots resolution."""
    set_allowed_roots(None)


def get_allowed_roots():
    """Return the currently effective allowed roots (resolved paths)."""
    if _allowed_roots_override is not None:
        return list(_allowed_roots_override)
    return _configured_roots()


def _is_within(path, root):
    """True when ``path`` equals or lies below ``root``."""
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def _require_allowed(resolved_path, label):
    """Raise PathRuleError unless the path lies inside an allowed root."""
    for root in get_allowed_roots():
        if _is_within(resolved_path, root):
            return
    raise PathRuleError(
        "{} '{}' is outside the allowed roots. Allowed roots: {}. "
        "Extend the {} environment variable to monitor additional "
        "locations.".format(
            label,
            resolved_path,
            ", ".join(str(root) for root in get_allowed_roots()),
            ALLOWED_ROOTS_ENV,
        ),
        status_code=403,
    )


def resolve_monitored_directory(value):
    """Validate and resolve a monitored directory request value.

    Returns the resolved Path.  Raises PathRuleError with a 400 status
    for malformed / non-existent values and 403 when the directory lies
    outside the allowed roots (symlinks are resolved first, so a link
    pointing outside the allow-list is rejected too).
    """
    text = str(value or "").strip()
    if not text:
        raise PathRuleError("directory is required", status_code=400)
    if "\x00" in text:
        raise PathRuleError(
            "directory must not contain NUL bytes", status_code=400
        )

    resolved = Path(text).resolve()
    if not resolved.exists():
        raise PathRuleError(
            "Monitored directory '{}' does not exist.".format(resolved),
            status_code=400,
        )
    if not resolved.is_dir():
        raise PathRuleError(
            "Monitored directory '{}' is not a directory.".format(resolved),
            status_code=400,
        )
    _require_allowed(resolved, "Monitored directory")
    return resolved


def resolve_baseline_file(value, must_exist=False, for_write=False,
                          overwrite=False):
    """Validate and resolve a baseline file request value.

    Returns the resolved Path.  Rules:

    * the file name must end with ``.json`` (400);
    * its parent directory must exist and lie inside the allowed roots
      (400 / 403);
    * with ``must_exist`` (scan requests) the file must already exist
      (404);
    * with ``for_write`` (baseline creation) an existing file is only
      replaced when ``overwrite`` is true (409), and the path must not
      point at a directory (400).
    """
    text = str(value or "").strip()
    if not text:
        raise PathRuleError("baseline_file is required", status_code=400)
    if "\x00" in text:
        raise PathRuleError(
            "baseline_file must not contain NUL bytes", status_code=400
        )
    if not text.lower().endswith(".json"):
        raise PathRuleError(
            "baseline_file must be a .json file.", status_code=400
        )

    resolved = Path(text).resolve()

    if resolved.is_dir():
        raise PathRuleError(
            "Baseline file path '{}' is a directory.".format(resolved),
            status_code=400,
        )

    parent = resolved.parent
    if for_write and not parent.exists():
        raise PathRuleError(
            "Baseline directory '{}' does not exist.".format(parent),
            status_code=400,
        )
    if not parent.exists():
        # For reads a missing parent simply means the baseline is absent.
        raise PathRuleError(
            "Baseline file not found: {}".format(resolved), status_code=404
        )
    _require_allowed(parent, "Baseline directory")

    if must_exist and not resolved.exists():
        raise PathRuleError(
            "Baseline file not found: {}".format(resolved), status_code=404
        )

    if for_write and resolved.exists() and not overwrite:
        raise PathRuleError(
            "Baseline file '{}' already exists. Pass \"overwrite\": true "
            "to replace it deliberately.".format(resolved),
            status_code=409,
        )

    return resolved
