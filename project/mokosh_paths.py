"""Central filesystem paths for the MOKOSH Stage 0 migration.

For compatibility, private runtime data remains beside the application during
Stage 0.  A later, separately tested migration can set ``MOKOSH_DATA_DIR`` and
move it to a dedicated private data directory.  Centralising the location now
removes the dependency on the retired ``~/phi_crypto`` symlink.
"""

from __future__ import annotations

import os
from pathlib import Path


APP_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.environ.get("MOKOSH_DATA_DIR", str(APP_DIR))).expanduser().resolve()


def ensure_private_data_dir() -> Path:
    """Create the runtime directory and keep it private to the current user."""
    DATA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    try:
        DATA_DIR.chmod(0o700)
    except OSError:
        # Some filesystems do not implement POSIX permissions.  Callers still
        # get the resolved path; the health check will report the condition.
        pass
    return DATA_DIR
