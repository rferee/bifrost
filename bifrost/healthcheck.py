"""Container healthcheck: has a sync pass finished recently?

bifrost has no listening port, so the heartbeat file the main loop touches after
every pass is the liveness signal.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from .config import parse_duration


def main() -> int:
    state_dir = os.environ.get("BIFROST_STATE_DIR")
    if not state_dir:
        state_dir = os.path.join(os.environ.get("BIFROST_DATA_DIR", "/data"), ".bifrost")

    heartbeat = Path(state_dir) / "heartbeat"
    if not heartbeat.is_file():
        print("no heartbeat yet", file=sys.stderr)
        return 1

    try:
        poll = parse_duration(os.environ.get("BIFROST_POLL_INTERVAL", "5m"), "poll")
    except Exception:
        poll = 300

    age = time.time() - heartbeat.stat().st_mtime
    limit = max(poll * 3, 120)
    if age > limit:
        print(f"last pass was {int(age)}s ago (limit {limit}s)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
