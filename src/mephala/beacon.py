# mephala (proprietary) | Fingerprint: MEPAHLA-FP-2025-REPLACE-ME-WITH-256BIT-HEX
# Copyright (c) 2025 ind4skylivey
# All rights reserved. Unauthorized use, copying, modification, distribution, or sale is prohibited.
"""Optional telemetry beacon for mephala (proprietary)."""

from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any, Dict
from urllib.error import URLError
from urllib.request import Request, urlopen


FINGERPRINT_PATH = Path(__file__).resolve().parents[2] / ".fingerprint"
ENV_BEACON_URL = "SAFE_RECON_BEACON_URL"


def _load_fingerprint() -> Dict[str, Any] | None:
    if not FINGERPRINT_PATH.is_file():
        return None
    try:
        return json.loads(FINGERPRINT_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def send_beacon() -> None:
    """Send forensic telemetry if configured; fail silently."""
    beacon_url = os.environ.get(ENV_BEACON_URL)
    if not beacon_url:
        return

    data = _load_fingerprint()
    if not data:
        return

    payload = {
        "fingerprint_sha256": data.get("fingerprint_sha256"),
        "fixed_tag": data.get("fixed_tag"),
        "timestamp_utc": data.get("timestamp_utc"),
        "session_id": str(uuid.uuid4()),
        "tool": "mephala",
        "purpose": "forensic-telemetry",
    }

    try:
        body = json.dumps(payload).encode("utf-8")
        req = Request(
            beacon_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urlopen(req, timeout=5):  # nosec B310 - intentional outbound beacon
            pass
    except (URLError, OSError, ValueError):
        return


__all__ = ["send_beacon"]
