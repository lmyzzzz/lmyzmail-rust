"""Capture Linux socket state on a handoff reservation error; retain assertions."""
import json
import os
import subprocess
from pathlib import Path

import pytest

from lmyzmail_blackbox.ports import PortAllocator

original = PortAllocator.reserve_port


def observed_reservation(self, port):
    try:
        return original(self, port)
    except OSError:
        tables = {}
        for name in ("tcp", "tcp6"):
            tables[name] = [line for line in Path(f"/proc/net/{name}").read_text().splitlines()
                            if f":{port:04X}" in line]
        print(json.dumps({"reservation_failed_port": port, "socket_tables": tables,
            "ss": subprocess.run(["ss", "-tanpo"], capture_output=True, text=True).stdout},
            indent=2), flush=True)
        raise


PortAllocator.reserve_port = observed_reservation
directory = Path(os.environ["LMYZMAIL_HANDOFF_DIAGNOSTIC_OUTPUT"])
directory.mkdir(exist_ok=False)
for iteration in range(1, 6):
    os.environ["LMYZMAIL_EXPORT_TAKEOVER_OUTPUT"] = str(directory / f"result-{iteration}.json")
    result = pytest.main(["-c", "blackbox/pyproject.toml", "tools/test_maildir_export.py",
                          "-q", "-s", f"--junitxml={directory / f'result-{iteration}.xml'}"])
    print(json.dumps({"iteration": iteration, "pytest_exitstatus": result}), flush=True)
    if result:
        raise SystemExit(result)
