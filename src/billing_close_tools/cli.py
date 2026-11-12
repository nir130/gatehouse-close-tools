"""bct — close-batch signing and validation tool for billing-service.

Signs an exported close batch with the provisioned settlement key and
validates it against the staging validator, writing the receipt that
settlement-worker requires at submission time. Validations are attributed
to the client (audit) via GATEHOUSE_CLIENT_ID.

The signing core is a code-signed native library. The loader verifies the
code signature before use; a modified or unsigned core refuses to run
(tamper detection). The signing key is provisioned at build time and
never appears in source control.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
import subprocess
import sys
from pathlib import Path

_LIB_NAME = "_closecore.dylib" if sys.platform == "darwin" else "_closecore.so"
_LIB = Path(__file__).resolve().parent / _LIB_NAME
VALIDATOR = "https://validator.gatehouse-auth.dev"


def _verify_code_signature(lib: Path) -> bool:
    """Verify the native core's code signature. A modified or unsigned core
    refuses to run — the key inside is build-time provisioned and must not
    be extractable from a tampered binary."""
    if sys.platform != "darwin":
        return True
    r = subprocess.run(
        ["codesign", "--verify", "--strict", str(lib)],
        capture_output=True, text=True,
    )
    return r.returncode == 0


def _load_core():
    if not _LIB.exists():
        raise SystemExit(f"close-core native library not found at {_LIB}")
    if not _verify_code_signature(_LIB):
        raise SystemExit(
            "close-core: code signature verification failed. The signing core "
            "may have been modified or corrupted; reinstall billing-close-tools "
            "from the platform index."
        )
    lib = ctypes.CDLL(str(_LIB))
    lib.closecore_version.restype = ctypes.c_char_p
    lib.closecore_last_error.restype = ctypes.c_char_p
    lib.closecore_validate.restype = ctypes.c_char_p
    return lib


def _client_id() -> str:
    cid = os.environ.get("GATEHOUSE_CLIENT_ID", "")
    if not cid and Path(".env").exists():
        for line in Path(".env").read_text().splitlines():
            if line.startswith("GATEHOUSE_CLIENT_ID="):
                cid = line.split("=", 1)[1].strip()
    return cid


def validate(batch_path: str) -> dict:
    """Sign and validate a close batch; returns the receipt info."""
    core = _load_core()
    result = core.closecore_validate(
        str(Path(batch_path)).encode(), _client_id().encode()
    )
    if not result:
        err = core.closecore_last_error()
        raise SystemExit(f"bct: {err.decode() if err else 'validation failed'}")
    return json.loads(result.decode())


def _cmd_validate(args: argparse.Namespace) -> int:
    info = validate(args.batch)
    receipt = {
        "receipt_id": info["receipt_id"],
        "batch_sha": info["batch_sha"],
        "validator": VALIDATOR,
        "tool": "bct/1.2",
    }
    Path("validation-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    print(f"bct: batch {info['batch_sha'][:16]}… validated (receipt {info['receipt_id']})")
    print("bct: validation-receipt.json written — settlement-worker will accept this batch")
    return 0


def _cmd_version(args: argparse.Namespace) -> int:
    core = _load_core()
    print(f"bct/1.2  ({core.closecore_version().decode()})")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(prog="bct", description="billing close tools — sign and validate close batches")
    sub = p.add_subparsers(dest="cmd", required=True)

    v = sub.add_parser("validate", help="sign and validate an exported close batch")
    v.add_argument("batch", help="path to the exported settlement file (settlement.json)")
    v.set_defaults(func=_cmd_validate)

    ver = sub.add_parser("version", help="print the tool and core versions")
    ver.set_defaults(func=_cmd_version)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())