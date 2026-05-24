#!/usr/bin/env python3
"""Firestore watch sidecar for noetl-gateway.

The gateway starts this process per subscription and reads JSON lines from
stdout. Credentials stay in the mounted file referenced by
GATEWAY_FIRESTORE_CREDENTIALS_PATH; this script never prints credential data.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
from typing import Any


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Stream Firestore collection changes as JSON lines")
    parser.add_argument("--credentials-path", required=True)
    parser.add_argument("--path", required=True)
    parser.add_argument("--project-id")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    os.environ["GOOGLE_APPLICATION_CREDENTIALS"] = args.credentials_path

    try:
        from google.cloud import firestore  # type: ignore
    except Exception as exc:  # pragma: no cover - exercised in deployment image build
        print(f"google-cloud-firestore import failed: {exc}", file=sys.stderr, flush=True)
        return 2

    client = firestore.Client(project=args.project_id) if args.project_id else firestore.Client()
    collection = client.collection(args.path.strip("/"))
    stopped = threading.Event()

    def on_snapshot(_snapshot: Any, changes: list[Any], _read_time: Any) -> None:
        for change in changes:
            doc = change.document
            record = {
                "doc_id": doc.id,
                "data": doc.to_dict() or {},
                "op": str(change.type.name).lower(),
            }
            print(json.dumps(record, separators=(",", ":")), flush=True)

    watch = collection.on_snapshot(on_snapshot)
    try:
        stopped.wait()
    except KeyboardInterrupt:
        pass
    finally:
        watch.unsubscribe()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
