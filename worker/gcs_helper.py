#!/usr/bin/env python3
"""
Lightweight Google Cloud Storage helper for CodeMender Slim Worker:
Replaces full google-cloud-cli package (~800MB) with minimal google-cloud-storage Python SDK (~25MB).
"""

import sys
from typing import Tuple


def parse_gcs_uri(gcs_uri: str) -> Tuple[str, str]:
    """Parses a gs://bucket/path/to/blob URI into (bucket, blob_name)."""
    if not gcs_uri.startswith("gs://"):
        raise ValueError(f"Invalid GCS URI (must start with gs://): {gcs_uri}")
    trimmed = gcs_uri[5:]
    if "/" not in trimmed:
        return trimmed, ""
    bucket, blob_name = trimmed.split("/", 1)
    return bucket, blob_name


def upload_file(local_path: str, gcs_uri: str) -> None:
    """Uploads a local file to a GCS destination URI using ambient service account credentials."""
    from google.cloud import storage

    bucket_name, blob_name = parse_gcs_uri(gcs_uri)
    if not blob_name:
        raise ValueError(f"Target GCS URI must include a destination object name: {gcs_uri}")

    client = storage.Client()
    bucket = client.bucket(bucket_name)
    blob = bucket.blob(blob_name)
    blob.upload_from_filename(local_path)
    print(f"Uploaded {local_path} -> {gcs_uri}")


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: gcs_helper.py upload <local_file> <gcs_uri>", file=sys.stderr)
        sys.exit(1)

    cmd = sys.argv[1].lower()
    if cmd == "upload" and len(sys.argv) >= 4:
        upload_file(sys.argv[2], sys.argv[3])
    else:
        print(f"Unknown or incomplete command: {cmd}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
