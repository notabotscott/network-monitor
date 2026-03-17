"""GCS-backed SQLite: download on job start, upload on job end."""
from __future__ import annotations

import logging
import os
from typing import Optional

logger = logging.getLogger(__name__)

_DB_OBJECT = "monitor.db"


def _object_name(prefix: str) -> str:
    return f"{prefix.rstrip('/')}/{_DB_OBJECT}" if prefix else _DB_OBJECT


def download(bucket: str, prefix: str, local_path: str) -> Optional[int]:
    """
    Download the SQLite file from GCS to local_path.
    Returns the GCS object generation (for conditional upload), or None if the
    file doesn't exist yet (first run).
    """
    from google.cloud import storage
    from google.cloud.exceptions import NotFound

    client = storage.Client()
    blob = client.bucket(bucket).blob(_object_name(prefix))
    try:
        blob.reload()
        generation = blob.generation
        blob.download_to_filename(local_path)
        logger.info(
            "GCS DB downloaded",
            extra={"bucket": bucket, "size": os.path.getsize(local_path), "generation": generation},
        )
        return generation
    except NotFound:
        logger.info("GCS DB not found — starting fresh", extra={"bucket": bucket})
        return None


def upload(bucket: str, prefix: str, local_path: str, generation: Optional[int]) -> None:
    """
    Upload the SQLite file to GCS.

    Uses a generation precondition so that if two jobs ran concurrently the
    slower upload fails with a clear error rather than silently overwriting data.
    generation=None means the file was newly created; precondition is 0 (must not exist).
    """
    from google.cloud import storage
    from google.cloud.exceptions import PreconditionFailed

    client = storage.Client()
    blob = client.bucket(bucket).blob(_object_name(prefix))
    precondition = generation if generation is not None else 0

    try:
        blob.upload_from_filename(local_path, if_generation_match=precondition)
        logger.info(
            "GCS DB uploaded",
            extra={"bucket": bucket, "size": os.path.getsize(local_path)},
        )
    except PreconditionFailed:
        raise RuntimeError(
            f"GCS upload failed: another job modified gs://{bucket}/{_object_name(prefix)} "
            "concurrently. The database is intact; the next scheduled run will proceed normally."
        )
