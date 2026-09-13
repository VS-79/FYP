"""
db.py
=====
Singleton MongoDB client for the FYP patch-study pipeline.

Connection is established lazily on first use.
The URI is read from the MONGO_URI environment variable (via .env).

Collections
-----------
  fyp_patches.successful_patches  – patches that passed validation
  fyp_patches.all_attempts        – every attempt (pass + fail), for analysis
"""

from __future__ import annotations

import os
import logging
from datetime import datetime, timezone
from pathlib import Path

from dotenv import load_dotenv
from pymongo import MongoClient, ASCENDING, errors

load_dotenv()

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────
_MONGO_URI       = os.getenv("MONGO_URI", "mongodb://localhost:27017")
# Set only when using X.509 certificate authentication (Atlas).
# Path to the PEM file containing the client certificate + private key.
_MONGO_CERT_PATH = os.getenv("MONGO_CERT_PATH")
_DB_NAME    = "fyp_patches"
_COL_PASS   = "successful_patches"
_COL_ALL    = "all_attempts"

# ── Internal singleton ────────────────────────────────────────────────────────
_client: MongoClient | None = None


def _get_db():
    """Return the database, initialising the client on first call.

    Supports two auth styles, chosen automatically:
      - Username/password embedded in MONGO_URI (default)
      - X.509 certificate auth, when MONGO_CERT_PATH is set. In this mode
        MONGO_URI should NOT contain credentials — it should look like:
          mongodb+srv://<cluster-host>/?authSource=$external&retryWrites=true&w=majority
    """
    global _client
    if _client is None:
        logger.info("db - connecting to MongoDB: %s", _MONGO_URI.split("@")[-1])

        client_kwargs: dict = {"serverSelectionTimeoutMS": 5_000}

        if _MONGO_CERT_PATH:
            cert_path = Path(_MONGO_CERT_PATH)
            if not cert_path.is_file():
                raise FileNotFoundError(
                    f"db - MONGO_CERT_PATH is set but does not point to a file: {cert_path}"
                )
            client_kwargs.update(
                {
                    "tls": True,
                    "tlsCertificateKeyFile": str(cert_path),
                    "authMechanism": "MONGODB-X509",
                }
            )
            logger.info("db - using X.509 certificate authentication (%s)", cert_path.name)

        _client = MongoClient(_MONGO_URI, **client_kwargs)
        # Verify connectivity early so failures are obvious
        _client.admin.command("ping")
        _ensure_indexes(_client[_DB_NAME])
        logger.info("db - connected OK")
    return _client[_DB_NAME]


def _ensure_indexes(db) -> None:
    """Create indexes if they don't already exist."""
    for col_name in (_COL_PASS, _COL_ALL):
        col = db[col_name]
        col.create_index([("package_name", ASCENDING), ("model_used", ASCENDING)])
        col.create_index([("timestamp", ASCENDING)])


# ── Public helpers ────────────────────────────────────────────────────────────

def save_patch_result(state: dict, passed: bool) -> str | None:
    """
    Persist a patch attempt to MongoDB.

    Always writes to `all_attempts`.
    If `passed=True`, also writes to `successful_patches`.

    Returns the inserted document's str(_id), or None on failure.
    """
    doc = _build_doc(state, passed)
    try:
        db = _get_db()
        result = db[_COL_ALL].insert_one(doc)
        inserted_id = str(result.inserted_id)

        if passed:
            # Re-insert the same doc (without the Mongo _id) into the pass collection
            doc.pop("_id", None)
            db[_COL_PASS].insert_one(doc)

        logger.info("db - saved attempt (pass=%s) _id=%s", passed, inserted_id)
        return inserted_id

    except errors.PyMongoError as exc:
        logger.error("db - failed to save to MongoDB: %s", exc)
        return None


def _build_doc(state: dict, passed: bool) -> dict:
    patch = state.get("current_patch") or {}
    return {
        "timestamp":       datetime.now(timezone.utc),
        "passed":          passed,
        "package_name":    state.get("package_name"),
        "package_version": state.get("package_version"),
        "model_used":      patch.get("model_used"),
        "attempt_number":  patch.get("attempt_number"),
        "diff":            patch.get("diff"),
        "validation":      state.get("validation") or {},
        "vulnerabilities": state.get("vulnerabilities") or [],
        "retry_count":     state.get("retry_count", 0),
        "errors":          state.get("errors") or [],
    }