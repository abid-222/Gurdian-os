"""Paths, constants and runtime configuration for Smart OS Guardian."""
from __future__ import annotations
import os, sys, json, pathlib

APP_NAME = "SmartOSGuardian"
VERSION = "0.3.0-mvp"
EVENT_SCHEMA_VERSION = 1
IS_WINDOWS = sys.platform.startswith("win")

ROOT = pathlib.Path(__file__).resolve().parents[3]          # repo root
UI_DIR = ROOT / "apps" / "desktop-ui"
POLICY_FILE = ROOT / "detection" / "policy" / "policy_v1.json"
MIGRATIONS_DIR = ROOT / "database" / "migrations"
_model_primary = ROOT / "ai" / "model-registry"
_model_fallback = ROOT / "optional" / "ai" / "model-registry"
MODEL_DIR = _model_primary if _model_primary.exists() else _model_fallback


def data_dir() -> pathlib.Path:
    """Per-install data dir. ProgramData on Windows (spec 8.2); ./data otherwise/dev."""
    override = os.environ.get("GUARDIAN_DATA_DIR")
    if override:
        p = pathlib.Path(override)
    elif IS_WINDOWS and os.environ.get("GUARDIAN_PORTABLE", "1") != "1":
        p = pathlib.Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / APP_NAME
    else:
        p = ROOT / "data"
    p.mkdir(parents=True, exist_ok=True)
    return p


def log_dir() -> pathlib.Path:
    p = data_dir() / "logs"
    p.mkdir(parents=True, exist_ok=True)
    return p


def runtime_dir() -> pathlib.Path:
    base = os.environ.get("LOCALAPPDATA") if IS_WINDOWS else str(pathlib.Path.home() / ".local" / "share")
    p = pathlib.Path(base or ".") / APP_NAME
    p.mkdir(parents=True, exist_ok=True)
    return p


# Spec section 16.2 initial engineering values
QUEUE_MAX_EVENTS = 10_000
QUEUE_MAX_BYTES = 32 * 1024 * 1024
BATCH_EVENTS = 500
BATCH_SECONDS = 1.0
WARN_RATIO = 0.70
SHED_RATIO = 0.90
RETENTION_DAYS = {"events": 14, "process_snapshots": 7, "detections": 180, "incidents": 180, "audit": 365}
DB_SIZE_CAP = 2 * 1024 ** 3
HEARTBEAT_SECONDS = 5
TOKEN_TTL_SECONDS = 24 * 3600

# event priorities: lower number = more important (shed last)
PRIORITY = {"alert": 0, "process_start": 1, "process_end": 2, "network_connect": 2, "dns_query": 2,
            "persistence_change": 1, "sensor_tamper": 0, "windows_event": 2, "defender_detection": 1,
            "process_access": 3, "file_create": 4, "image_load": 5, "resource_sample": 3}


def load_policy() -> dict:
    with open(POLICY_FILE, "r", encoding="utf-8") as f:
        return json.load(f)
