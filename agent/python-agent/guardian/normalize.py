"""Event normalisation: common envelope (schema v1), UTC timestamps and privacy redaction."""
from __future__ import annotations
import re, uuid, time, datetime as dt
from . import config

_USER_PATH = re.compile(r"(?i)([a-z]:\\users\\|/home/|/users/)([^\\/]+)")
_SECRET_ARG = re.compile(r"(?i)(--?(?:password|passwd|pwd|token|secret|apikey|api-key|key|auth|bearer)[=\s:]+)(\S+)")
_SECRET_KV = re.compile(r"(?i)\b(password|passwd|pwd|token|secret|apikey|api_key|authorization)=([^&\s]+)")
_LONG_B64 = re.compile(r"[A-Za-z0-9+/=]{40,}")


def redact_path(p: str | None, enabled: bool = True) -> tuple[str | None, bool]:
    if not p or not enabled:
        return p, False
    new = _USER_PATH.sub(lambda m: m.group(1) + "<user>", p)
    return new, new != p


def redact_cmdline(cmd: str | None) -> tuple[str | None, list[str]]:
    if not cmd:
        return cmd, []
    flags = []
    out = _SECRET_ARG.sub(lambda m: m.group(1) + "<redacted>", cmd)
    out = _SECRET_KV.sub(lambda m: m.group(1) + "=<redacted>", out)
    if out != cmd:
        flags.append("secret_args_redacted")
    out2 = _LONG_B64.sub("<blob>", out)
    if out2 != out:
        flags.append("blob_redacted")
    out2, pf = redact_path(out2)
    if pf:
        flags.append("user_path_redacted")
    return out2[:512], flags


def utc_iso(ts: float) -> str:
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def make_event(host_id: str, source: str, event_type: str, *, ts: float | None = None, pid: int | None = None,
               parent_pid: int | None = None, process_key: str | None = None, image_path: str | None = None,
               sha256: str | None = None, attributes: dict | None = None, privacy_flags: list | None = None,
               severity: str | None = None, redact: bool = True) -> dict:
    ts = ts or time.time()
    flags = list(privacy_flags or [])
    img, changed = redact_path(image_path, redact)
    if changed:
        flags.append("image_path_user_redacted")
    attrs = dict(attributes or {})
    if "command_line" in attrs:
        attrs["command_line"], f = redact_cmdline(attrs["command_line"])
        flags += f
        if f:
            flags.append("command_line_redacted")
    return {
        "event_id": str(uuid.uuid4()), "schema_version": config.EVENT_SCHEMA_VERSION, "host_id": host_id,
        "ts": ts, "timestamp_utc": utc_iso(ts), "source": source, "event_type": event_type,
        "process": {"pid": pid, "parent_pid": parent_pid, "process_guid": process_key, "image_path": img, "sha256": sha256},
        "attributes": attrs, "privacy_flags": sorted(set(flags)), "severity": severity,
    }


def validate_event(e: dict) -> bool:
    """Accept current schema version only (previous versions: none yet)."""
    return isinstance(e, dict) and e.get("schema_version") == config.EVENT_SCHEMA_VERSION and "event_id" in e and "event_type" in e
