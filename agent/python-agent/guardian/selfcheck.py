"""Basic health check (proposal M6: installer, uninstall, logs and basic health checks): python -m guardian.selfcheck"""
from __future__ import annotations
import importlib, socket, sys, tempfile, pathlib
from . import config, capabilities


def main() -> int:
    rows, bad = [], 0

    def check(name, ok, detail="", fatal=True):
        nonlocal bad
        rows.append(("OK  " if ok else ("FAIL" if fatal else "WARN"), name, detail))
        if not ok and fatal:
            bad += 1

    check("python >= 3.10", sys.version_info >= (3, 10), sys.version.split()[0])
    for mod in ("fastapi", "uvicorn", "psutil", "pydantic", "pefile", "websockets"):
        try:
            importlib.import_module(mod); check(f"module {mod}", True)
        except Exception as e:
            check(f"module {mod}", False, str(e))
    try:
        s = socket.socket(); s.bind(("127.0.0.1", 0)); s.close(); check("loopback port bind", True)
    except OSError as e:
        check("loopback port bind", False, str(e))
    try:
        from .db import Database
        with tempfile.TemporaryDirectory() as d:
            db = Database(pathlib.Path(d) / "t.db"); db.set_setting("x", 1)
            check("SQLite WAL + migrations", db.get_setting("x") == 1 and not db.read_only)
            db.conn.close()
    except Exception as e:
        check("SQLite WAL + migrations", False, str(e))
    try:
        config.load_policy(); check("policy file", True)
    except Exception as e:
        check("policy file", False, str(e))
    try:
        d = config.data_dir(); t = d / ".w"; t.write_text("x"); t.unlink(); check("data dir writable", True, str(d))
    except Exception as e:
        check("data dir writable", False, str(e))
    caps = capabilities.discover(False, True)
    check("administrator", caps["admin"], "needed only for the Security log / full process paths", fatal=False)
    for k, v in caps["sources"].items():
        if k != "pe_model":
            check(f"source {k}", v["status"] == "available", v["reason"][:70], fatal=False)
    try:
        primary = config.ROOT / "ai" / "malware-pe"
        fallback = config.ROOT / "optional" / "ai" / "malware-pe"
        extractor_dir = primary if primary.exists() else fallback
        sys.path.insert(0, str(extractor_dir))
        import features
        try:
            ok, why = features.available()
        except Exception as e:
            # ML libraries (lightgbm, scikit-learn) may not be installed; that is acceptable
            ok, why = False, f"ML libraries not installed: {e}"
        check("PE model extractor (optional)", ok, why[:90], fatal=False)
    except Exception as e:
        check("PE model extractor (optional)", False, str(e)[:90], fatal=False)
    for r in rows:
        print(f"[{r[0]}] {r[1]:<34} {r[2]}")
    print("\nSelf-check passed." if not bad else f"\n{bad} required check(s) failed.")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
