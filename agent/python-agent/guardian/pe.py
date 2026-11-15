"""PE static analysis + model slot. Files are parsed, never executed.

Model contract (spec 11.2): every result carries model_id, model_version, feature_schema_version, score, threshold,
inference_time_ms. With no model installed the scan reports metadata only and the system runs rules-only.
"""
from __future__ import annotations
import hashlib, json, math, time, pathlib, os
from . import config

try:
    import pefile
except ImportError:  # pragma: no cover
    pefile = None



def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def extract_metadata(path: str) -> dict:
    """Light, safe metadata. The EMBER-compatible feature vector is built in ai/malware-pe/features.py."""
    p = pathlib.Path(path)
    out: dict = {"path": str(p), "exists": p.is_file()}
    if not p.is_file():
        return out
    st = p.stat()
    out["size"] = st.st_size
    h = hashlib.sha256()
    with open(p, "rb") as f:
        head = f.read(2)
        f.seek(0)
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    out["sha256"] = h.hexdigest()
    out["is_pe"] = head == b"MZ"
    if out["is_pe"] and pefile and st.st_size < 256 * 1024 * 1024:
        try:
            pe = pefile.PE(str(p), fast_load=False)
            secs = []
            for s in pe.sections:
                data = s.get_data()
                secs.append({"name": s.Name.rstrip(b"\x00").decode("latin1", "replace"), "vsize": s.Misc_VirtualSize,
                             "rsize": s.SizeOfRawData, "entropy": round(entropy(data[:2_000_000]), 2),
                             "exec": bool(s.Characteristics & 0x20000000), "write": bool(s.Characteristics & 0x80000000)})
            imports = []
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                imports = [e.dll.decode("latin1", "replace").lower() for e in pe.DIRECTORY_ENTRY_IMPORT][:60]
            out.update({"machine": hex(pe.FILE_HEADER.Machine), "timestamp": pe.FILE_HEADER.TimeDateStamp,
                        "is_dll": pe.is_dll(), "subsystem": getattr(pe.OPTIONAL_HEADER, "Subsystem", None),
                        "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint), "sections": secs, "imports": imports,
                        "has_signature_dir": bool(pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size),
                        "high_entropy_sections": [s["name"] for s in secs if s["entropy"] > 7.2],
                        "wx_sections": [s["name"] for s in secs if s["exec"] and s["write"]]})
            pe.close()
        except Exception as e:
            out["parse_error"] = str(e)[:200]
    return out


def mark_of_the_web(path: str) -> dict | None:
    """File-origin metadata (proposal 5: 'file origin metadata where available'): the Zone.Identifier stream Windows
    adds to downloaded files. Only the zone and the host name are kept, never the full URL (privacy)."""
    if not config.IS_WINDOWS:
        return None
    try:
        with open(path + ":Zone.Identifier", "r", encoding="utf-8", errors="replace") as f:
            txt = f.read()
    except OSError:
        return None
    out: dict = {}
    for line in txt.splitlines():
        k, _, v = line.partition("=")
        if k == "ZoneId" and v.strip().isdigit():
            out["zone_id"] = int(v)
            out["zone"] = {0: "local", 1: "intranet", 2: "trusted", 3: "internet", 4: "restricted"}.get(int(v), "unknown")
        elif k in ("HostUrl", "ReferrerUrl") and v.strip():
            from urllib.parse import urlparse
            host = urlparse(v.strip()).hostname
            if host and "origin_host" not in out:
                out["origin_host"] = host
    return out or None


class PEModel:
    """Loads a LightGBM model package from ai/model-registry/malware-pe/<version>/ if present.

    Package layout: model.txt, calibrator.json, model_card.json, feature_schema.json (written by ai/malware-pe/train.py).
    Refused (system continues rules-only, with a visible warning) when: hash mismatch, feature schema/layout mismatch,
    lightgbm or the extractor are missing, or the model failed to load.  A model is only used as E1 evidence when its card says
    `validated: true` (threshold and calibration chosen on validation data, spec 11.3); otherwise scores are shown but not counted.
    """

    MAX_BYTES = 64 * 1024 * 1024

    def __init__(self, model_dir=None):
        self.loaded = False
        self.info: dict = {}
        self.booster = None
        self.calibrator = None
        self.columns = None
        self.warning: str | None = None
        self.root = pathlib.Path(model_dir) if model_dir else config.MODEL_DIR / "malware-pe"
        self._try_load()

    @property
    def validated(self) -> bool:
        return bool(self.loaded and self.info.get("validated"))

    def _try_load(self):
        if not self.root.exists():
            return
        versions = sorted([d for d in self.root.iterdir() if d.is_dir() and (d / "model_card.json").exists()])
        if not versions:
            return
        d = versions[-1]
        try:
            card = json.loads((d / "model_card.json").read_text())
            mpath = d / "model.txt"
            digest = hashlib.sha256(mpath.read_bytes()).hexdigest()
            if card.get("model_sha256") != digest:
                self.warning = "model hash mismatch: model not loaded, running rules-only"
                return
            schema = card.get("feature_schema_version")
            if schema == "csv_pefields_v1":                      # model trained from a CSV of PE header fields
                fc = _features_csv()
                cols = card.get("columns") or []
                if not cols or card.get("feature_layout_hash") != fc.layout_hash(cols):
                    self.warning = "feature schema mismatch: model not loaded, running rules-only"
                    return
                self.columns = cols
            else:
                feats = _features()
                ok, why = feats.available()
                if not ok:
                    self.warning = f"model not loaded: {why}"
                    return
                if schema != feats.FEATURE_SCHEMA_VERSION or card.get("feature_layout_hash") != feats.feature_layout_hash():
                    self.warning = "feature schema mismatch: model not loaded, running rules-only"
                    return
                self.columns = None
            try:
                import lightgbm as lgb
            except ImportError:
                self.warning = "model not loaded: lightgbm is not installed (open Model Lab and press Train: it installs the components)"
                return
            self.booster = lgb.Booster(model_file=str(mpath))
            cal = d / "calibrator.json"
            self.calibrator = json.loads(cal.read_text()) if cal.exists() else None
            self.info = {"model_id": card.get("model_id", "malware-pe"), "version": card.get("version", d.name), "hash": digest,
                         "feature_schema_version": card["feature_schema_version"], "threshold_high": card.get("threshold_high", 0.9),
                         "metrics": card.get("metrics", {}), "trained_on": card.get("dataset"), "calibrated": bool(self.calibrator),
                         "validated": bool(card.get("validated")), "limitations": card.get("limitations", []),
                         "split": card.get("split"), "quality_gate": card.get("quality_gate")}
            self.loaded = True
            if not self.info["validated"]:
                self.warning = "model loaded but NOT validated: scores are shown, never used as E1 evidence. " + (card.get("quality_gate") or "")
        except Exception as e:
            self.warning = f"model load failed: {e}"

    @staticmethod
    def _extractor_schema() -> str:
        try:
            return _features().FEATURE_SCHEMA_VERSION
        except Exception:
            return "unavailable"

    @staticmethod
    def extractor_status() -> dict:
        try:
            ok, why = _features().available()
        except Exception as e:
            ok, why = False, str(e)
        return {"available": ok, "reason": why}

    def score_file(self, path: str) -> dict | None:
        if not self.loaded:
            return None
        t0 = time.perf_counter()
        vec = _features_csv().vectorize_file(path, self.columns) if self.columns else _features().vectorize_file(path)
        raw = float(self.booster.predict([vec])[0])
        score = self._calibrate(raw)
        thr = self.info["threshold_high"]

        # Explainability: Top-3 feature contributions via LightGBM SHAP values
        top_features = []
        try:
            contribs = self.booster.predict([vec], pred_contrib=True)[0]
            # contribs length is len(features) + 1 (last element is expected value / bias)
            feat_contribs = contribs[:-1]
            raw_names = getattr(self.booster, "feature_name", lambda: None)() or (self.columns if self.columns else None)

            def _friendly_feature_name(idx: int, raw_name: str | None) -> str:
                if raw_name and not raw_name.lower().startswith(("column_", "feature_")):
                    return raw_name
                # Map EMBER2024 feature vector offsets to explainable security categories
                if 0 <= idx < 7:
                    return f"General File Metadata (idx {idx})"
                elif 7 <= idx < 263:
                    return f"Byte Distribution Anomaly (idx {idx})"
                elif 263 <= idx < 519:
                    return f"High Section & Byte Entropy / Packed Code (idx {idx})"
                elif 519 <= idx < 696:
                    return f"Suspicious Embedded Strings / IOCs (idx {idx})"
                elif 696 <= idx < 920:
                    return f"Abnormal PE Section Characteristics / W+X (idx {idx})"
                elif 920 <= idx < 2202:
                    return f"Suspicious API Import Table (idx {idx})"
                elif 2202 <= idx < 2331:
                    return f"Suspicious Export Table Functions (idx {idx})"
                elif 2331 <= idx < 2405:
                    return f"PE / COFF Header Anomalies (idx {idx})"
                elif 2405 <= idx < 2439:
                    return f"PE Data Directory Layout (idx {idx})"
                elif 2439 <= idx < 2472:
                    return f"Rich Header Compiler Stamp (idx {idx})"
                elif 2472 <= idx < 2480:
                    return f"Authenticode Signature Anomaly (idx {idx})"
                elif 2480 <= idx < 2568:
                    return f"PE Structural / Header Warnings (idx {idx})"
                return raw_name or f"Feature #{idx}"

            ranked_indices = sorted(range(len(feat_contribs)), key=lambda i: abs(feat_contribs[i]), reverse=True)[:3]
            for idx in ranked_indices:
                val = float(feat_contribs[idx])
                raw_n = raw_names[idx] if raw_names and idx < len(raw_names) else None
                label = _friendly_feature_name(idx, raw_n)
                top_features.append({
                    "feature": label,
                    "index": idx,
                    "impact": round(val, 4),
                    "direction": "malicious" if val > 0 else "benign"
                })
        except Exception:
            pass

        return {"model_id": self.info["model_id"], "model_version": self.info["version"],
                "feature_schema_version": self.info["feature_schema_version"], "score": round(score, 4), "raw_score": round(raw, 4),
                "threshold": thr, "prediction": "malicious" if score >= thr else "benign",
                "top_features": top_features,
                "calibrated": bool(self.calibrator), "validated": self.validated,
                "inference_time_ms": round((time.perf_counter() - t0) * 1000, 1)}

    def _calibrate(self, p: float) -> float:
        if not self.calibrator:
            return p
        xs, ys = self.calibrator["x"], self.calibrator["y"]      # isotonic step function
        if p <= xs[0]:
            return ys[0]
        for i in range(1, len(xs)):
            if p <= xs[i]:
                return ys[i]
        return ys[-1]


def _features_csv():
    import sys
    primary = config.ROOT / "ai" / "malware-pe"
    fallback = config.ROOT / "optional" / "ai" / "malware-pe"
    d = str(primary if primary.exists() else fallback)
    if d not in sys.path:
        sys.path.insert(0, d)
    import features_csv  # type: ignore
    return features_csv


def _features():
    """The extractor lives next to the training code (ai/malware-pe/features.py) so both use identical code.
    Falls back to optional/ai/malware-pe if ai/malware-pe is not present at the repo root."""
    import sys
    primary = config.ROOT / "ai" / "malware-pe"
    fallback = config.ROOT / "optional" / "ai" / "malware-pe"
    d = str(primary if primary.exists() else fallback)
    if d not in sys.path:
        sys.path.insert(0, d)
    import features  # type: ignore
    return features


def scan_file(path: str, model: PEModel) -> dict:
    """On-demand File Intelligence: hash, PE metadata, signer, origin (Mark-of-the-Web) and the model score. Never executes the file."""
    meta = extract_metadata(path)
    res: dict = {"file": meta, "executed": False, "model": None}
    if meta.get("exists"):
        from .enrich import authenticode_status
        meta["signer"] = authenticode_status(path) if config.IS_WINDOWS and meta.get("is_pe") else "unknown"
        meta["origin"] = mark_of_the_web(path)
    if meta.get("is_pe") and model.loaded:
        try:
            res["model"] = model.score_file(path)
        except Exception as e:
            res["model_error"] = str(e)[:200]
    res["model_status"] = ("scored" if res["model"] else "scoring failed" if res.get("model_error")
                           else "not installed (rules E2-E6 active)" if not model.loaded else "not a PE file")
    if model.warning:
        res["warning"] = model.warning
    return res
