import shutil, subprocess, sys, pathlib
from guardian import config
from guardian.pe import PEModel

ROOT = pathlib.Path(__file__).resolve().parents[2]


def _train(tmp):
    subprocess.run([sys.executable, str(ROOT / "ai/malware-pe/train.py"), "--synthetic", "--rounds", "20", "--version", "t1",
                    "--out", str(tmp / "malware-pe")], check=True, capture_output=True)


def test_model_loads_and_tamper_is_refused(tmp_path, monkeypatch):
    _train(tmp_path)
    monkeypatch.setattr(config, "MODEL_DIR", tmp_path)
    m = PEModel()
    assert m.loaded and m.info["version"] == "t1" and m.info["calibrated"]
    (tmp_path / "malware-pe" / "t1" / "model.txt").write_text("tampered")      # A2 swaps the model file
    m2 = PEModel()
    assert not m2.loaded and "hash mismatch" in m2.warning                      # falls back to rules-only
