import json, os, sqlite3, sys, time, pathlib, pytest
from guardian import commands, config, simulate
from guardian.collectors import winevents
from guardian.db import Database

# ---------------------------------------------------------------------------
# Guard: ML / training tests require ai/malware-pe at the repo root AND the
# optional ML libraries (lightgbm, scikit-learn, numpy …).  When those are
# absent (e.g. the plain OS-Lab install) all tests in this file still run
# except the ones decorated with @_ml_test.
# ---------------------------------------------------------------------------
_AI_PE_DIR = config.ROOT / "ai" / "malware-pe"
_ML_AVAILABLE = _AI_PE_DIR.exists()


def _ml_test(fn):
    """Decorator: skip test when ai/malware-pe is not at the repo root."""
    return pytest.mark.skipif(
        not _ML_AVAILABLE,
        reason="ai/malware-pe not present at repo root (moved to optional/); skipping ML test",
    )(fn)


def test_terminal_strips_quotes_keeps_backslashes():
    assert commands.split_line(r'scan --file "C:\Program Files\x y\a.exe"') == ["scan", "--file", r"C:\Program Files\x y\a.exe"]
    assert commands.split_line("processes --top 5") == ["processes", "--top", "5"]


def test_eventlog_bookmark_no_loss_no_duplicates():
    r = lambda i, t: {"record": i, "time": t}
    first, bm = winevents.select_new([r(1, "2026-11-11T02:15:00.100Z"), r(2, "2026-11-11T02:15:01Z")], {"ts": 0, "ids": {}})
    assert [x["record"] for x in first] == [1, 2]
    again, bm = winevents.select_new([r(2, "2026-11-11T02:15:01Z"), r(3, "2026-11-11T02:15:03Z")], bm)   # overlapping re-query after restart
    assert [x["record"] for x in again] == [3]


def test_db_recovers_from_corruption(tmp_path):
    f = tmp_path / "bad.db"; f.write_bytes(b"this is not a sqlite database" * 50)
    db = Database(f)
    assert db.recovery_notice and not db.read_only
    assert list(tmp_path.glob("bad.corrupt-*.db"))             # damaged file kept
    db.set_setting("k", 1); assert db.get_setting("k") == 1    # fresh DB works


def test_retention_uses_user_setting(agent):
    now = time.time()
    agent.db.execute("INSERT INTO events(event_id,schema_version,host_id,ts,source,event_type) VALUES('old',1,'h',?,'x','process_start')", (now - 5 * 86400,))
    agent.db.execute("INSERT INTO events(event_id,schema_version,host_id,ts,source,event_type) VALUES('new',1,'h',?,'x','process_start')", (now - 3600,))
    agent.db.retention(events_days=2)
    ids = {r["event_id"] for r in agent.db.query("SELECT event_id FROM events")}
    assert ids == {"new"}


class FakeModel:
    loaded = True; validated = True; warning = None; info = {"model_id": "malware-pe", "version": "t", "threshold_high": 0.5}
    def score_file(self, p):
        return {"model_version": "t", "score": 0.6, "threshold": 0.5, "feature_schema_version": "x", "inference_time_ms": 1.0, "calibrated": True, "validated": True}


def _proc(agent, tmp_path):
    exe = tmp_path / "AppData" / "evil.exe"; exe.parent.mkdir(); exe.write_bytes(b"MZ" + b"\0" * 64)
    pi = {"key": "9:1", "pid": 9, "ppid": 1, "parent_key": None, "parent_name": "explorer.exe", "name": "evil.exe", "exe": str(exe), "start_ts": time.time(),
          "exe_created_ts": None, "preexisting": False, "sha256": "ab" * 32, "signer": "unsigned", "cpu": 0, "rss": 1, "cmdline": None, "simulated": False, "first_outbound_ts": None}
    agent.procs[pi["key"]] = pi
    return pi


def test_e1_uses_model_threshold_not_policy_constant(agent, tmp_path):
    agent.model = FakeModel()                                  # score 0.6 < policy 0.90 but >= the model's validated threshold 0.5
    pi = _proc(agent, tmp_path)
    agent.engine.evaluate_process(pi)
    assert "E1" in {r["evidence_class"] for r in agent.db.query("SELECT evidence_class FROM detections")}


def test_unvalidated_model_is_not_evidence(agent, tmp_path):
    m = FakeModel(); m.validated = False; agent.model = m
    agent.engine.evaluate_process(_proc(agent, tmp_path))
    assert "E1" not in {r["evidence_class"] for r in agent.db.query("SELECT evidence_class FROM detections")}


def test_incident_keeps_process_name_after_exit(agent):
    simulate.run(agent, "drop_and_execute")
    for k in [k for k in agent.procs if k.startswith("sim:")]:
        agent.procs.pop(k)                                      # process exited
    agent.engine.correlate()
    i = agent.db.one("SELECT process_name, pid FROM incidents")
    assert i["process_name"] and i["pid"]


def test_notes_export_hash_search_and_live_privacy(agent):
    from fastapi.testclient import TestClient
    from guardian.api import create_app
    T = "t" * 43; H = {"X-Guardian-Token": T}
    c = TestClient(create_app(agent, T), base_url="http://127.0.0.1:8123")
    simulate.run(agent, "drop_and_execute")
    iid = agent.db.one("SELECT incident_id FROM incidents")["incident_id"]
    assert c.post(f"/api/v1/alerts/{iid}/notes", headers=H, json={"body": "checked with admin"}).json()["ok"]
    assert c.get(f"/api/v1/alerts/{iid}/notes", headers=H).json()["items"][0]["body"] == "checked with admin"
    exp = c.get(f"/api/v1/alerts/{iid}/export", headers=H).json()
    assert exp["notes"] and exp["detections"] and exp["incident"]["incident_id"] == iid
    agent.db.insert_events(agent.queue.drain(timeout=0.1))      # no writer thread in this fixture: flush the queue ourselves
    h = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    assert c.get(f"/api/v1/events?q={h}", headers=H).json()["items"], "searching by hash must match the sha256 column"
    assert c.get("/api/v1/alerts/nope/notes", headers=H).status_code == 200
    assert c.post("/api/v1/alerts/nope/notes", headers=H, json={"body": "x"}).status_code == 404
    before = {col.name_id for col in agent.collectors}
    agent.privacy["collect_network"] = False
    agent.apply_privacy()
    assert "network" not in {col.name_id for col in agent.collectors}
    agent.privacy["collect_network"] = True
    agent.apply_privacy()
    assert "network" in {col.name_id for col in agent.collectors}


@_ml_test
def test_pe_pipeline_train_package_load_score(tmp_path):
    """Pipeline check with SYNTHETIC data: proves train -> calibrate -> package -> hash/layout check -> live scoring work.
    The package is marked validated=false and must never count as evidence."""
    sys.path.insert(0, str(config.ROOT / "ai" / "malware-pe"))
    import train
    out = train.main(["--synthetic", "--out", str(tmp_path), "--version", "t1", "--rounds", "15"])
    from guardian.pe import PEModel
    m = PEModel(tmp_path)
    assert m.loaded and not m.validated and "NOT validated" in m.warning
    f = tmp_path / "x.exe"; f.write_bytes(b"MZ" + b"\0" * 1024)
    r = m.score_file(str(f))
    assert 0 <= r["score"] <= 1 and r["feature_schema_version"] == "ember2024_fv3_2568"
    card = json.loads((out / "model_card.json").read_text()); card["model_sha256"] = "0" * 64      # tamper -> refused
    (out / "model_card.json").write_text(json.dumps(card))
    bad = PEModel(tmp_path); assert not bad.loaded and "hash mismatch" in bad.warning


# ---------------------------------------------------------------- response actions (REAL processes)
def _spawn(tmp_path, name="victim.exe"):
    import shutil, subprocess, psutil
    exe = tmp_path / name
    shutil.copy2("/bin/sleep" if os.name != "nt" else os.path.join(os.environ["SystemRoot"], "System32", "ping.exe"), exe)
    p = subprocess.Popen([str(exe), "60"] if os.name != "nt" else [str(exe), "-n", "60", "127.0.0.1"], stdout=subprocess.DEVNULL)
    time.sleep(0.4)
    return p, psutil.Process(p.pid)


def _reg(agent, p, ps, exe):
    pi = {"key": f"{p.pid}:{int(ps.create_time()*1000)}", "pid": p.pid, "ppid": os.getpid(), "parent_key": None, "parent_name": "pytest", "name": pathlib.Path(exe).name.lower(),
          "exe": str(exe), "start_ts": ps.create_time(), "exe_created_ts": None, "preexisting": False, "sha256": "ab" * 32, "signer": "unknown", "cpu": 0, "rss": 1,
          "cmdline": None, "simulated": False, "first_outbound_ts": None}
    agent.procs[pi["key"]] = pi
    return pi


def test_response_terminate_needs_typed_confirmation(agent, tmp_path):
    from guardian import response
    p, ps = _spawn(tmp_path); pi = _reg(agent, p, ps, tmp_path / "victim.exe")
    with pytest.raises(response.ActionError, match="confirmation"):
        response.execute(agent, "terminate", pi["key"], "wrong")
    assert ps.is_running()
    r = response.execute(agent, "terminate", pi["key"], "victim.exe")
    assert r["ok"]; p.wait(timeout=5)
    assert agent.db.one("SELECT 1 FROM actions_audit WHERE action='response_terminate' AND result='ok'")


def test_response_refuses_protected_and_self(agent):
    from guardian import response
    import psutil
    me = psutil.Process()
    agent.procs["me"] = {"key": "me", "pid": os.getpid(), "name": "python", "exe": sys.executable, "start_ts": me.create_time(), "simulated": False}
    with pytest.raises(response.ActionError, match="protected"):
        response.execute(agent, "terminate", "me", "python")
    with pytest.raises(response.ActionError, match="synthetic"):
        simulate.run(agent, "drop_and_execute")
        response.execute(agent, "terminate", next(k for k in agent.procs if k.startswith("sim:")), "x")


def test_response_quarantine_and_restore(agent, tmp_path, monkeypatch):
    from guardian import response
    monkeypatch.setattr(response, "qdir", lambda: (tmp_path / "q").mkdir(exist_ok=True) or tmp_path / "q")
    p, ps = _spawn(tmp_path, "dropper.exe"); exe = tmp_path / "dropper.exe"; pi = _reg(agent, p, ps, exe)
    r = response.execute(agent, "quarantine", pi["key"], "dropper.exe")
    assert r["ok"] and not exe.exists()
    item = response.quarantine_list()[0]
    assert response.restore(agent, item["id"])["ok"] and exe.exists()
    p.wait(timeout=5)


# ---------------------------------------------------------------- datasets/ folder + one-button training pipeline
def _ds():
    primary = config.ROOT / "ai" / "malware-pe"
    fallback = config.ROOT / "optional" / "ai" / "malware-pe"
    extractor_dir = primary if primary.exists() else fallback
    sys.path.insert(0, str(extractor_dir))
    import datasets
    return datasets


@_ml_test
def test_dataset_scan_unpacks_zip_and_reads_csv(tmp_path):
    import zipfile, csv, random
    ds = _ds()
    with zipfile.ZipFile(tmp_path / "Win64_test.zip", "w") as z:
        z.writestr("Win64_test/2023-10-08_Win64_test.jsonl", '{"label": 1}\n{"label": 0}\n')
        z.writestr("Win64_test/2023-10-08_ELF_test.jsonl", '{"label": 1}\n')
    cols = ["Machine", "NumberOfSections", "SizeOfCode", "SizeOfImage", "SectionsMeanEntropy", "ImportsNb", "e_lfanew", "Subsystem", "SizeOfHeaders"]
    r = random.Random(3)
    with open(tmp_path / "t.csv", "w", newline="") as f:
        w = csv.writer(f, delimiter=";"); w.writerow(["Name", *cols, "legitimate"])
        for i in range(200):
            lab = i % 2; w.writerow([f"f{i}", *[r.random() * (1 + lab) for _ in cols], lab])
    (tmp_path / "benign").mkdir(); (tmp_path / "benign" / "a.exe").write_bytes(b"MZ" + b"\0" * 2000)
    (tmp_path / "malware").mkdir(); (tmp_path / "malware" / "b.exe").write_bytes(b"MZ" + b"\1" * 2000)
    s = ds.scan(tmp_path, unpack=True)
    assert s["ember"]["found"] and s["ember"]["test_files"] == 1          # the ELF file is not a PE and is skipped
    assert s["folders"]["found"] and s["folders"]["benign"] == 1 and s["folders"]["malware"] == 1
    c = s["csv"][0]; assert c["usable"] and c["usable_columns"] == len(cols) and c["label_column"] == "legitimate" and c["kind"] == "pe_header_fields"
    assert s["chosen"] == "ember"                                          # best source wins


@_ml_test
def test_csv_training_end_to_end_with_quality_gate(tmp_path):
    import csv, random
    sys.path.insert(0, str(config.ROOT / "ai" / "malware-pe")); import train
    cols = ["Machine", "NumberOfSections", "SizeOfCode", "SizeOfImage", "SectionsMeanEntropy", "ImportsNb", "e_lfanew", "Subsystem", "SizeOfHeaders", "SectionsNb"]
    ds_dir = tmp_path / "datasets"; ds_dir.mkdir(); r = random.Random(5)
    with open(ds_dir / "t.csv", "w", newline="") as f:
        w = csv.writer(f); w.writerow([*cols, "label"])
        for i in range(600):
            lab = r.randint(0, 1); w.writerow([r.random() for _ in cols] + [lab])        # random labels: must NOT pass the quality gate
    out = train.main(["--datasets-dir", str(ds_dir), "--out", str(tmp_path / "reg"), "--version", "c1", "--rounds", "10"])
    card = json.loads((out / "model_card.json").read_text())
    assert card["feature_schema_version"] == "csv_pefields_v1" and len(card["columns"]) == len(cols)
    assert card["validated"] is False and "NOT passed" in card["quality_gate"]
    from guardian.pe import PEModel
    m = PEModel(tmp_path / "reg"); assert m.loaded and not m.validated


@_ml_test
def test_hot_reload_picks_up_new_model(agent, tmp_path):
    sys.path.insert(0, str(config.ROOT / "ai" / "malware-pe")); import train
    assert not agent.model.loaded
    train.main(["--synthetic", "--out", str(config.MODEL_DIR / "malware-pe"), "--version", "2099.01.01.0000", "--rounds", "10"])
    agent.reload_model()
    assert agent.model.loaded and not agent.model.validated
    assert agent.trainer is not None and agent.trainer.datasets()["missing_components"] == []


def test_guardian_shell_pipeline(agent):
    res = commands.run(agent, "echo hello | grep hello | wc")
    assert res["ok"] is True
    assert "1" in res["output"]


def test_guardian_shell_redirection(agent):
    r1 = commands.run(agent, "echo test > a.txt")
    assert r1["ok"] is True
    r2 = commands.run(agent, "cat < a.txt")
    assert r2["ok"] is True
    assert "test" in r2["output"]


def test_guardian_shell_background_job_control(agent):
    r1 = commands.run(agent, "sleep 2 &")
    assert r1["ok"] is True
    assert "[1]" in r1["output"]

    r2 = commands.run(agent, "jobs")
    assert r2["ok"] is True
    assert "[1]" in r2["output"]
    assert "running" in r2["output"] or "sleep" in r2["output"]

    r3 = commands.run(agent, "kill 1")
    assert r3["ok"] is True
    assert "[1]" in r3["output"] or "terminated" in r3["output"]

    r4 = commands.run(agent, "jobs")
    assert r4["ok"] is True
    assert "terminated" in r4["output"]


def test_guardian_shell_os_inspection_and_security(agent):
    agent.procs["1:0"] = {"pid": 1, "ppid": 0, "name": "system", "rss": 1024}
    agent.procs["2:1"] = {"pid": 2, "ppid": 1, "name": "child", "rss": 2048}
    r = commands.run(agent, "pstree")
    assert r["ok"] is True and "system" in r["output"] and "child" in r["output"]
    assert "├─" in r["output"] or "└─" in r["output"]

    rt = commands.run(agent, "threads")
    assert rt["ok"] is True and "Bounded EventQueue" in rt["output"]

    bad = commands.run(agent, "cat ../secret.txt")
    assert bad["ok"] is False and "sandbox" in bad["output"]


def test_agent_thread_status_and_health(agent):
    threads = agent.thread_status()
    assert isinstance(threads, list)
    names = {t["name"] for t in threads}
    roles = {t["role"] for t in threads}
    assert "enricher" in names
    assert "worker (SHA-256 / Authenticode)" in roles
    enricher_entry = next(t for t in threads if t["name"] == "enricher")
    assert "queue_depth" in enricher_entry

    h = agent.health()
    assert "threads" in h
    assert isinstance(h["threads"], list)
    assert any(t["name"] == "enricher" for t in h["threads"])


