import json, time, pytest
from fastapi.testclient import TestClient
from guardian import simulate
from guardian.api import create_app

TOKEN = "t" * 43


@pytest.fixture()
def client(agent):
    app = create_app(agent, TOKEN)
    return TestClient(app, base_url="http://127.0.0.1:8123"), agent


H = {"X-Guardian-Token": TOKEN}


def test_drop_and_execute_one_linked_incident(agent):
    simulate.run(agent, "drop_and_execute")
    incs = agent.db.query("SELECT * FROM incidents WHERE simulated=1")
    assert len(incs) == 1, "scenario must produce ONE linked incident (M5 exit criterion)"
    i = incs[0]
    classes = set(json.loads(i["classes"]))
    assert {"E2", "E3", "E4", "E5", "E6"} <= classes
    assert i["severity"] == "high"                      # never critical without a validated rule
    assert "Unknown is not malicious" in i["caveat"]


def test_benign_scenario_stays_quiet(agent):
    simulate.run(agent, "benign_dev_tools")
    assert agent.db.query("SELECT * FROM incidents") == []
    assert agent.db.one("SELECT COUNT(*) c FROM detections")["c"] == 1     # kept as a quiet timeline entry


def test_log_cleared_observation(agent):
    simulate.run(agent, "log_cleared")
    r = agent.db.query("SELECT * FROM incidents")
    assert len(r) == 1 and r[0]["severity"] == "medium"


def test_allowlist_suppresses(agent):
    agent.db.execute("INSERT INTO allowlist VALUES('path',?,?,?)", (r"C:\Users\demo\AppData\Local\Temp\updater_svc.exe", "test", time.time()))
    simulate.run(agent, "drop_and_execute")
    classes = {r["evidence_class"] for r in agent.db.query("SELECT evidence_class FROM detections")}
    assert "E3" not in classes and "E4" not in classes


def test_api_auth_host_origin(client):
    c, agent = client
    assert c.get("/api/v1/health").status_code == 401
    assert c.get("/api/v1/health", headers={"X-Guardian-Token": "wrong" * 9}).status_code == 401
    assert c.get("/api/v1/health", headers=H).status_code == 200
    assert c.get("/api/v1/health", headers={**H, "Host": "evil.example.com"}).status_code == 403          # DNS rebinding
    assert c.get("/api/v1/health", headers={**H, "Origin": "https://evil.example.com"}).status_code == 403  # cross-site
    assert c.get("/api/v1/health", headers={**H, "Origin": "http://127.0.0.1:8123"}).status_code == 200


def test_api_actions_preview_is_harmless_and_execute_is_guarded(client):
    c, agent = client
    r = c.post("/api/v1/actions/preview", headers=H, json={"action": "terminate", "target": "123"})
    assert r.status_code == 200 and r.json()["executed"] is False
    assert c.post("/api/v1/actions/execute", headers=H, json={}).status_code == 422                  # schema enforced
    r = c.post("/api/v1/actions/execute", headers=H, json={"action": "terminate", "target": "999999", "confirm_name": "x"})
    assert r.status_code == 400 and "not found" in r.json()["detail"]                                 # unknown target: refused, nothing executed
    assert c.post("/api/v1/actions/execute", json={"action": "terminate", "target": "1", "confirm_name": "x"}).status_code in (401, 403)


def test_api_input_validation(client):
    c, agent = client
    assert c.put("/api/v1/settings/privacy", headers=H, json={"retention_days_events": 9999}).status_code == 422
    assert c.post("/api/v1/terminal", headers=H, json={"line": "rm -rf /"}).json()["ok"] is False
    assert c.request("DELETE", "/api/v1/data", headers=H, json={"confirm": "no"}).status_code in (400, 422)


def test_terminal_and_scan(client, tmp_path):
    c, agent = client
    assert "status" in c.post("/api/v1/terminal", headers=H, json={"line": "help"}).json()["output"]
    f = tmp_path / "x.bin"; f.write_bytes(b"MZ" + b"\x00" * 100)
    out = c.post("/api/v1/terminal", headers=H, json={"line": f"scan --file {f}"}).json()["output"]
    assert "executed: never" in out and ("not installed" in out or "no model installed" in out)


def test_ack_and_dismiss_audited(client):
    c, agent = client
    simulate.run(agent, "drop_and_execute")
    iid = agent.db.one("SELECT incident_id FROM incidents")["incident_id"]
    assert c.post(f"/api/v1/alerts/{iid}/acknowledge", headers=H).json()["ok"]
    assert c.post(f"/api/v1/alerts/{iid}/dismiss", headers=H, json={"reason": "expected"}).json()["ok"]
    d = c.get(f"/api/v1/alerts/{iid}", headers=H).json()
    assert [a["action"] for a in d["audit"]] == ["acknowledge", "dismiss"] and agent.db.verify_audit_chain()
