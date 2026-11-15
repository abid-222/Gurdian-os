import json, time
from guardian import normalize, engine, config
from guardian.queue import EventQueue
from guardian.collectors import winevents


def test_redaction():
    cmd, flags = normalize.redact_cmdline(r'app.exe --token=abc123 C:\Users\alice\Doc.txt password=hunter2')
    assert "abc123" not in cmd and "hunter2" not in cmd and "alice" not in cmd
    assert "command_line" not in flags and flags


def test_event_envelope():
    e = normalize.make_event("h1", "psutil", "process_start", pid=1, image_path=r"C:\Users\bob\x.exe", attributes={"command_line": "x --password=1"})
    assert e["schema_version"] == 1 and e["timestamp_utc"].endswith("Z") and "bob" not in e["process"]["image_path"]
    assert "command_line_redacted" in e["privacy_flags"] and normalize.validate_event(e)


def test_queue_backpressure_and_shedding():
    q = EventQueue(max_events=100, max_bytes=10**9)
    mk = lambda t: normalize.make_event("h", "sysmon", t)
    for _ in range(95):
        q.put(mk("process_start"))
    assert q.state() == "shedding"
    assert q.put(mk("image_load")) is False                # low priority shed first
    assert q.put(mk("process_start")) is True              # important events kept
    assert q.dropped_by_source["sysmon"] == 1 and q.stats()["dropped"] == 1


def test_severity_policy():
    pol = config.load_policy()
    s = engine.severity_for
    assert s({"E4"}, pol) == "informational"
    assert s({"E2"}, pol) == "low"
    assert s({"E4", "E6"}, pol) == "informational"          # tuned: two weak classes stay quiet
    assert s({"E2", "E4"}, pol) == "medium"
    assert s({"E1"}, pol) == "medium"
    assert s({"E2", "E3", "E4"}, pol) == "high"
    assert s({"E2", "E3", "E4"}, pol, validated_rule_hit=True) == "critical"
    assert s({"E4", "E5", "E6"}, pol) == "medium"           # 3 classes but only one medium, no strong -> not High


def test_sysmon_fixture_parsing_and_mapping():
    xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>13</EventID>
    <TimeCreated SystemTime="2026-11-11T02:15:00.123456700Z"/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><EventRecordID>9</EventRecordID></System>
    <EventData><Data Name="Image">C:\\Users\\x\\AppData\\a.exe</Data><Data Name="ProcessId">4242</Data>
    <Data Name="TargetObject">HKU\\S\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Upd</Data></EventData></Event>
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>1102</EventID><TimeCreated SystemTime="2026-11-11T02:16:00Z"/>
    <Channel>Security</Channel></System></Event>"""
    recs = winevents.parse_events(xml)
    assert [r["event_id"] for r in recs] == [13, 1102]
    et, kw = winevents.map_event(recs[0])
    assert et == "persistence_change" and kw["attributes"]["run_key"] and kw["pid"] == 4242
    et2, kw2 = winevents.map_event(recs[1])
    assert et2 == "sensor_tamper" and kw2["attributes"]["kind"] == "log_cleared"


def test_audit_chain(agent):
    agent.db.audit("user", "a"); agent.db.audit("user", "b")
    assert agent.db.verify_audit_chain()
    agent.db.execute("UPDATE actions_audit SET detail='tampered' WHERE action_id=1")
    assert not agent.db.verify_audit_chain()


def test_migration_and_wal(agent):
    assert agent.db.one("PRAGMA journal_mode")["journal_mode"] == "wal"
    assert agent.db.one("SELECT version FROM schema_migrations")["version"] == 1
