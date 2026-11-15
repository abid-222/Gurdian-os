"""Safe, non-destructive scenario replay for demos and tests.

Nothing is executed. Synthetic process records and events are injected, clearly labelled source='simulation'
and process keys prefixed 'sim:'. This mirrors the controlled-testbed idea (proposal 21.3): labels come from the scenario manifest.
"""
from __future__ import annotations
import time, json, pathlib
from . import config

SCENARIOS = {
    "drop_and_execute": {
        "title": "Document macro drops and runs an unsigned binary, connects out, adds startup entry",
        "expected_classes": ["E2", "E3", "E4", "E5", "E6"],
    },
    "benign_dev_tools": {
        "title": "Noisy but legitimate: unsigned dev tool in AppData (should stay quiet)",
        "expected_classes": ["E4"],
    },
    "log_cleared": {
        "title": "Observation: Windows System log cleared (sensor tampering)",
        "expected_classes": [],
    },
}


def run(agent, name: str) -> dict:
    if name not in SCENARIOS:
        raise KeyError(name)
    now = time.time()
    tag = f"sim:{name}:{int(now)}"
    pol = agent.engine.policy
    made = []

    def proc(suffix, pid, name_, exe, parent_key, parent_name, signer, created_before, started_at, **kw):
        key = f"{tag}:{suffix}"
        pi = {"key": key, "pid": pid, "ppid": 0, "parent_key": parent_key, "parent_name": parent_name, "name": name_, "exe": exe,
              "start_ts": started_at, "exe_created_ts": started_at - created_before if created_before is not None else None,
              "preexisting": False, "sha256": kw.get("sha256"), "signer": signer, "cpu": 0.0, "rss": 20_000_000,
              "cmdline": kw.get("cmdline"), "simulated": True, "first_outbound_ts": kw.get("outbound_ts"),
              "first_outbound": kw.get("outbound")}
        agent.procs[key] = pi
        agent.emit("simulation", "process_start", pid=pid, parent_pid=0, process_key=key, image_path=exe, sha256=pi["sha256"],
                   ts=started_at, attributes={"name": name_, "parent_name": parent_name, "command_line": pi["cmdline"],
                                              "scenario": name, "simulated": True})
        made.append(key)
        return pi

    if name == "drop_and_execute":
        t0 = now - 20
        word = proc("word", 4100, "winword.exe", r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", None, "explorer.exe",
                    "signed", None, t0 - 30)
        word["preexisting"] = False
        ps = proc("ps", 4188, "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", word["key"], "winword.exe",
                  "signed", None, t0, cmdline="powershell -nop -w hidden -enc " + "A" * 60)
        payload = proc("payload", 4210, "updater_svc.exe", r"C:\Users\demo\AppData\Local\Temp\updater_svc.exe", ps["key"], "powershell.exe",
                       "unsigned", 6, t0 + 8, sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                       cmdline="updater_svc.exe --token=abcd1234secret", outbound_ts=t0 + 15, outbound="203.0.113.50:443")
        agent.emit("simulation", "persistence_change", pid=4210, process_key=payload["key"], image_path=payload["exe"],
                   ts=t0 + 17, inline=True,
                   attributes={"target": r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Updater", "run_key": True,
                               "sysmon": True, "scenario": name})
    elif name == "benign_dev_tools":
        proc("node", 5200, "devtool.exe", r"C:\Users\demo\AppData\Local\devtool\devtool.exe", None, "code.exe", "unsigned", None, now - 10)
    elif name == "log_cleared":
        agent.emit("simulation", "sensor_tamper", ts=now, inline=True,
                   attributes={"kind": "log_cleared", "log": "Security", "event_id": 1102})
    for k in made:
        agent.engine.evaluate_process(agent.procs[k])
    agent.engine.correlate()
    agent.db.audit("user", "simulate", name, "ok", "synthetic scenario, nothing executed")
    return {"scenario": name, "keys": made, "expected_classes": SCENARIOS[name]["expected_classes"]}


def clear(agent):
    for k in [k for k in agent.procs if k.startswith("sim:")]:
        agent.procs.pop(k, None)
    agent.db.execute("DELETE FROM detections WHERE process_key LIKE 'sim:%'")
    agent.db.execute("DELETE FROM incidents WHERE simulated=1")
    agent.db.execute("DELETE FROM events WHERE source='simulation'")
