"""REAL end-to-end test of the live pipeline (no synthetic events).

Launches harmless real processes on THIS machine, lets Guardian's real collectors see them, then asks the local API whether the
expected evidence classes were raised. Nothing malicious is executed: only copies of OS utilities (ping/cmd/sleep) and an echo.
Run Guardian first (run.bat), keep it open, then:   .venv\\Scripts\\python testbed\\run_real_scenarios.py
Exit code 0 = every scenario behaved as expected.  Use only on your own machine / a disposable VM (proposal 19.1, 21.3).
"""
import json, os, pathlib, shutil, subprocess, sys, tempfile, time, urllib.request

WIN = sys.platform.startswith("win")


def runtime():
    base = os.environ.get("LOCALAPPDATA") if WIN else str(pathlib.Path.home() / ".local" / "share")
    f = pathlib.Path(base) / "SmartOSGuardian" / "runtime.json"
    if not f.exists():
        sys.exit("Guardian is not running (runtime.json missing). Start run.bat first.")
    return json.loads(f.read_text())


RT = runtime()


def api(path):
    req = urllib.request.Request(f"http://127.0.0.1:{RT['port']}/api/v1{path}", headers={"X-Guardian-Token": RT["token"]})
    return json.load(urllib.request.urlopen(req, timeout=10))


def incidents():
    return api("/alerts?limit=200")["items"]


def wait_for(pred, timeout=40):
    end = time.time() + timeout
    while time.time() < end:
        hit = next((i for i in incidents() if pred(i)), None)
        if hit:
            return hit
        time.sleep(2)
    return None


def workdir():
    d = pathlib.Path(tempfile.gettempdir()) / "guardian_realtest" / ("AppData" if WIN else "Downloads")
    d.mkdir(parents=True, exist_ok=True)      # path contains a user-writable marker (\\temp\\ or /tmp/) so rule E3 applies
    return d


def scenario_drop_and_execute(tag):
    """E3: an executable is created in a user-writable folder and run within seconds."""
    d = workdir()
    name = f"g{tag}up.exe"          # <=15 chars so Linux dev mode (comm name) matches too
    src = pathlib.Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "ping.exe" if WIN else pathlib.Path("/bin/sleep")
    dst = d / name
    shutil.copy2(src, dst)
    os.utime(dst, None)
    args = [str(dst), "-n", "6", "127.0.0.1"] if WIN else [str(dst), "8"]
    p = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    hit = wait_for(lambda i: name.lower() in (i["summary"] or "").lower() and "E3" in i["classes"])
    p.wait(timeout=30)
    dst.unlink(missing_ok=True)
    return hit is not None, f"expected E3 on {name}", hit


def scenario_script_host_child(tag):
    """E2: a script host (wscript.exe) launches a shell (cmd.exe)."""
    d = workdir()
    if WIN:
        vbs = d / f"gtest_{tag}.vbs"
        vbs.write_text('CreateObject("WScript.Shell").Run "cmd.exe /c ping -n 6 127.0.0.1 > nul", 0, True\n')
        p = subprocess.Popen(["wscript.exe", "//B", "//Nologo", str(vbs)])
        hit = wait_for(lambda i: "E2" in i["classes"] and "wscript.exe" in (i["summary"] or "").lower())
        p.wait(timeout=30)
        vbs.unlink(missing_ok=True)
    else:                                     # developer mode on Linux: renamed copies make the same parent/child shape
        host, child = d / "wscript.exe", d / "cmd.exe"
        shutil.copy2("/bin/sh", host); shutil.copy2("/bin/sleep", child)
        p = subprocess.Popen([str(host), "-c", f"{child} 8; true"])
        hit = wait_for(lambda i: "E2" in i["classes"] and "wscript.exe" in (i["summary"] or "").lower())
        p.wait(timeout=30)
        host.unlink(missing_ok=True); child.unlink(missing_ok=True)
    return hit is not None, "expected E2 (script host -> shell)", hit


def scenario_benign_control(tag):
    """Negative control: a normal OS tool must not raise an incident."""
    before = {i["incident_id"] for i in incidents()}
    cmd = ["ping.exe", "-n", "4", "127.0.0.1"] if WIN else ["sleep", "5"]
    subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    time.sleep(8)
    new = [i for i in incidents() if i["incident_id"] not in before and not i["simulated"]]
    names = {i["process_name"] for i in new}
    bad = [i for i in new if i["process_name"] in ("ping.exe", "sleep", "ping")]
    return not bad, "expected NO incident for a normal system tool", bad[0] if bad else None


def main():
    tag = str(int(time.time()) % 100000)
    results = []
    for fn in (scenario_drop_and_execute, scenario_script_host_child, scenario_benign_control):
        ok, what, hit = fn(tag)
        results.append(ok)
        extra = f"  -> {hit['incident_id']} {hit['severity']} classes={hit['classes']}" if hit else ""
        print(f"[{'PASS' if ok else 'FAIL'}] {fn.__name__}: {what}{extra}")
    print("\nAll real scenarios passed." if all(results) else "\nSome scenarios failed: check Guardian's Security Center and logs/guardian.log.")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
