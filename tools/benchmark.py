"""Measure the proposal's section 21.1 targets on THIS machine against a running Guardian (real measurements, no estimates).

  python tools/benchmark.py --idle 120 --busy 60          (use --idle 1800 for the full 30 min idle test)

Measures: idle CPU, busy CPU (mean/p95) under a scripted process-launch workload, RSS of the agent process, event-drop rate,
alert latency (process start -> incident visible via API) and PE scoring latency (if a validated model is installed).
Writes docs/benchmarks/benchmark-<host>-<date>.json and prints a PASS/MISS table. Misses are reported, never hidden (section 21.1).
"""
import argparse, json, os, pathlib, platform, shutil, statistics, subprocess, sys, tempfile, time, urllib.request
import psutil

WIN = sys.platform.startswith("win")
ROOT = pathlib.Path(__file__).resolve().parents[1]


def runtime():
    base = os.environ.get("LOCALAPPDATA") if WIN else str(pathlib.Path.home() / ".local" / "share")
    f = pathlib.Path(base) / "SmartOSGuardian" / "runtime.json"
    if not f.exists():
        sys.exit("Guardian is not running. Start run.bat first.")
    return json.loads(f.read_text())


RT = runtime()


def api(path):
    req = urllib.request.Request(f"http://127.0.0.1:{RT['port']}/api/v1{path}", headers={"X-Guardian-Token": RT["token"]})
    return json.load(urllib.request.urlopen(req, timeout=10))


def sample(proc, seconds):
    cpu, rss = [], []
    proc.cpu_percent(None)
    end = time.time() + seconds
    while time.time() < end:
        time.sleep(1)
        cpu.append(proc.cpu_percent(None) / psutil.cpu_count())          # share of the whole machine, like Task Manager
        rss.append(proc.memory_info().rss)
    return cpu, rss


def p95(v):
    v = sorted(v)
    return v[min(len(v) - 1, int(len(v) * 0.95))] if v else 0.0


def workload(seconds):
    """Scripted, harmless workload: many short-lived processes + file writes."""
    d = pathlib.Path(tempfile.gettempdir()) / "guardian_bench"; d.mkdir(exist_ok=True)
    cmd = ["ping.exe", "-n", "2", "127.0.0.1"] if WIN else ["sleep", "1"]       # each process lives ~1 s
    end, n, running = time.time() + seconds, 0, []
    while time.time() < end:
        running = [p for p in running if p.poll() is None]
        if len(running) < 8:
            running.append(subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)); n += 1
        (d / f"f{n % 50}.txt").write_text("x" * 1024)
        time.sleep(0.1)
    for p in running:
        p.wait()
    shutil.rmtree(d, ignore_errors=True)
    return n


def alert_latency():
    d = pathlib.Path(tempfile.gettempdir()) / "guardian_bench"; d.mkdir(exist_ok=True)
    name = f"b{int(time.time()) % 100000}up.exe"
    dst = d / name
    shutil.copy2(pathlib.Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "ping.exe" if WIN else "/bin/sleep", dst)
    t0 = time.time()
    p = subprocess.Popen([str(dst), "-n", "6", "127.0.0.1"] if WIN else [str(dst), "8"], stdout=subprocess.DEVNULL)
    while time.time() - t0 < 60:
        hit = next((i for i in api("/alerts?limit=50")["items"] if name.lower() in (i["summary"] or "").lower()), None)
        if hit:
            took = round(time.time() - t0, 2)
            p.wait(); dst.unlink(missing_ok=True)
            return took
        time.sleep(0.25)
    p.kill(); dst.unlink(missing_ok=True)
    return None


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--idle", type=int, default=120); ap.add_argument("--busy", type=int, default=60)
    a = ap.parse_args()
    agent = psutil.Process(RT["pid"])
    q0 = api("/health")["queue"]
    print(f"idle phase {a.idle}s ..."); cpu_i, rss_i = sample(agent, a.idle)
    print(f"busy phase {a.busy}s ...")
    import threading
    out = {}
    t = threading.Thread(target=lambda: out.update(n=workload(a.busy))); t.start()
    cpu_b, rss_b = sample(agent, a.busy); t.join()
    time.sleep(3)
    q1 = api("/health")["queue"]
    gen, drop = q1["generated"] - q0["generated"], q1["dropped"] - q0["dropped"]
    lat = alert_latency()
    h = api("/health")
    model = None
    try:
        sample_pe = sys.executable
        r = api("/models")
        if r.get("validated"):
            t0 = time.perf_counter(); import urllib.request as u
            req = u.Request(f"http://127.0.0.1:{RT['port']}/api/v1/scan", data=json.dumps({"path": sample_pe}).encode(),
                            headers={"X-Guardian-Token": RT["token"], "Content-Type": "application/json"})
            res = json.load(u.urlopen(req)); model = res.get("model")
    except Exception:
        pass
    res = {"host": platform.node(), "os": f"{platform.system()} {platform.release()}", "cpu_count": psutil.cpu_count(), "ram_gb": round(psutil.virtual_memory().total / 2**30, 1),
           "date": time.strftime("%Y-%m-%d %H:%M:%S"), "agent_version": h["version"], "idle_s": a.idle, "busy_s": a.busy,
           "idle_cpu_mean_pct": round(statistics.mean(cpu_i), 2), "busy_cpu_mean_pct": round(statistics.mean(cpu_b), 2), "busy_cpu_p95_pct": round(p95(cpu_b), 2),
           "rss_mb_max": round(max(rss_i + rss_b) / 2**20, 1), "workload_processes": out.get("n"), "events_generated": gen, "events_dropped": drop, "launched_processes_observed": (api("/events/stats")["last_hour"].get("process_start", 0)),
           "drop_rate_pct": round(100 * drop / gen, 4) if gen else 0.0, "alert_latency_s": lat,
           "pe_scoring_ms": model["inference_time_ms"] if model else "no validated model installed"}
    T = [("Idle CPU < 3 %", res["idle_cpu_mean_pct"] < 3), ("Busy CPU mean < 10 %", res["busy_cpu_mean_pct"] < 10), ("Busy CPU p95 < 20 %", res["busy_cpu_p95_pct"] < 20),
         ("RAM <= 300 MB", res["rss_mb_max"] <= 300), ("Event drop < 0.1 %", res["drop_rate_pct"] < 0.1),
         ("Alert latency p95 < 2 s (single sample)", lat is not None and lat < 2)]
    res["targets"] = {k: ("PASS" if ok else "MISS") for k, ok in T}
    outf = ROOT / "docs" / "benchmarks" / f"benchmark-{platform.node()}-{time.strftime('%Y%m%d-%H%M')}.json"
    outf.write_text(json.dumps(res, indent=2))
    print(json.dumps(res, indent=2)); print("saved", outf)


if __name__ == "__main__":
    main()
