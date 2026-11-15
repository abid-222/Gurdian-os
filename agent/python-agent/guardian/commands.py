"""Guardian Shell: Lexical parser, pipelines, sandboxed redirection, job control, and OS inspection."""
from __future__ import annotations
import os, sys, time, json, shlex, pathlib, threading
from . import config, pe, normalize

HELP = """Guardian Shell commands:
  help                      show this list
  status                    agent, database, queue and model health
  sources                   telemetry sources and their capability state
  system                    CPU / RAM / disk summary
  processes [--top N]       top resource-consuming processes
  pstree                    parent-child process tree (ASCII)
  threads                   bounded queue stats & active threads table
  alerts [--recent]         recent incidents
  timeline [--hours N]      recent correlated activity
  scan --file <path>        analyse file metadata (parsed, never executed)
  models                    installed model versions
  privacy                   telemetry and retention settings
  version                   show version information

Shell Utilities:
  echo <text>               print text
  cat [file]                read file or print stdin
  ls                        list files in sandboxed shell workspace
  grep [-i] <pattern>       filter lines matching pattern (-i: case-insensitive)
  head [-n N]               output first N lines (default 10)
  tail [-n N]               output last N lines (default 10)
  wc                        count lines, words, and characters
  sort [-r]                 sort lines alphabetically (-r: reverse)
  sleep <sec>               pause for specified seconds

Job Control:
  <command> &               run command as a background job
  jobs                      list background jobs
  fg <id>                   bring job to foreground
  bg <id>                   resume stopped job in background
  kill <id>                 terminate a background job

Pipelines & Redirection:
  cmd1 | cmd2               pipe stdout of cmd1 to stdin of cmd2
  cmd > file                redirect stdout to sandboxed file (overwrite)
  cmd >> file               redirect stdout to sandboxed file (append)
  cmd < file                read stdin from sandboxed file

Examples:
  processes --top 15 | grep python | wc
  pstree | grep python
  echo "hello world" > greeting.txt
  cat < greeting.txt | grep hello
  sleep 10 &
  jobs
  kill 1"""


def _fmt_bytes(n):
    n = float(n or 0)
    for u in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024:
            return f"{n:.0f} {u}" if u == "B" else f"{n:.1f} {u}"
        n /= 1024
    return f"{n:.1f} PB"


def split_line(line: str) -> list[str]:
    """Split a command line the way a user expects on Windows: backslashes stay literal, "double quotes" group a
    path with spaces and are removed. (shlex in non-POSIX mode keeps the quote characters, which broke
    `scan --file "C:\\Program Files\\x.exe"`.)"""
    parts = shlex.split(line, posix=False)
    out = []
    for p in parts:
        if len(p) >= 2 and p[0] == p[-1] and p[0] in "\"'":
            p = p[1:-1]
        out.append(p)
    return out


def strip_quotes(s: str) -> str:
    """Strip matching outer quotes if present."""
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("\"", "'"):
        return s[1:-1]
    return s


def tokenize_shell(line: str) -> list[str]:
    """Tokenize a shell command line while respecting quotes and recognizing shell operators: |, >>, >, <, &."""
    tokens = []
    i = 0
    n = len(line)
    while i < n:
        c = line[i]
        if c.isspace():
            i += 1
            continue

        if c == ">":
            if i + 1 < n and line[i + 1] == ">":
                tokens.append(">>")
                i += 2
            else:
                tokens.append(">")
                i += 1
            continue

        if c in ("|", "<", "&"):
            tokens.append(c)
            i += 1
            continue

        word = []
        while i < n and not line[i].isspace() and line[i] not in ("|", "<", ">", "&"):
            ch = line[i]
            if ch in ("\"", "'"):
                quote_char = ch
                word.append(quote_char)
                i += 1
                while i < n and line[i] != quote_char:
                    word.append(line[i])
                    i += 1
                if i < n and line[i] == quote_char:
                    word.append(quote_char)
                    i += 1
            else:
                word.append(ch)
                i += 1
        tok = "".join(word)
        if tok:
            tokens.append(tok)
    return tokens


def _safe_shell_path(filename: str) -> pathlib.Path:
    """Resolve a path strictly inside config.data_dir() / 'shell' to prevent traversal."""
    base = (config.data_dir() / "shell").resolve()
    base.mkdir(parents=True, exist_ok=True)
    clean = filename.strip().strip("\"'")
    target = (base / clean).resolve()
    try:
        if not target.is_relative_to(base):
            raise ValueError(f"permission denied: access outside shell sandbox '{filename}'")
    except AttributeError:
        if not str(target).startswith(str(base)):
            raise ValueError(f"permission denied: access outside shell sandbox '{filename}'")
    return target


# ---------------------------------------------------------------------------
# Background Job Control
# ---------------------------------------------------------------------------

class Job:
    def __init__(self, job_id: int, cmd_line: str):
        self.id = job_id
        self.cmd_line = cmd_line
        self.status = "running"  # running, stopped, done, terminated
        self.start_time = time.time()
        self.end_time: float | None = None
        self.output = ""
        self.thread: threading.Thread | None = None
        self.cancel_event = threading.Event()
        self.pause_event = threading.Event()
        self.pause_event.set()

    @property
    def elapsed(self) -> float:
        if self.end_time is not None:
            return self.end_time - self.start_time
        return time.time() - self.start_time


class JobManager:
    """Thread-safe background job manager."""

    def __init__(self):
        self._jobs: dict[int, Job] = {}
        self._next_id = 1
        self._lock = threading.Lock()

    def start_job(self, agent, line: str) -> Job:
        with self._lock:
            jid = self._next_id
            self._next_id += 1
            job = Job(jid, f"{line} &")
            self._jobs[jid] = job

        def target():
            try:
                res = execute_pipeline(agent, line, job=job)
                with self._lock:
                    if job.status != "terminated":
                        job.output = res.get("output", "")
                        job.status = "done"
                        job.end_time = time.time()
            except Exception as e:
                with self._lock:
                    if job.status != "terminated":
                        job.output = f"job error: {e}"
                        job.status = "terminated"
                        job.end_time = time.time()

        t = threading.Thread(target=target, name=f"job-{jid}", daemon=True)
        job.thread = t
        t.start()
        return job

    def list_jobs(self) -> list[Job]:
        with self._lock:
            return list(self._jobs.values())

    def get_job(self, jid: int) -> Job | None:
        with self._lock:
            return self._jobs.get(jid)

    def kill_job(self, jid: int) -> bool:
        with self._lock:
            job = self._jobs.get(jid)
            if not job:
                return False
            if job.status in ("running", "stopped"):
                job.status = "terminated"
                job.end_time = time.time()
                job.cancel_event.set()
                job.pause_event.set()
            return True

    def stop_job(self, jid: int) -> bool:
        with self._lock:
            job = self._jobs.get(jid)
            if not job or job.status != "running":
                return False
            job.status = "stopped"
            job.pause_event.clear()
            return True

    def resume_job(self, jid: int) -> bool:
        with self._lock:
            job = self._jobs.get(jid)
            if not job or job.status != "stopped":
                return False
            job.status = "running"
            job.pause_event.set()
            return True


def get_job_manager(agent) -> JobManager:
    if not hasattr(agent, "jobs") or agent.jobs is None:
        agent.jobs = JobManager()
    return agent.jobs


# ---------------------------------------------------------------------------
# Built-in Commands Implementation
# ---------------------------------------------------------------------------

def _cmd_pstree(agent) -> dict:
    if not agent.procs:
        return {"ok": True, "output": "no processes tracked"}

    procs_by_pid = {}
    children: dict[int, list[int]] = {}
    for p in agent.procs.values():
        pid = p.get("pid")
        if pid is None:
            continue
        procs_by_pid[pid] = p
        children.setdefault(pid, [])

    for pid, p in procs_by_pid.items():
        ppid = p.get("ppid")
        if ppid is not None and ppid in procs_by_pid and ppid != pid:
            children[ppid].append(pid)

    roots = [pid for pid, p in procs_by_pid.items() if p.get("ppid") not in procs_by_pid or p.get("ppid") == 0 or p.get("ppid") == pid]
    roots.sort()

    lines = []
    visited = set()

    def format_node(pid):
        p = procs_by_pid[pid]
        rss = _fmt_bytes(p.get("rss", 0))
        ppid = p.get("ppid", "?")
        name = p.get("name", "unknown")
        return f"{name} (PID: {pid}, PPID: {ppid}, RSS: {rss})"

    def render_children(parent_pid, prefix=""):
        ch_list = sorted(children.get(parent_pid, []))
        for i, cpid in enumerate(ch_list):
            if cpid in visited:
                continue
            visited.add(cpid)
            is_last = (i == len(ch_list) - 1)
            branch = "└─ " if is_last else "├─ "
            lines.append(f"{prefix}{branch}{format_node(cpid)}")
            child_prefix = prefix + ("   " if is_last else "│  ")
            render_children(cpid, child_prefix)

    for rpid in roots:
        if rpid in visited:
            continue
        visited.add(rpid)
        lines.append(format_node(rpid))
        render_children(rpid, "")

    for pid in sorted(procs_by_pid):
        if pid not in visited:
            visited.add(pid)
            lines.append(format_node(pid))
            render_children(pid, "")

    return {"ok": True, "output": "\n".join(lines)}


def _cmd_threads(agent) -> dict:
    q = agent.queue.stats()
    lines = [
        "Bounded EventQueue (Producer-Consumer IPC Buffer):",
        f"  depth          : {q['depth']} / {config.QUEUE_MAX_EVENTS} events ({q['fill_pct']}%)",
        f"  memory (bytes) : {_fmt_bytes(q['bytes'])} / {_fmt_bytes(config.QUEUE_MAX_BYTES)}",
        f"  queue state    : {q['state']}",
        f"  events ingested: {q['generated']}",
        f"  events dropped : {q['dropped']} ({q['drop_rate_pct']}%)",
    ]
    if q.get("dropped_by_source"):
        lines.append(f"  drop by source : {dict(q['dropped_by_source'])}")
    lines.append("")
    lines.append("OS Threads & Synchronization Primitives:")
    lines.append(f"{'NAME':<16} {'ROLE':<30} {'SYNC PRIMITIVE':<32} {'STATUS'}")
    t_status = {t["name"]: t for t in agent.thread_status()}
    for t in sorted(threading.enumerate(), key=lambda x: x.name):
        info = t_status.get(t.name, {})
        role = info.get("role", "worker thread")
        sync = info.get("sync_primitive", "thread")
        status = "alive" if t.is_alive() else "stopped"
        lines.append(f"{t.name:<16} {role:<30} {sync:<32} {status}")
    return {"ok": True, "output": "\n".join(lines)}


def _cmd_sleep(args: list[str], job: Job | None = None) -> dict:
    if not args:
        sec = 1.0
    else:
        try:
            sec = float(args[0])
        except ValueError:
            return {"ok": False, "output": f"sleep: invalid time interval '{args[0]}'"}

    t_end = time.time() + sec
    while time.time() < t_end:
        if job:
            if job.cancel_event.is_set() or job.status == "terminated":
                return {"ok": False, "output": "sleep interrupted"}
            while not job.pause_event.is_set():
                if job.cancel_event.is_set() or job.status == "terminated":
                    return {"ok": False, "output": "sleep interrupted"}
                time.sleep(0.05)
        time.sleep(min(0.05, max(0.0, t_end - time.time())))
    return {"ok": True, "output": ""}


def _cmd_echo(args: list[str]) -> dict:
    return {"ok": True, "output": " ".join(args)}


def _cmd_ls() -> dict:
    sdir = (config.data_dir() / "shell").resolve()
    sdir.mkdir(parents=True, exist_ok=True)
    files = sorted(sdir.iterdir(), key=lambda p: p.name)
    if not files:
        return {"ok": True, "output": "(empty)"}
    lines = [f"{'SIZE':>8}  {'MODIFIED':<19}  NAME"]
    for f in files:
        try:
            st = f.stat()
            sz = _fmt_bytes(st.st_size)
            mtime = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(st.st_mtime))
            lines.append(f"{sz:>8}  {mtime:<19}  {f.name}")
        except OSError:
            lines.append(f"{'?':>8}  {'?':<19}  {f.name}")
    return {"ok": True, "output": "\n".join(lines)}


def _cmd_cat(args: list[str], stdin_text: str = "") -> dict:
    if args:
        filename = args[0]
        try:
            target = _safe_shell_path(filename)
            if not target.is_file():
                return {"ok": False, "output": f"cat: {filename}: No such file or directory"}
            content = target.read_text(encoding="utf-8", errors="replace")
            return {"ok": True, "output": content}
        except ValueError as e:
            return {"ok": False, "output": str(e)}
        except Exception as e:
            return {"ok": False, "output": f"cat: {e}"}
    return {"ok": True, "output": stdin_text}


def _cmd_grep(args: list[str], stdin_text: str = "") -> dict:
    ignore_case = False
    pattern = None
    file_arg = None
    i = 0
    while i < len(args):
        if args[i] == "-i":
            ignore_case = True
        elif pattern is None:
            pattern = args[i]
        elif file_arg is None:
            file_arg = args[i]
        i += 1

    if pattern is None:
        return {"ok": False, "output": "usage: grep [-i] <pattern> [file]"}

    text = stdin_text
    if file_arg:
        try:
            target = _safe_shell_path(file_arg)
            if not target.is_file():
                return {"ok": False, "output": f"grep: {file_arg}: No such file or directory"}
            text = target.read_text(encoding="utf-8", errors="replace")
        except ValueError as e:
            return {"ok": False, "output": str(e)}

    lines = text.splitlines()
    matched = []
    pat = pattern.lower() if ignore_case else pattern
    for line in lines:
        target_str = line.lower() if ignore_case else line
        if pat in target_str:
            matched.append(line)
    return {"ok": True, "output": "\n".join(matched)}


def _cmd_head(args: list[str], stdin_text: str = "") -> dict:
    n = 10
    file_arg = None
    i = 0
    while i < len(args):
        if args[i] == "-n" and i + 1 < len(args):
            try:
                n = int(args[i + 1])
            except ValueError:
                return {"ok": False, "output": f"head: invalid number of lines: '{args[i+1]}'"}
            i += 2
            continue
        elif not args[i].startswith("-") and file_arg is None:
            file_arg = args[i]
        i += 1

    text = stdin_text
    if file_arg:
        try:
            target = _safe_shell_path(file_arg)
            if not target.is_file():
                return {"ok": False, "output": f"head: {file_arg}: No such file or directory"}
            text = target.read_text(encoding="utf-8", errors="replace")
        except ValueError as e:
            return {"ok": False, "output": str(e)}

    lines = text.splitlines()[:max(0, n)]
    return {"ok": True, "output": "\n".join(lines)}


def _cmd_tail(args: list[str], stdin_text: str = "") -> dict:
    n = 10
    file_arg = None
    i = 0
    while i < len(args):
        if args[i] == "-n" and i + 1 < len(args):
            try:
                n = int(args[i + 1])
            except ValueError:
                return {"ok": False, "output": f"tail: invalid number of lines: '{args[i+1]}'"}
            i += 2
            continue
        elif not args[i].startswith("-") and file_arg is None:
            file_arg = args[i]
        i += 1

    text = stdin_text
    if file_arg:
        try:
            target = _safe_shell_path(file_arg)
            if not target.is_file():
                return {"ok": False, "output": f"tail: {file_arg}: No such file or directory"}
            text = target.read_text(encoding="utf-8", errors="replace")
        except ValueError as e:
            return {"ok": False, "output": str(e)}

    lines = text.splitlines()
    selected = lines[-n:] if n > 0 else []
    return {"ok": True, "output": "\n".join(selected)}


def _cmd_wc(args: list[str], stdin_text: str = "") -> dict:
    text = stdin_text
    if args:
        file_arg = args[0]
        try:
            target = _safe_shell_path(file_arg)
            if not target.is_file():
                return {"ok": False, "output": f"wc: {file_arg}: No such file or directory"}
            text = target.read_text(encoding="utf-8", errors="replace")
        except ValueError as e:
            return {"ok": False, "output": str(e)}

    lines_count = len(text.splitlines())
    words_count = len(text.split())
    chars_count = len(text)
    return {"ok": True, "output": f"{lines_count:>7} {words_count:>7} {chars_count:>7}"}


def _cmd_sort(args: list[str], stdin_text: str = "") -> dict:
    reverse = "-r" in args
    file_arg = None
    for a in args:
        if a != "-r":
            file_arg = a
            break

    text = stdin_text
    if file_arg:
        try:
            target = _safe_shell_path(file_arg)
            if not target.is_file():
                return {"ok": False, "output": f"sort: {file_arg}: No such file or directory"}
            text = target.read_text(encoding="utf-8", errors="replace")
        except ValueError as e:
            return {"ok": False, "output": str(e)}

    lines = text.splitlines()
    lines.sort(reverse=reverse)
    return {"ok": True, "output": "\n".join(lines)}


def _cmd_jobs(agent) -> dict:
    mgr = get_job_manager(agent)
    all_jobs = mgr.list_jobs()
    if not all_jobs:
        return {"ok": True, "output": "no active jobs"}
    rows = []
    for j in all_jobs:
        rows.append(f"[{j.id}]  {j.status:<11} {j.cmd_line} ({j.elapsed:.1f}s)")
    return {"ok": True, "output": "\n".join(rows)}


def _cmd_fg(agent, args: list[str]) -> dict:
    if not args:
        return {"ok": False, "output": "usage: fg <job_id>"}
    try:
        jid = int(args[0].lstrip("%"))
    except ValueError:
        return {"ok": False, "output": f"fg: invalid job id: {args[0]}"}
    mgr = get_job_manager(agent)
    job = mgr.get_job(jid)
    if not job:
        return {"ok": False, "output": f"fg: no such job: {jid}"}
    if job.status == "stopped":
        mgr.resume_job(jid)
    if job.thread and job.thread.is_alive():
        job.thread.join(timeout=30.0)
    return {"ok": True, "output": job.output}


def _cmd_bg(agent, args: list[str]) -> dict:
    if not args:
        return {"ok": False, "output": "usage: bg <job_id>"}
    try:
        jid = int(args[0].lstrip("%"))
    except ValueError:
        return {"ok": False, "output": f"bg: invalid job id: {args[0]}"}
    mgr = get_job_manager(agent)
    job = mgr.get_job(jid)
    if not job:
        return {"ok": False, "output": f"bg: no such job: {jid}"}
    if job.status == "stopped":
        mgr.resume_job(jid)
        return {"ok": True, "output": f"[{job.id}] {job.cmd_line} &"}
    elif job.status == "running":
        return {"ok": True, "output": f"job {jid} is already running in background"}
    return {"ok": False, "output": f"job {jid} is already {job.status}"}


def _cmd_kill(agent, args: list[str]) -> dict:
    if not args:
        return {"ok": False, "output": "usage: kill <job_id>"}
    try:
        jid = int(args[0].lstrip("%"))
    except ValueError:
        return {"ok": False, "output": f"kill: invalid job id: {args[0]}"}
    mgr = get_job_manager(agent)
    job = mgr.get_job(jid)
    if not job:
        return {"ok": False, "output": f"kill: ({jid}) - No such job"}
    mgr.kill_job(jid)
    return {"ok": True, "output": f"[{job.id}] terminated"}


# ---------------------------------------------------------------------------
# Command Dispatcher
# ---------------------------------------------------------------------------

def execute_single_command(agent, cmd: str, args: list[str], stdin_text: str = "", job: Job | None = None) -> dict:
    cmd = cmd.lower()

    def opt(name, default=None):
        if name in args:
            i = args.index(name)
            return args[i + 1] if i + 1 < len(args) else default
        return default

    if cmd == "help":
        return {"ok": True, "output": HELP}
    if cmd == "version":
        pol = agent.engine.policy.get("policy_version", "1") if hasattr(agent, "engine") and hasattr(agent.engine, "policy") else "1"
        return {"ok": True, "output": f"Smart OS Guardian {config.VERSION}  policy {pol}"}
    if cmd == "status":
        h = agent.health()
        q = h["queue"]
        lines = [f"agent      : {h['status']}  (paused={h['paused']})  uptime {h['uptime_s']}s",
                 f"host       : {h['hostname']}  {h['os']} {h['architecture']}  admin={h['admin']}",
                 f"database   : {_fmt_bytes(h['db']['size_bytes'])}  read_only={h['db']['read_only']}  audit_chain_ok={h['db']['audit_chain_ok']}",
                 f"queue      : {q['depth']} events  {q['fill_pct']}%  state={q['state']}  dropped={q['dropped']} ({q['drop_rate_pct']}%)",
                 f"model      : {'loaded ' + h['model'].get('version', '') if h['model']['loaded'] else 'none installed - rules-only'}",
                 f"degraded   : {', '.join(h['degraded']) or '-'}", f"unavailable: {', '.join(h['unavailable']) or '-'}"]
        return {"ok": True, "output": "\n".join(lines)}
    if cmd == "sources":
        rows = [f"{k:<20} {v['status']:<12} {v.get('reason', '')}" for k, v in agent.sources_health().items()]
        return {"ok": True, "output": "\n".join(rows)}
    if cmd == "system":
        s = agent.resources.latest() if getattr(agent, "resources", None) else None
        if not s:
            return {"ok": False, "output": "no sample yet"}
        return {"ok": True, "output": f"cpu   {s['cpu']:.1f}%  ({s['cpu_count']} cores)\nmem   {s['mem']:.1f}%  {_fmt_bytes(s['mem_used'])} / {_fmt_bytes(s['mem_total'])}\n"
                                      f"disk  {s['disk']}%  free {_fmt_bytes(s['disk_free'])}\nuptime {int(s['uptime'] // 3600)}h {int(s['uptime'] % 3600 // 60)}m\nprocs {s['load_procs']}"}
    if cmd == "processes":
        n = int(opt("--top", 20) or 20)
        rows = sorted(agent.procs.values(), key=lambda v: v.get("rss", 0), reverse=True)[:max(1, min(n, 100))]
        out = [f"{'PID':>7} {'CPU%':>5} {'RSS':>9}  {'SIGNER':<9} NAME"]
        out += [f"{p['pid']:>7} {p.get('cpu', 0):>5.1f} {_fmt_bytes(p.get('rss', 0)):>9}  {p.get('signer', '?'):<9} {p['name']}" for p in rows]
        return {"ok": True, "output": "\n".join(out)}
    if cmd == "alerts":
        rows = agent.db.query("SELECT incident_id, severity, status, title, opened_at FROM incidents ORDER BY opened_at DESC LIMIT 15")
        if not rows:
            return {"ok": True, "output": "no incidents"}
        return {"ok": True, "output": "\n".join(f"{r['incident_id']}  {r['severity'].upper():<13} {r['status']:<13} {r['title']}" for r in rows)}
    if cmd == "timeline":
        hours = float(opt("--hours", 2) or 2)
        rows = agent.db.query("SELECT ts, source, event_type, image_path, attributes FROM events WHERE ts>? ORDER BY ts DESC LIMIT 40",
                              (time.time() - hours * 3600,))
        out = []
        for r in reversed(rows):
            a = json.loads(r["attributes"] or "{}")
            out.append(f"{time.strftime('%H:%M:%S', time.localtime(r['ts']))} {r['source']:<13} {r['event_type']:<18} {a.get('name') or r['image_path'] or ''}")
        return {"ok": True, "output": "\n".join(out) or "no events in range"}
    if cmd == "scan":
        path = opt("--file")
        if not path:
            return {"ok": False, "output": "usage: scan --file <path>"}
        res = pe.scan_file(path, agent.model)
        f = res["file"]
        if not f.get("exists"):
            return {"ok": False, "output": f"not a file: {path}"}
        lines = [f"file     {normalize.redact_path(f['path'])[0]}", f"size     {_fmt_bytes(f['size'])}", f"sha256   {f['sha256']}",
                 f"PE       {f.get('is_pe')}   executed: never", f"model    {res['model_status']}"]
        if f.get("sections"):
            lines.append("sections " + ", ".join(f"{s['name']}(H={s['entropy']})" for s in f["sections"]))
            if f["high_entropy_sections"]:
                lines.append("note     high-entropy sections: " + ", ".join(f["high_entropy_sections"]) + " (packed/encrypted possible; not proof)")
        if res["model"]:
            m = res["model"]
            lines.append(f"score    {m['score']} (threshold {m['threshold']}, model {m['model_version']}, {m['inference_time_ms']} ms)")
        return {"ok": True, "output": "\n".join(lines)}
    if cmd == "models":
        h = agent.model
        return {"ok": True, "output": (f"malware-pe {h.info['version']}  schema {h.info['feature_schema_version']}  sha256 {h.info['hash'][:16]}…"
                                       if h.loaded else "E1 model slot: not installed (optional) — running rules E2–E6")
                                      + (f"\nwarning: {h.warning}" if h.warning else "")}
    if cmd == "privacy":
        return {"ok": True, "output": "\n".join(f"{k:<24} {v}" for k, v in agent.privacy.items())}

    # Shell builtins
    if cmd == "pstree":
        return _cmd_pstree(agent)
    if cmd == "threads":
        return _cmd_threads(agent)
    if cmd == "sleep":
        return _cmd_sleep(args, job=job)
    if cmd == "echo":
        return _cmd_echo(args)
    if cmd == "ls":
        return _cmd_ls()
    if cmd == "cat":
        return _cmd_cat(args, stdin_text=stdin_text)
    if cmd == "grep":
        return _cmd_grep(args, stdin_text=stdin_text)
    if cmd == "head":
        return _cmd_head(args, stdin_text=stdin_text)
    if cmd == "tail":
        return _cmd_tail(args, stdin_text=stdin_text)
    if cmd == "wc":
        return _cmd_wc(args, stdin_text=stdin_text)
    if cmd == "sort":
        return _cmd_sort(args, stdin_text=stdin_text)
    if cmd == "jobs":
        return _cmd_jobs(agent)
    if cmd == "fg":
        return _cmd_fg(agent, args)
    if cmd == "bg":
        return _cmd_bg(agent, args)
    if cmd == "kill":
        return _cmd_kill(agent, args)
    if cmd in ("clear", "exit"):
        return {"ok": True, "output": ""}

    return {"ok": False, "output": f"guardian: command not found: {cmd}  (type 'help'; arbitrary shell execution is disabled)"}


# ---------------------------------------------------------------------------
# Pipeline & Redirection Execution
# ---------------------------------------------------------------------------

def execute_pipeline(agent, line: str, job: Job | None = None, initial_stdin: str = "") -> dict:
    tokens = tokenize_shell(line)
    if not tokens:
        return {"ok": True, "output": ""}

    stages_tokens: list[list[str]] = []
    current_stage: list[str] = []
    for tok in tokens:
        if tok == "|":
            if not current_stage:
                return {"ok": False, "output": "syntax error near unexpected token '|'"}
            stages_tokens.append(current_stage)
            current_stage = []
        else:
            current_stage.append(tok)

    if current_stage:
        stages_tokens.append(current_stage)
    elif tokens and tokens[-1] == "|":
        return {"ok": False, "output": "syntax error near unexpected token '|'"}

    stdin_text = initial_stdin

    for stage in stages_tokens:
        clean_args = []
        redir_in = None
        redir_out = None
        append_out = False
        idx = 0
        while idx < len(stage):
            t = stage[idx]
            if t == "<":
                if idx + 1 >= len(stage):
                    return {"ok": False, "output": "syntax error near unexpected token '<'"}
                redir_in = strip_quotes(stage[idx + 1])
                idx += 2
                continue
            elif t == ">":
                if idx + 1 >= len(stage):
                    return {"ok": False, "output": "syntax error near unexpected token '>'"}
                redir_out = strip_quotes(stage[idx + 1])
                append_out = False
                idx += 2
                continue
            elif t == ">>":
                if idx + 1 >= len(stage):
                    return {"ok": False, "output": "syntax error near unexpected token '>>'"}
                redir_out = strip_quotes(stage[idx + 1])
                append_out = True
                idx += 2
                continue
            else:
                clean_args.append(strip_quotes(t))
                idx += 1

        if redir_in:
            try:
                in_path = _safe_shell_path(redir_in)
                if not in_path.is_file():
                    return {"ok": False, "output": f"guardian: {redir_in}: No such file or directory"}
                stdin_text = in_path.read_text(encoding="utf-8", errors="replace")
            except ValueError as e:
                return {"ok": False, "output": str(e)}

        if not clean_args:
            if redir_out:
                try:
                    out_path = _safe_shell_path(redir_out)
                    mode = "a" if append_out else "w"
                    with open(out_path, mode, encoding="utf-8") as f:
                        f.write(stdin_text)
                    stdin_text = ""
                except ValueError as e:
                    return {"ok": False, "output": str(e)}
            continue

        res = execute_single_command(agent, clean_args[0], clean_args[1:], stdin_text=stdin_text, job=job)
        if not res["ok"]:
            return res

        output = res.get("output", "")

        if redir_out:
            try:
                out_path = _safe_shell_path(redir_out)
                mode = "a" if append_out else "w"
                with open(out_path, mode, encoding="utf-8") as f:
                    f.write(output + ("\n" if output and not output.endswith("\n") else ""))
                stdin_text = ""
            except ValueError as e:
                return {"ok": False, "output": str(e)}
        else:
            stdin_text = output

    return {"ok": True, "output": stdin_text}


def run(agent, line: str) -> dict:
    clean = line.strip()
    if not clean:
        return {"ok": True, "output": ""}
    try:
        tokens = tokenize_shell(clean)
    except Exception as e:
        return {"ok": False, "output": f"parse error: {e}"}
    if not tokens:
        return {"ok": True, "output": ""}

    if tokens[-1] == "&":
        mgr = get_job_manager(agent)
        cmd_tokens = tokens[:-1]
        if not cmd_tokens:
            return {"ok": False, "output": "syntax error: empty command before '&'"}
        clean_line = clean[:clean.rfind("&")].strip()
        job = mgr.start_job(agent, clean_line)
        return {"ok": True, "output": f"[{job.id}] started"}

    return execute_pipeline(agent, clean)
