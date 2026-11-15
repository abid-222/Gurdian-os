CREATE TABLE IF NOT EXISTS hosts(host_id TEXT PRIMARY KEY, os_build TEXT, architecture TEXT, hostname TEXT, first_seen TEXT, capabilities TEXT);
CREATE TABLE IF NOT EXISTS events(
  event_id TEXT PRIMARY KEY, schema_version INTEGER, host_id TEXT, ts REAL, timestamp_utc TEXT,
  source TEXT, event_type TEXT, process_key TEXT, pid INTEGER, parent_pid INTEGER, image_path TEXT, sha256 TEXT,
  attributes TEXT, privacy_flags TEXT, severity TEXT);
CREATE INDEX IF NOT EXISTS ix_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS ix_events_pk ON events(process_key);
CREATE INDEX IF NOT EXISTS ix_events_type ON events(event_type, ts);
CREATE INDEX IF NOT EXISTS ix_events_sha ON events(sha256);
CREATE TABLE IF NOT EXISTS process_snapshots(
  id INTEGER PRIMARY KEY AUTOINCREMENT, host_id TEXT, ts REAL, pid INTEGER, process_key TEXT, name TEXT, image TEXT,
  sha256 TEXT, signer TEXT, cpu REAL, rss INTEGER);
CREATE INDEX IF NOT EXISTS ix_snap_ts ON process_snapshots(ts);
CREATE TABLE IF NOT EXISTS network_flows(
  flow_id TEXT PRIMARY KEY, host_id TEXT, start_ts REAL, end_ts REAL, protocol TEXT, laddr TEXT, lport INTEGER,
  raddr TEXT, rport INTEGER, direction TEXT, status TEXT, process_key TEXT, pid INTEGER);
CREATE INDEX IF NOT EXISTS ix_flow_ts ON network_flows(start_ts);
CREATE TABLE IF NOT EXISTS detections(
  detection_id TEXT PRIMARY KEY, ts REAL, host_id TEXT, evidence_class TEXT, rule_id TEXT, model_version TEXT,
  score REAL, threshold REAL, strength TEXT, process_key TEXT, sha256 TEXT, title TEXT, reason TEXT, evidence_refs TEXT);
CREATE INDEX IF NOT EXISTS ix_det_pk ON detections(process_key, ts);
CREATE TABLE IF NOT EXISTS incidents(
  incident_id TEXT PRIMARY KEY, status TEXT, severity TEXT, risk INTEGER, title TEXT, summary TEXT,
  process_key TEXT, process_name TEXT, pid INTEGER, sha256 TEXT, opened_at REAL, updated_at REAL, closed_at REAL,
  classes TEXT, detection_ids TEXT, caveat TEXT, policy_version TEXT, simulated INTEGER DEFAULT 0, decision TEXT, decision_reason TEXT,
  steps TEXT);
CREATE INDEX IF NOT EXISTS ix_inc_pk ON incidents(process_key);
CREATE TABLE IF NOT EXISTS actions_audit(
  action_id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, actor TEXT, action TEXT, target TEXT, result TEXT, detail TEXT,
  prev_hash TEXT, hash TEXT);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT, updated_at REAL);
CREATE TABLE IF NOT EXISTS model_registry(
  model_id TEXT, version TEXT, hash TEXT, feature_schema_version TEXT, installed_at REAL, status TEXT, path TEXT,
  PRIMARY KEY(model_id, version));
CREATE TABLE IF NOT EXISTS allowlist(kind TEXT, value TEXT, reason TEXT, added_at REAL, PRIMARY KEY(kind, value));
