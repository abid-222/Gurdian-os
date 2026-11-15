-- Investigation notes (proposal section 5: Security History = acknowledged alerts, investigation notes and export)
CREATE TABLE IF NOT EXISTS incident_notes(
  note_id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL, ts REAL, author TEXT, body TEXT);
CREATE INDEX IF NOT EXISTS ix_notes_inc ON incident_notes(incident_id, ts);
