-- StorageForge schema v44 · sqlite: the notification center (notifications.py). An alert gets its level and host, who is on it, and a snooze;
-- mutes are rules by host and kind; events are the history, which the alerts table loses when an alert opens again.
ALTER TABLE alerts ADD COLUMN level TEXT NOT NULL DEFAULT 'warn';
ALTER TABLE alerts ADD COLUMN host TEXT;
ALTER TABLE alerts ADD COLUMN acked_by TEXT;
ALTER TABLE alerts ADD COLUMN acked_at INTEGER;
ALTER TABLE alerts ADD COLUMN ack_note TEXT;
ALTER TABLE alerts ADD COLUMN snoozed_until INTEGER;
ALTER TABLE alerts ADD COLUMN snoozed_by TEXT;

-- host and kind are shell patterns ('*' for any). A mute never covers a critical notification, drift or a security finding: notifications.py decides.
CREATE TABLE notification_mutes (
    mute_id    INTEGER PRIMARY KEY,
    host       TEXT    NOT NULL DEFAULT '*',
    kind       TEXT    NOT NULL DEFAULT '*',
    note       TEXT    NOT NULL DEFAULT '',
    until_at   INTEGER,
    created_by TEXT    NOT NULL,
    created_at INTEGER NOT NULL
);

-- event: opened, escalated, resolved, acknowledged, unacknowledged, snoozed, unsnoozed. actor is NULL for what the evaluation did.
CREATE TABLE notification_events (
    event_id  INTEGER PRIMARY KEY,
    alert_key TEXT    NOT NULL,
    kind      TEXT    NOT NULL,
    host      TEXT,
    level     TEXT    NOT NULL,
    title     TEXT    NOT NULL,
    event     TEXT    NOT NULL,
    actor     TEXT,
    note      TEXT    NOT NULL DEFAULT '',
    at        INTEGER NOT NULL
);
CREATE INDEX notification_events_at ON notification_events (at);
CREATE INDEX notification_events_key ON notification_events (alert_key, at);

INSERT INTO schema_version (version, name, applied_at)
VALUES (44, 'notifications', CAST(strftime('%s', 'now') AS INTEGER));
