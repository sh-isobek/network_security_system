-- Web activity events.
-- Run through the project's normal DB migration mechanism.
CREATE TABLE IF NOT EXISTS web_activity (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMPTZ NOT NULL,
    device_id VARCHAR(255),
    hostname VARCHAR(255),
    ip INET NOT NULL,
    username VARCHAR(255),
    domain VARCHAR(512),
    site VARCHAR(512) NOT NULL,
    url TEXT,
    category VARCHAR(128),
    source VARCHAR(128),
    action VARCHAR(32) DEFAULT 'unknown',
    bytes_in BIGINT DEFAULT 0,
    bytes_out BIGINT DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_web_activity_timestamp ON web_activity(timestamp);
CREATE INDEX IF NOT EXISTS idx_web_activity_ip ON web_activity(ip);
CREATE INDEX IF NOT EXISTS idx_web_activity_site ON web_activity(site);
CREATE INDEX IF NOT EXISTS idx_web_activity_device ON web_activity(device_id);
CREATE INDEX IF NOT EXISTS idx_web_activity_hostname ON web_activity(hostname);
