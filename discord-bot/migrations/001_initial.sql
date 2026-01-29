-- Initial schema for AWD Logger

-- Whitelist table for IP addresses
CREATE TABLE IF NOT EXISTS whitelist (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT UNIQUE NOT NULL,
    description TEXT,
    added_by TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_used_at DATETIME,
    request_count INTEGER DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE
);

-- Request logs for statistics
CREATE TABLE IF NOT EXISTS request_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    channel_name TEXT NOT NULL,
    level TEXT NOT NULL,
    source_ip TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Create indexes for better performance
CREATE INDEX IF NOT EXISTS idx_whitelist_ip ON whitelist(ip_address);
CREATE INDEX IF NOT EXISTS idx_whitelist_active ON whitelist(is_active);
CREATE INDEX IF NOT EXISTS idx_request_logs_channel ON request_logs(channel_name);
CREATE INDEX IF NOT EXISTS idx_request_logs_timestamp ON request_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_request_logs_source_ip ON request_logs(source_ip);
