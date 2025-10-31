-- ========================================================
-- IDS (Intrusion Detection System) Database Schema
-- SQLite Database Structure for Login Security Monitoring
-- ========================================================

-- ========================================================
-- TABLE 1: LOGIN_EVENTS
-- Description: Stores all login attempts (successful and failed)
-- Purpose: Track all user login activities for audit trail
-- ========================================================
CREATE TABLE IF NOT EXISTS login_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    status TEXT NOT NULL,
    location TEXT
);

CREATE INDEX IF NOT EXISTS idx_login_username ON login_events(username);
CREATE INDEX IF NOT EXISTS idx_login_ip ON login_events(ip_address);
CREATE INDEX IF NOT EXISTS idx_login_timestamp ON login_events(timestamp);


-- ========================================================
-- TABLE 2: ALERTS
-- Description: Stores all security alerts triggered by IDS
-- Purpose: Track suspicious login activities and anomalies
-- ========================================================
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT NOT NULL,
    username TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    severity TEXT NOT NULL,
    resolved INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_alert_username ON alerts(username);
CREATE INDEX IF NOT EXISTS idx_alert_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alert_resolved ON alerts(resolved);


-- ========================================================
-- TABLE 3: FORENSIC_LOGS
-- Description: Complete audit trail of all system actions
-- Purpose: Maintain forensic records for compliance and investigation
-- ========================================================
CREATE TABLE IF NOT EXISTS forensic_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    user TEXT NOT NULL,
    ip_address TEXT,
    action TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    details TEXT
);

CREATE INDEX IF NOT EXISTS idx_forensic_user ON forensic_logs(user);
CREATE INDEX IF NOT EXISTS idx_forensic_timestamp ON forensic_logs(timestamp);


-- ========================================================
-- TABLE 4: BLOCKED_IPS_LOG
-- Description: Tracks all IP addresses that have been blocked
-- Purpose: Maintain record of blacklisted IPs for security
-- ========================================================
CREATE TABLE IF NOT EXISTS blocked_ips_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    reason TEXT NOT NULL,
    blocked_at TEXT NOT NULL,
    blocked_by TEXT DEFAULT 'SYSTEM',
    is_active INTEGER DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_blocked_ip ON blocked_ips_log(ip_address);
CREATE INDEX IF NOT EXISTS idx_blocked_status ON blocked_ips_log(is_active);


-- ========================================================
-- TABLE 5: LOCKED_ACCOUNTS_LOG
-- Description: Tracks all user accounts that have been locked
-- Purpose: Maintain record of account lockouts for security
-- ========================================================
CREATE TABLE IF NOT EXISTS locked_accounts_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    reason TEXT NOT NULL,
    locked_at TEXT NOT NULL,
    locked_by TEXT DEFAULT 'SYSTEM',
    unlock_time TEXT,
    is_active INTEGER DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_locked_user ON locked_accounts_log(username);
CREATE INDEX IF NOT EXISTS idx_locked_status ON locked_accounts_log(is_active);


-- ========================================================
-- TABLE 6: CONFIG
-- Description: Stores IDS system configuration parameters
-- Purpose: Store configurable thresholds and settings
-- ========================================================
CREATE TABLE IF NOT EXISTS config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    value TEXT NOT NULL,
    updated_at TEXT
);


-- ========================================================
-- TABLE 7: DETECTION_RULES
-- Description: Stores detection rules for anomaly detection
-- Purpose: Define and manage IDS detection rules
-- ========================================================
CREATE TABLE IF NOT EXISTS detection_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name TEXT NOT NULL,
    rule_condition TEXT NOT NULL,
    severity TEXT NOT NULL,
    action TEXT NOT NULL,
    created_at TEXT,
    is_active INTEGER DEFAULT 1
);


-- ========================================================
-- SAMPLE DATA & INITIALIZATION
-- ========================================================

-- Insert default configuration values if not exists
INSERT OR IGNORE INTO config (key, value, updated_at) VALUES 
('max_failed_attempts', '3', datetime('now')),
('failed_attempts_window', '120', datetime('now')),
('lockout_duration', '900', datetime('now')),
('cooldown_period', '600', datetime('now'));


-- Insert default detection rules if not exists
INSERT OR IGNORE INTO detection_rules (rule_name, rule_condition, severity, action, created_at, is_active) VALUES 
('Multiple Failed Attempts', 'IF user fails to log in 3+ times within 2 minutes THEN trigger lockout', 'high', 'lock', datetime('now'), 1),
('Blacklisted IP Detection', 'IF login attempt from blacklisted IP THEN block attempt', 'critical', 'block', datetime('now'), 1),
('Simultaneous Locations', 'IF same account logs in from different locations within 60s THEN flag suspicious', 'medium', 'flag', datetime('now'), 1);


-- ========================================================
-- TABLE 8: USERS
-- Description: Stores user credentials with hashed passwords
-- Purpose: Maintain user accounts with secure password storage
-- ========================================================
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    created_at TEXT NOT NULL,
    is_active INTEGER DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);