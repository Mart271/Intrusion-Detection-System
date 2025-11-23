-- ========================================================
-- IDS DATABASE SCHEMA - SYNCHRONIZED WITH main.py v4.0
-- ========================================================
-- This schema is designed to work with the Flask IDS Application
-- Run this script to initialize or reset the database
-- ========================================================

-- Drop existing tables if resetting (comment out for production)
-- DROP TABLE IF EXISTS alert_tags;
-- DROP TABLE IF EXISTS sessions;
-- DROP TABLE IF EXISTS detection_patterns;
-- DROP TABLE IF EXISTS detection_rules;
-- DROP TABLE IF EXISTS locked_accounts_log;
-- DROP TABLE IF EXISTS blocked_ips_log;
-- DROP TABLE IF EXISTS forensic_logs;
-- DROP TABLE IF EXISTS alerts;
-- DROP TABLE IF EXISTS login_events;
-- DROP TABLE IF EXISTS config;
-- DROP TABLE IF EXISTS users;


-- ========================================================
-- TABLE 1: USERS
-- Description: User accounts with bcrypt hashed passwords
-- Used by: UserModel class in main.py
-- ========================================================
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user', 'analyst', 'admin')),
    email TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_login TEXT,
    is_active INTEGER DEFAULT 1,
    failed_attempts INTEGER DEFAULT 0,
    last_failed_attempt TEXT,
    must_change_password INTEGER DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);
CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active);


-- ========================================================
-- TABLE 2: LOGIN_EVENTS
-- Description: All login attempts (successful and failed)
-- Used by: LoginEventModel class in main.py
-- ========================================================
CREATE TABLE IF NOT EXISTS login_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    status TEXT NOT NULL CHECK(status IN ('success', 'failed', 'rate_limited', 'blocked_ip', 'locked_account')),
    location TEXT,
    user_agent TEXT
);

CREATE INDEX IF NOT EXISTS idx_login_username ON login_events(username);
CREATE INDEX IF NOT EXISTS idx_login_ip ON login_events(ip_address);
CREATE INDEX IF NOT EXISTS idx_login_timestamp ON login_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_login_status ON login_events(status);


-- ========================================================
-- TABLE 3: ALERTS
-- Description: Security alerts triggered by IDS
-- Used by: AlertModel class in main.py
-- ========================================================
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_type TEXT NOT NULL,
    username TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    severity TEXT NOT NULL CHECK(severity IN ('low', 'medium', 'high', 'critical')),
    resolved INTEGER DEFAULT 0,
    resolved_at TEXT,
    resolved_by TEXT,
    notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_alert_username ON alerts(username);
CREATE INDEX IF NOT EXISTS idx_alert_timestamp ON alerts(timestamp);
CREATE INDEX IF NOT EXISTS idx_alert_resolved ON alerts(resolved);
CREATE INDEX IF NOT EXISTS idx_alert_severity ON alerts(severity);


-- ========================================================
-- TABLE 4: FORENSIC_LOGS
-- Description: Complete audit trail for compliance
-- Used by: ForensicLogModel class in main.py
-- ========================================================
CREATE TABLE IF NOT EXISTS forensic_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    user TEXT NOT NULL,
    ip_address TEXT,
    action TEXT NOT NULL,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    details TEXT
);

CREATE INDEX IF NOT EXISTS idx_forensic_user ON forensic_logs(user);
CREATE INDEX IF NOT EXISTS idx_forensic_timestamp ON forensic_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_forensic_event_type ON forensic_logs(event_type);


-- ========================================================
-- TABLE 5: BLOCKED_IPS_LOG
-- Description: Blocked IP addresses
-- Used by: BlockedIPModel class in main.py
-- ========================================================
CREATE TABLE IF NOT EXISTS blocked_ips_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    reason TEXT NOT NULL,
    blocked_at TEXT NOT NULL DEFAULT (datetime('now')),
    blocked_by TEXT DEFAULT 'SYSTEM' CHECK(blocked_by IN ('SYSTEM', 'ADMIN', 'AUTO')),
    unblocked_at TEXT,
    unblocked_by TEXT,
    is_active INTEGER DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_blocked_ip ON blocked_ips_log(ip_address);
CREATE INDEX IF NOT EXISTS idx_blocked_status ON blocked_ips_log(is_active);


-- ========================================================
-- TABLE 6: LOCKED_ACCOUNTS_LOG
-- Description: Locked user accounts with auto-unlock time
-- Used by: LockedAccountModel class in main.py
-- ========================================================
CREATE TABLE IF NOT EXISTS locked_accounts_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL,
    reason TEXT NOT NULL,
    locked_at TEXT NOT NULL DEFAULT (datetime('now')),
    locked_by TEXT DEFAULT 'SYSTEM' CHECK(locked_by IN ('SYSTEM', 'ADMIN', 'AUTO')),
    unlock_time TEXT NOT NULL,
    unlocked_at TEXT,
    unlocked_by TEXT,
    is_active INTEGER DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_locked_user ON locked_accounts_log(username);
CREATE INDEX IF NOT EXISTS idx_locked_status ON locked_accounts_log(is_active);


-- ========================================================
-- TABLE 7: DETECTION_PATTERNS
-- Description: Detected attack patterns for analyst review
-- Used by: DetectionPatternModel class in main.py
-- ========================================================
CREATE TABLE IF NOT EXISTS detection_patterns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern_type TEXT NOT NULL,
    username TEXT,
    ip_address TEXT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    severity TEXT NOT NULL CHECK(severity IN ('low', 'medium', 'high', 'critical')),
    details TEXT,
    analyst_review TEXT DEFAULT 'pending' CHECK(analyst_review IN ('pending', 'escalated', 'archived', 'false_positive')),
    analyst_notes TEXT,
    reviewed_at TEXT,
    reviewed_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_detection_timestamp ON detection_patterns(timestamp);
CREATE INDEX IF NOT EXISTS idx_detection_review ON detection_patterns(analyst_review);
CREATE INDEX IF NOT EXISTS idx_detection_severity ON detection_patterns(severity);


-- ========================================================
-- TABLE 8: DETECTION_RULES
-- Description: Configurable IDS detection rules
-- Used by: DetectionRuleModel class in main.py
-- ========================================================
CREATE TABLE IF NOT EXISTS detection_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_name TEXT NOT NULL,
    rule_condition TEXT NOT NULL,
    severity TEXT NOT NULL CHECK(severity IN ('low', 'medium', 'high', 'critical')),
    action TEXT NOT NULL CHECK(action IN ('alert', 'lock', 'block', 'flag')),
    threshold INTEGER DEFAULT 3,
    time_window INTEGER DEFAULT 120,
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT,
    is_active INTEGER DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_rules_active ON detection_rules(is_active);


-- ========================================================
-- TABLE 9: CONFIG
-- Description: IDS configuration parameters
-- Used by: ConfigModel class in main.py
-- IMPORTANT: Keys must match InputValidator._ALLOWED_COUNT_CONDITIONS
-- ========================================================
CREATE TABLE IF NOT EXISTS config (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key TEXT UNIQUE NOT NULL,
    value TEXT NOT NULL,
    description TEXT,
    updated_at TEXT DEFAULT (datetime('now')),
    updated_by TEXT DEFAULT 'SYSTEM'
);

CREATE INDEX IF NOT EXISTS idx_config_key ON config(key);


-- ========================================================
-- TABLE 10: SESSIONS (Optional - for database-backed sessions)
-- Description: Active user sessions
-- Note: main.py uses in-memory SessionManager by default
-- ========================================================
CREATE TABLE IF NOT EXISTS sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL UNIQUE,
    username TEXT NOT NULL,
    role TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_activity TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    is_active INTEGER DEFAULT 1,
    FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username);
CREATE INDEX IF NOT EXISTS idx_sessions_active ON sessions(is_active);


-- ========================================================
-- TABLE 11: ALERT_TAGS (For analyst tagging feature)
-- Description: Tags applied to alerts by analysts
-- Used by: tag_incident endpoint in main.py
-- ========================================================
CREATE TABLE IF NOT EXISTS alert_tags (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL,
    tag TEXT NOT NULL,
    tagged_by TEXT NOT NULL,
    tagged_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (alert_id) REFERENCES alerts(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_alert_tags_alert ON alert_tags(alert_id);
CREATE INDEX IF NOT EXISTS idx_alert_tags_tag ON alert_tags(tag);


-- ========================================================
-- DEFAULT CONFIGURATION VALUES
-- These match DetectionThresholds dataclass in main.py
-- ========================================================
INSERT OR IGNORE INTO config (key, value, description, updated_at) VALUES 
    ('max_failed_attempts', '3', 'Maximum failed login attempts before lockout', datetime('now')),
    ('detection_window', '120', 'Time window in seconds for counting failed attempts', datetime('now')),
    ('lockout_duration', '900', 'Account lockout duration in seconds (15 minutes)', datetime('now')),
    ('distributed_threshold', '5', 'Number of unique IPs to trigger distributed attack alert', datetime('now')),
    ('credential_stuffing_threshold', '10', 'Number of unique usernames from same IP to trigger alert', datetime('now')),
    ('sustained_attack_threshold', '10', 'Failed attempts to trigger sustained attack alert', datetime('now')),
    ('sustained_attack_window', '600', 'Time window for sustained attack detection (10 min)', datetime('now')),
    ('session_timeout', '1800', 'Session timeout in seconds (30 minutes)', datetime('now')),
    ('rate_limit_requests', '10', 'Maximum requests per rate limit window', datetime('now')),
    ('rate_limit_window', '60', 'Rate limit window in seconds', datetime('now')),
    ('rate_limit_block_duration', '60', 'Rate limit block duration in seconds', datetime('now')),
    ('cooldown_period', '600', 'Cooldown period after suspicious activity', datetime('now'));


-- ========================================================
-- DEFAULT DETECTION RULES
-- ========================================================
INSERT OR IGNORE INTO detection_rules (id, rule_name, rule_condition, severity, action, threshold, time_window, created_at, is_active) VALUES 
    (1, 'Brute Force Attack', 'IF user fails 3+ login attempts within 2 minutes THEN lock account', 'high', 'lock', 3, 120, datetime('now'), 1),
    (2, 'Blacklisted IP Detection', 'IF login attempt from blocked IP THEN reject immediately', 'critical', 'block', 1, 0, datetime('now'), 1),
    (3, 'Distributed Attack', 'IF same account targeted from 5+ unique IPs within 5 minutes THEN alert', 'critical', 'alert', 5, 300, datetime('now'), 1),
    (4, 'Credential Stuffing', 'IF single IP attempts 10+ different usernames within 5 minutes THEN block IP', 'critical', 'block', 10, 300, datetime('now'), 1),
    (5, 'Sustained Attack Pattern', 'IF user has 10+ failed attempts within 10 minutes THEN alert admin', 'high', 'alert', 10, 600, datetime('now'), 1),
    (6, 'Rate Limit Exceeded', 'IF IP exceeds 10 requests per minute THEN temporarily block', 'medium', 'block', 10, 60, datetime('now'), 1);


-- ========================================================
-- VIEWS FOR DASHBOARD STATISTICS
-- ========================================================

-- View: Security Summary for Dashboard
CREATE VIEW IF NOT EXISTS v_security_summary AS
SELECT 
    (SELECT COUNT(*) FROM alerts WHERE resolved = 0) as active_alerts,
    (SELECT COUNT(*) FROM alerts WHERE resolved = 0 AND severity = 'critical') as critical_alerts,
    (SELECT COUNT(*) FROM blocked_ips_log WHERE is_active = 1) as blocked_ips,
    (SELECT COUNT(*) FROM locked_accounts_log WHERE is_active = 1) as locked_accounts,
    (SELECT COUNT(*) FROM detection_patterns WHERE analyst_review = 'pending') as pending_review,
    (SELECT COUNT(*) FROM login_events) as total_logins,
    (SELECT COUNT(*) FROM login_events WHERE status = 'failed') as failed_logins;


-- View: Recent Failed Logins (last 24 hours)
CREATE VIEW IF NOT EXISTS v_recent_failed_logins AS
SELECT 
    username,
    ip_address,
    COUNT(*) as attempt_count,
    MAX(timestamp) as last_attempt
FROM login_events
WHERE status = 'failed' 
    AND timestamp > datetime('now', '-24 hours')
GROUP BY username, ip_address
ORDER BY attempt_count DESC;


-- View: Top Attacked Users (last 7 days)
CREATE VIEW IF NOT EXISTS v_top_attacked_users AS
SELECT 
    username,
    COUNT(*) as total_failed,
    COUNT(DISTINCT ip_address) as unique_ips,
    MAX(timestamp) as last_attack
FROM login_events
WHERE status = 'failed' 
    AND timestamp > datetime('now', '-7 days')
GROUP BY username
ORDER BY total_failed DESC
LIMIT 20;


-- View: Alerts by Severity (for reporting)
CREATE VIEW IF NOT EXISTS v_alerts_by_severity AS
SELECT 
    severity,
    COUNT(*) as total_count,
    SUM(CASE WHEN resolved = 0 THEN 1 ELSE 0 END) as unresolved_count,
    MAX(timestamp) as latest_alert
FROM alerts
GROUP BY severity
ORDER BY 
    CASE severity 
        WHEN 'critical' THEN 1 
        WHEN 'high' THEN 2 
        WHEN 'medium' THEN 3 
        WHEN 'low' THEN 4 
    END;


-- View: Login Activity Summary (hourly)
CREATE VIEW IF NOT EXISTS v_login_activity_hourly AS
SELECT 
    strftime('%Y-%m-%d %H:00', timestamp) as hour,
    COUNT(*) as total_attempts,
    SUM(CASE WHEN status = 'success' THEN 1 ELSE 0 END) as successful,
    SUM(CASE WHEN status = 'failed' THEN 1 ELSE 0 END) as failed,
    SUM(CASE WHEN status = 'rate_limited' THEN 1 ELSE 0 END) as rate_limited,
    SUM(CASE WHEN status = 'blocked_ip' THEN 1 ELSE 0 END) as blocked_ip
FROM login_events
WHERE timestamp > datetime('now', '-24 hours')
GROUP BY strftime('%Y-%m-%d %H:00', timestamp)
ORDER BY hour DESC;


-- ========================================================
-- TRIGGERS FOR AUTOMATIC ACTIONS
-- ========================================================

-- Trigger: Update last_login on successful login
CREATE TRIGGER IF NOT EXISTS trg_update_last_login
AFTER INSERT ON login_events
WHEN NEW.status = 'success'
BEGIN
    UPDATE users 
    SET last_login = NEW.timestamp 
    WHERE username = NEW.username;
END;


-- Trigger: Track failed attempts in users table
CREATE TRIGGER IF NOT EXISTS trg_track_failed_attempts
AFTER INSERT ON login_events
WHEN NEW.status = 'failed'
BEGIN
    UPDATE users 
    SET failed_attempts = failed_attempts + 1,
        last_failed_attempt = NEW.timestamp
    WHERE username = NEW.username;
END;


-- Trigger: Reset failed attempts on successful login
CREATE TRIGGER IF NOT EXISTS trg_reset_failed_attempts
AFTER INSERT ON login_events
WHEN NEW.status = 'success'
BEGIN
    UPDATE users 
    SET failed_attempts = 0,
        last_failed_attempt = NULL
    WHERE username = NEW.username;
END;


-- Trigger: Auto-update config timestamp
CREATE TRIGGER IF NOT EXISTS trg_config_updated
AFTER UPDATE ON config
BEGIN
    UPDATE config SET updated_at = datetime('now') WHERE key = NEW.key;
END;


