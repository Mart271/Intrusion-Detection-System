from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta
import sqlite3
import json
import csv
from io import StringIO
from collections import defaultdict
import secrets
import string
import random

app = Flask(__name__)
CORS(app)

DB_PATH = 'ids_system.db'

# ==================== CONFIGURATION ====================
IDS_CONFIG = {
    'detection_window': 120,  # Time window for pattern detection (seconds)
    'rapid_failure_threshold': 3,  # Failed attempts for rapid attack detection
    'sustained_failure_threshold': 10,  # Failed attempts for sustained attack
    'distributed_attack_threshold': 5,  # Number of IPs targeting same user
    'credential_stuffing_threshold': 10,  # Different usernames from same IP
    'impossible_travel_time': 300,  # 5 minutes for location change detection
    'detection_rules': [
        'rapid_failed_attempts',
        'sustained_attack_pattern',
        'distributed_attack',
        'credential_stuffing',
        'impossible_travel'
    ]
}

# In-memory storage (for detection patterns only)
LOGIN_HISTORY = defaultdict(list)
IP_HISTORY = defaultdict(list)
USER_SESSIONS = {}
DETECTION_LOG = []

# Test users database (in production, use proper user management)
USERS_DB = {
    'testuser': {'password': 'correct_password', 'email': 'testuser@example.com', 'role': 'user'},
    'admin_user': {'password': 'admin_password', 'email': 'admin@example.com', 'role': 'admin'},
    'analyst_user': {'password': 'analyst_password', 'email': 'analyst@example.com', 'role': 'security_analyst'}
}

# ==================== DATABASE ====================

def init_db():
    """Initialize database with IDS schema"""
    conn = sqlite3.connect(DB_PATH)
    try:
        with open('ids_database_schema.sql', 'r') as f:
            sql_script = f.read()
        conn.executescript(sql_script)
        
        # Add detection_patterns table for IDS
        conn.execute('''CREATE TABLE IF NOT EXISTS detection_patterns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            pattern_type TEXT NOT NULL,
            username TEXT,
            ip_address TEXT,
            timestamp TEXT NOT NULL,
            severity TEXT NOT NULL,
            details TEXT,
            analyst_review TEXT DEFAULT 'pending',
            analyst_notes TEXT,
            reviewed_at TEXT,
            reviewed_by TEXT
        )''')
        
        conn.commit()
        print("✓ IDS Database initialized successfully")
    except Exception as e:
        print(f"ERROR initializing database: {e}")
        conn.close()
        exit(1)
    finally:
        conn.close()

# ==================== UTILITY FUNCTIONS ====================

def generate_session_token():
    return secrets.token_urlsafe(32)

def get_ip_location(ip):
    """Simulate geolocation lookup"""
    return f"Location_{hash(ip) % 10}"

def send_email(to_email, subject, body):
    """Simulated email sending"""
    print(f"\n📧 EMAIL NOTIFICATION")
    print(f"   To: {to_email}")
    print(f"   Subject: {subject}")
    print(f"   Body: {body[:100]}...")
    return True

def log_event(username, ip, status, location):
    """Log all login events for analysis"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    timestamp = datetime.now().isoformat()
    c.execute('''INSERT INTO login_events 
                 (username, ip_address, timestamp, status, location)
                 VALUES (?, ?, ?, ?, ?)''',
              (username, ip, timestamp, status, location))
    
    # Store in memory for real-time pattern detection
    LOGIN_HISTORY[username].append({
        'ip': ip,
        'timestamp': timestamp,
        'status': status,
        'location': location
    })
    IP_HISTORY[ip].append({
        'username': username,
        'timestamp': timestamp,
        'status': status
    })
    
    conn.commit()
    conn.close()

def create_alert(alert_type, username, ip, severity="medium"):
    """Create alert for security analysts"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    timestamp = datetime.now().isoformat()
    c.execute('''INSERT INTO alerts 
                 (alert_type, username, ip_address, timestamp, severity, resolved)
                 VALUES (?, ?, ?, ?, ?, 0)''',
              (alert_type, username, ip, timestamp, severity))
    conn.commit()
    conn.close()
    
    print(f"🚨 ALERT: {alert_type} - User: {username}, IP: {ip}, Severity: {severity}")

def log_forensic_action(event_type, user, ip, action, details=""):
    """Log all forensic actions for audit trail"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    timestamp = datetime.now().isoformat()
    c.execute('''INSERT INTO forensic_logs 
                 (event_type, user, ip_address, action, timestamp, details)
                 VALUES (?, ?, ?, ?, ?, ?)''',
              (event_type, user, ip, action, timestamp, details))
    conn.commit()
    conn.close()

def log_detection(pattern_type, username, ip, severity, details):
    """Log detected pattern for analyst review"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    timestamp = datetime.now().isoformat()
    c.execute('''INSERT INTO detection_patterns 
                 (pattern_type, username, ip_address, timestamp, severity, details, analyst_review)
                 VALUES (?, ?, ?, ?, ?, ?, 'pending')''',
              (pattern_type, username, ip, timestamp, severity, details))
    detection_id = c.lastrowid
    conn.commit()
    conn.close()
    
    DETECTION_LOG.append({
        'id': detection_id,
        'pattern_type': pattern_type,
        'username': username,
        'ip': ip,
        'timestamp': timestamp,
        'severity': severity,
        'details': details
    })
    
    print(f"🔍 DETECTION: {pattern_type} - {details}")
    return detection_id

# ==================== IDS DETECTION PATTERNS ====================

def detect_rapid_failed_attempts(username):
    """
    Pattern: Rapid Failed Attempts
    Detects: Multiple failed logins in short time (brute force)
    Action: Alert only, no blocking
    """
    now = datetime.now()
    window = timedelta(seconds=IDS_CONFIG['detection_window'])
    
    recent_failures = [
        event for event in LOGIN_HISTORY[username]
        if event['status'] == 'failed' and 
        (now - datetime.fromisoformat(event['timestamp'])) < window
    ]
    
    if len(recent_failures) >= IDS_CONFIG['rapid_failure_threshold']:
        details = f"User '{username}' had {len(recent_failures)} failed attempts in {IDS_CONFIG['detection_window']}s"
        log_detection('RAPID_FAILED_ATTEMPTS', username, recent_failures[0]['ip'], 'high', details)
        create_alert('BRUTE_FORCE_ATTEMPT', username, recent_failures[0]['ip'], 'high')
        return True, details
    
    return False, ""

def detect_sustained_attack(username):
    """
    Pattern: Sustained Attack
    Detects: Many failures over longer period (persistent attacker)
    Action: Alert only
    """
    now = datetime.now()
    window = timedelta(seconds=IDS_CONFIG['detection_window'] * 5)  # Longer window
    
    failures = [
        event for event in LOGIN_HISTORY[username]
        if event['status'] == 'failed' and
        (now - datetime.fromisoformat(event['timestamp'])) < window
    ]
    
    if len(failures) >= IDS_CONFIG['sustained_failure_threshold']:
        details = f"Sustained attack on '{username}': {len(failures)} failures over {IDS_CONFIG['detection_window'] * 5}s"
        log_detection('SUSTAINED_ATTACK', username, failures[0]['ip'], 'high', details)
        create_alert('SUSTAINED_ATTACK', username, failures[0]['ip'], 'high')
        return True, details
    
    return False, ""

def detect_distributed_attack(username):
    """
    Pattern: Distributed Attack
    Detects: Same user targeted from multiple IPs (coordinated attack)
    Action: Alert only
    """
    now = datetime.now()
    window = timedelta(seconds=IDS_CONFIG['detection_window'])
    
    recent_attempts = [
        event for event in LOGIN_HISTORY[username]
        if (now - datetime.fromisoformat(event['timestamp'])) < window
    ]
    
    unique_ips = set(event['ip'] for event in recent_attempts)
    
    if len(unique_ips) >= IDS_CONFIG['distributed_attack_threshold']:
        details = f"Distributed attack detected: User '{username}' targeted from {len(unique_ips)} different IPs"
        ips_str = ", ".join(list(unique_ips)[:5])
        log_detection('DISTRIBUTED_ATTACK', username, ips_str, 'critical', details)
        create_alert('DISTRIBUTED_ATTACK', username, ips_str, 'critical')
        return True, details
    
    return False, ""

def detect_credential_stuffing(ip):
    """
    Pattern: Credential Stuffing
    Detects: Same IP trying many different usernames (password list attack)
    Action: Alert only
    """
    now = datetime.now()
    window = timedelta(seconds=IDS_CONFIG['detection_window'])
    
    recent_attempts = [
        event for event in IP_HISTORY[ip]
        if (now - datetime.fromisoformat(event['timestamp'])) < window
    ]
    
    unique_users = set(event['username'] for event in recent_attempts)
    
    if len(unique_users) >= IDS_CONFIG['credential_stuffing_threshold']:
        details = f"Credential stuffing detected: IP '{ip}' tried {len(unique_users)} different usernames"
        log_detection('CREDENTIAL_STUFFING', "", ip, 'high', details)
        create_alert('CREDENTIAL_STUFFING', f"Multiple ({len(unique_users)})", ip, 'high')
        return True, details
    
    return False, ""

def detect_impossible_travel(username):
    """
    Pattern: Impossible Travel
    Detects: Same user logging in from distant locations in short time
    Action: Alert only
    """
    now = datetime.now()
    window = timedelta(seconds=IDS_CONFIG['impossible_travel_time'])
    
    recent_logins = [
        event for event in LOGIN_HISTORY[username]
        if event['status'] == 'success' and
        (now - datetime.fromisoformat(event['timestamp'])) < window
    ]
    
    unique_locations = set(event['location'] for event in recent_logins)
    
    if len(unique_locations) > 1:
        details = f"Impossible travel detected: User '{username}' logged in from {len(unique_locations)} locations within {IDS_CONFIG['impossible_travel_time']}s"
        log_detection('IMPOSSIBLE_TRAVEL', username, recent_logins[0]['ip'], 'medium', details)
        create_alert('IMPOSSIBLE_TRAVEL', username, recent_logins[0]['ip'], 'medium')
        return True, details
    
    return False, ""

def run_detection_rules(username, ip):
    """
    Run all IDS detection rules
    This is PURE detection - no blocking, just logging and alerting
    """
    detections = []
    
    # Check all patterns
    detected, msg = detect_rapid_failed_attempts(username)
    if detected:
        detections.append(('rapid_failed', msg))
    
    detected, msg = detect_sustained_attack(username)
    if detected:
        detections.append(('sustained_attack', msg))
    
    detected, msg = detect_distributed_attack(username)
    if detected:
        detections.append(('distributed_attack', msg))
    
    detected, msg = detect_credential_stuffing(ip)
    if detected:
        detections.append(('credential_stuffing', msg))
    
    detected, msg = detect_impossible_travel(username)
    if detected:
        detections.append(('impossible_travel', msg))
    
    return detections

# ==================== LOGIN ENDPOINT (IDS MONITORING) ====================

@app.route('/api/login', methods=['POST'])
def login():
    """
    Login endpoint with IDS monitoring
    - Allows all login attempts to proceed
    - Logs everything for forensic analysis
    - Detects suspicious patterns
    - Alerts analysts but DOES NOT BLOCK
    """
    try:
        data = request.json
        username = data.get('username', '').strip()
        password = data.get('password', '')
        ip = request.remote_addr
        location = get_ip_location(ip)
        
        # Validate credentials
        if username in USERS_DB and USERS_DB[username]['password'] == password:
            # ✅ SUCCESSFUL LOGIN
            status = 'success'
            log_event(username, ip, status, location)
            log_forensic_action("LOGIN_SUCCESS", username, ip, "AUTHENTICATED", "Valid credentials")
            
            # Create session
            session_token = generate_session_token()
            USER_SESSIONS[session_token] = {
                'username': username,
                'role': USERS_DB[username]['role'],
                'ip': ip,
                'login_time': datetime.now().isoformat()
            }
            
            # Send notification email
            send_email(USERS_DB[username]['email'], 
                      "Successful Login", 
                      f"New login from IP {ip} at {location}")
            
            print(f"✅ LOGIN SUCCESS: {username} from {ip}")
            
            return jsonify({
                'success': True,
                'message': 'Login successful',
                'session_token': session_token,
                'role': USERS_DB[username]['role']
            })
        
        else:
            # ❌ FAILED LOGIN - Log and detect, but allow retry
            status = 'failed'
            log_event(username, ip, status, location)
            log_forensic_action("LOGIN_FAILED", username, ip, "INVALID_CREDENTIALS", "Wrong password or username")
            
            # Run IDS detection rules
            detections = run_detection_rules(username, ip)
            
            # Log detection results
            if detections:
                detection_summary = "; ".join([d[1] for d in detections])
                print(f"🔍 DETECTIONS FOR {username}: {len(detections)} patterns detected")
                
                # Send alert to analysts
                send_email("security-team@example.com",
                          f"IDS Detection Alert - {username}",
                          f"Suspicious activity detected:\n{detection_summary}")
            
            print(f"❌ LOGIN FAILED: {username} from {ip} - Invalid credentials")
            
            return jsonify({
                'success': False,
                'message': 'Invalid username or password'
            }), 401
    
    except Exception as e:
        log_forensic_action("LOGIN_ERROR", "SYSTEM", request.remote_addr, "ERROR", str(e))
        return jsonify({'success': False, 'message': 'Server error'}), 500

# ==================== ANALYST ENDPOINTS ====================

@app.route('/api/analyst/detections', methods=['GET'])
def get_detections():
    """Get all detected patterns for analyst review"""
    try:
        limit = request.args.get('limit', 50, type=int)
        status = request.args.get('status', 'all')  # pending, reviewed, all
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        if status == 'all':
            c.execute('''SELECT id, pattern_type, username, ip_address, timestamp, 
                        severity, details, analyst_review, analyst_notes
                        FROM detection_patterns 
                        ORDER BY timestamp DESC LIMIT ?''', (limit,))
        else:
            c.execute('''SELECT id, pattern_type, username, ip_address, timestamp, 
                        severity, details, analyst_review, analyst_notes
                        FROM detection_patterns 
                        WHERE analyst_review=?
                        ORDER BY timestamp DESC LIMIT ?''', (status, limit))
        
        detections = c.fetchall()
        conn.close()
        
        return jsonify({
            'detections': [{
                'id': d[0],
                'pattern_type': d[1],
                'username': d[2],
                'ip_address': d[3],
                'timestamp': d[4],
                'severity': d[5],
                'details': d[6],
                'analyst_review': d[7],
                'analyst_notes': d[8]
            } for d in detections],
            'count': len(detections)
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyst/detections/<int:detection_id>/review', methods=['POST'])
def review_detection(detection_id):
    """
    Analyst reviews a detection and provides classification
    - True Positive: Confirm it's an attack
    - False Positive: Mark as benign
    - Needs Investigation: Requires more analysis
    """
    try:
        data = request.json
        classification = data.get('classification')  # true_positive, false_positive, investigate
        notes = data.get('notes', '')
        recommendation = data.get('recommendation', '')  # monitor, notify, block_ip, lock_account, escalate
        analyst_name = data.get('analyst', 'ANALYST')
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        c.execute('''UPDATE detection_patterns 
                    SET analyst_review=?, analyst_notes=?, reviewed_at=?, reviewed_by=?
                    WHERE id=?''',
                  (classification, f"{notes}\nRecommendation: {recommendation}", 
                   datetime.now().isoformat(), analyst_name, detection_id))
        
        conn.commit()
        conn.close()
        
        log_forensic_action("DETECTION_REVIEWED", analyst_name, "SYSTEM", "ANALYST_REVIEW",
                           f"Detection {detection_id} classified as {classification}")
        
        return jsonify({
            'success': True,
            'message': 'Detection reviewed successfully',
            'classification': classification,
            'recommendation': recommendation
        })
    
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/analyst/user/<username>/details', methods=['GET'])
def get_user_forensics(username):
    """Get detailed forensic information about a user"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # Get login history
        c.execute('''SELECT ip_address, timestamp, status, location 
                    FROM login_events WHERE username=? 
                    ORDER BY timestamp DESC LIMIT 50''', (username,))
        login_history = c.fetchall()
        
        # Get related alerts
        c.execute('''SELECT alert_type, ip_address, timestamp, severity 
                    FROM alerts WHERE username=? 
                    ORDER BY timestamp DESC''', (username,))
        alerts = c.fetchall()
        
        # Get detections
        c.execute('''SELECT pattern_type, timestamp, severity, details, analyst_review
                    FROM detection_patterns WHERE username=? 
                    ORDER BY timestamp DESC''', (username,))
        detections = c.fetchall()
        
        conn.close()
        
        return jsonify({
            'username': username,
            'login_history': [{
                'ip': l[0], 'timestamp': l[1], 'status': l[2], 'location': l[3]
            } for l in login_history],
            'alerts': [{
                'type': a[0], 'ip': a[1], 'timestamp': a[2], 'severity': a[3]
            } for a in alerts],
            'detections': [{
                'pattern': d[0], 'timestamp': d[1], 'severity': d[2], 
                'details': d[3], 'review_status': d[4]
            } for d in detections],
            'total_logins': len(login_history),
            'failed_logins': len([l for l in login_history if l[2] == 'failed']),
            'total_alerts': len(alerts),
            'total_detections': len(detections)
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyst/ip/<ip>/details', methods=['GET'])
def get_ip_forensics(ip):
    """Get detailed forensic information about an IP address"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # Get attempts from this IP
        c.execute('''SELECT username, timestamp, status, location 
                    FROM login_events WHERE ip_address=? 
                    ORDER BY timestamp DESC LIMIT 50''', (ip,))
        attempts = c.fetchall()
        
        # Get alerts for this IP
        c.execute('''SELECT alert_type, username, timestamp, severity 
                    FROM alerts WHERE ip_address=? 
                    ORDER BY timestamp DESC''', (ip,))
        alerts = c.fetchall()
        
        conn.close()
        
        unique_users = set(a[0] for a in attempts)
        failed_attempts = len([a for a in attempts if a[2] == 'failed'])
        
        return jsonify({
            'ip_address': ip,
            'attempts': [{
                'username': a[0], 'timestamp': a[1], 'status': a[2], 'location': a[3]
            } for a in attempts],
            'alerts': [{
                'type': a[0], 'username': a[1], 'timestamp': a[2], 'severity': a[3]
            } for a in alerts],
            'total_attempts': len(attempts),
            'failed_attempts': failed_attempts,
            'unique_users_targeted': len(unique_users),
            'is_suspicious': failed_attempts > 10 or len(unique_users) > 5
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== SECURITY OFFICER ENDPOINTS (Manual Actions) ====================

@app.route('/api/admin/block-ip', methods=['POST'])
def admin_block_ip():
    """
    Administrator manually blocks an IP based on analyst recommendation
    This is a MANUAL action, not automatic
    """
    try:
        data = request.json
        ip = data.get('ip')
        reason = data.get('reason', 'Administrator decision')
        admin_name = data.get('admin', 'ADMIN')
        detection_id = data.get('detection_id')  # Link to analyst review
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''INSERT INTO blocked_ips_log 
                    (ip_address, reason, blocked_at, blocked_by)
                    VALUES (?, ?, ?, ?)''',
                  (ip, reason, datetime.now().isoformat(), admin_name))
        conn.commit()
        conn.close()
        
        log_forensic_action("IP_BLOCKED", admin_name, ip, "MANUAL_BLOCK", 
                           f"Reason: {reason}, Detection ID: {detection_id}")
        
        return jsonify({
            'success': True,
            'message': f'IP {ip} blocked successfully',
            'action': 'manual_block',
            'admin': admin_name
        })
    
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/admin/lock-account', methods=['POST'])
def admin_lock_account():
    """
    Administrator manually locks an account based on analyst recommendation
    This is a MANUAL action, not automatic
    """
    try:
        data = request.json
        username = data.get('username')
        reason = data.get('reason', 'Administrator decision')
        admin_name = data.get('admin', 'ADMIN')
        detection_id = data.get('detection_id')
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        unlock_time = (datetime.now() + timedelta(hours=24)).isoformat()
        c.execute('''INSERT INTO locked_accounts_log 
                    (username, reason, locked_at, locked_by, unlock_time)
                    VALUES (?, ?, ?, ?, ?)''',
                  (username, reason, datetime.now().isoformat(), admin_name, unlock_time))
        conn.commit()
        conn.close()
        
        log_forensic_action("ACCOUNT_LOCKED", admin_name, username, "MANUAL_LOCK",
                           f"Reason: {reason}, Detection ID: {detection_id}")
        
        return jsonify({
            'success': True,
            'message': f'Account {username} locked successfully',
            'action': 'manual_lock',
            'admin': admin_name,
            'unlock_time': unlock_time
        })
    
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/admin/unlock-account', methods=['POST'])
def admin_unlock_account():
    """Administrator manually unlocks an account"""
    try:
        data = request.json
        username = data.get('username')
        admin_name = data.get('admin', 'ADMIN')
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''UPDATE locked_accounts_log SET is_active=0 
                    WHERE username=? AND is_active=1''', (username,))
        conn.commit()
        conn.close()
        
        log_forensic_action("ACCOUNT_UNLOCKED", admin_name, username, "MANUAL_UNLOCK", "Administrator decision")
        
        return jsonify({
            'success': True,
            'message': f'Account {username} unlocked successfully'
        })
    
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# ==================== DASHBOARD & REPORTING ====================

@app.route('/api/dashboard/stats', methods=['GET'])
def get_dashboard_stats():
    """Get overall statistics for dashboard"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # Total logins
        c.execute('SELECT COUNT(*) FROM login_events')
        total_logins = c.fetchone()[0]
        
        # Failed attempts
        c.execute("SELECT COUNT(*) FROM login_events WHERE status='failed'")
        failed_attempts = c.fetchone()[0]
        
        # Active alerts
        c.execute('SELECT COUNT(*) FROM alerts WHERE resolved=0')
        active_alerts = c.fetchone()[0]
        
        # Unreviewed detections
        c.execute("SELECT COUNT(*) FROM detection_patterns WHERE analyst_review='pending'")
        unreviewed_detections = c.fetchone()[0]
        
        # Blocked IPs
        c.execute('SELECT COUNT(*) FROM blocked_ips_log WHERE is_active=1')
        blocked_ips = c.fetchone()[0]
        
        # Locked accounts
        c.execute('SELECT COUNT(*) FROM locked_accounts_log WHERE is_active=1')
        locked_accounts = c.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'total_logins': total_logins,
            'failed_attempts': failed_attempts,
            'active_alerts': active_alerts,
            'unreviewed_detections': unreviewed_detections,
            'blocked_ips': blocked_ips,
            'locked_accounts': locked_accounts
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/detections/stats', methods=['GET'])
def get_detection_stats():
    """Get statistics about detected patterns"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        # Detections by pattern type
        c.execute('''SELECT pattern_type, COUNT(*) 
                    FROM detection_patterns 
                    GROUP BY pattern_type''')
        by_pattern = dict(c.fetchall())
        
        # Detections by severity
        c.execute('''SELECT severity, COUNT(*) 
                    FROM detection_patterns 
                    GROUP BY severity''')
        by_severity = dict(c.fetchall())
        
        # Review status breakdown
        c.execute('''SELECT analyst_review, COUNT(*) 
                    FROM detection_patterns 
                    GROUP BY analyst_review''')
        by_review = dict(c.fetchall())
        
        conn.close()
        
        return jsonify({
            'by_pattern': by_pattern,
            'by_severity': by_severity,
            'by_review_status': by_review
        })
    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard/alerts', methods=['GET'])
def get_alerts():
    """Get recent alerts"""
    try:
        limit = request.args.get('limit', 20, type=int)
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''SELECT id, alert_type, username, ip_address, timestamp, severity 
                     FROM alerts WHERE resolved=0 
                     ORDER BY timestamp DESC LIMIT ?''', (limit,))
        alerts = c.fetchall()
        conn.close()
        
        return jsonify({
            'alerts': [{
                'id': a[0], 'alert_type': a[1], 'username': a[2],
                'ip_address': a[3], 'timestamp': a[4], 'severity': a[5]
            } for a in alerts],
            'count': len(alerts)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard/login-history', methods=['GET'])
def get_login_history():
    """Get recent login history"""
    try:
        limit = request.args.get('limit', 50, type=int)
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''SELECT username, ip_address, timestamp, status, location 
                     FROM login_events ORDER BY timestamp DESC LIMIT ?''', (limit,))
        history = c.fetchall()
        conn.close()
        
        return jsonify({
            'history': [{
                'username': h[0], 'ip_address': h[1], 'timestamp': h[2],
                'status': h[3], 'location': h[4]
            } for h in history],
            'count': len(history)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/config', methods=['GET'])
def get_config():
    """Get IDS configuration"""
    return jsonify(IDS_CONFIG)

@app.route('/api/config', methods=['POST'])
def update_config():
    """Update IDS configuration (admin only)"""
    try:
        data = request.json
        for key in data:
            if key in IDS_CONFIG:
                IDS_CONFIG[key] = data[key]
        
        log_forensic_action("CONFIG_UPDATED", "ADMIN", "SYSTEM", "CONFIG_CHANGE", json.dumps(data))
        return jsonify({'success': True, 'config': IDS_CONFIG})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/export/forensic-logs', methods=['GET'])
def export_forensic_logs():
    """Export forensic logs to CSV"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT * FROM forensic_logs ORDER BY timestamp DESC')
        logs = c.fetchall()
        conn.close()
        
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['ID', 'Event Type', 'User', 'IP', 'Action', 'Timestamp', 'Details'])
        writer.writerows(logs)
        
        return output.getvalue(), 200, {
            'Content-Disposition': 'attachment; filename=forensic_logs.csv',
            'Content-Type': 'text/csv'
        }
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/detections', methods=['GET'])
def export_detections():
    """Export all detections to CSV"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT * FROM detection_patterns ORDER BY timestamp DESC')
        detections = c.fetchall()
        conn.close()
        
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['ID', 'Pattern', 'Username', 'IP', 'Timestamp', 'Severity', 
                        'Details', 'Review Status', 'Notes', 'Reviewed At', 'Reviewed By'])
        writer.writerows(detections)
        
        return output.getvalue(), 200, {
            'Content-Disposition': 'attachment; filename=detections.csv',
            'Content-Type': 'text/csv'
        }
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/audit-log', methods=['GET'])
def get_audit_log():
    """Get complete audit trail"""
    try:
        limit = request.args.get('limit', 100, type=int)
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''SELECT event_type, user, ip_address, action, timestamp, details 
                    FROM forensic_logs 
                    ORDER BY timestamp DESC LIMIT ?''', (limit,))
        logs = c.fetchall()
        conn.close()
        
        return jsonify({
            'audit_log': [{
                'event_type': l[0],
                'user': l[1],
                'ip': l[2],
                'action': l[3],
                'timestamp': l[4],
                'details': l[5]
            } for l in logs],
            'count': len(logs)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health():
    """Health check"""
    return jsonify({
        'status': 'OK',
        'mode': 'IDS (Detection Only)',
        'timestamp': datetime.now().isoformat(),
        'active_sessions': len(USER_SESSIONS),
        'detection_rules_active': len(IDS_CONFIG['detection_rules'])
    })

# ==================== MAIN ====================

if __name__ == '__main__':
    init_db()
    
    print("\n" + "="*80)
    print("🔍 IDS (INTRUSION DETECTION SYSTEM) - PURE DETECTION MODE")
    print("="*80)
    print("\n📋 SYSTEM MODE: Detection & Alerting Only")
    print("   ✓ All login attempts are allowed to proceed")
    print("   ✓ Suspicious patterns are detected and logged")
    print("   ✓ Analysts review detections and recommend actions")
    print("   ✓ Officers implement actions manually based on recommendations")
    print("\n🔍 ACTIVE DETECTION PATTERNS:")
    for rule in IDS_CONFIG['detection_rules']:
        print(f"   • {rule}")
    print("\n🚀 Running on http://localhost:5000")
    print("="*80 + "\n")
    
    app.run(debug=False, port=5000, use_reloader=False)