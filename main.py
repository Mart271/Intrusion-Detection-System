from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime, timedelta
import sqlite3
import json
import csv
from io import StringIO
from collections import defaultdict
import os
import threading
import time
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
CORS(app)

DB_PATH = 'ids_system.db'

# ==================== GLOBAL CONFIGURATION ====================
IDS_CONFIG = {
    'max_failed_attempts': 3,
    'failed_attempts_window': 120,  # seconds
    'lockout_duration': 900,  # 15 minutes
    'cooldown_period': 600,  # 10 minutes
    'detection_rules': [
        'multiple_failed_attempts',
        'blacklisted_ip',
        'simultaneous_locations'
    ]
}

# In-memory storage
BLOCKED_IPS = set()
LOCKED_USERS = {}
LOGIN_HISTORY = defaultdict(list)
CUSTOM_RULES = []

# ==================== DATABASE INITIALIZATION ====================

def init_db():
    """Initialize SQLite database from SQL schema file"""
    conn = sqlite3.connect(DB_PATH)
    
    try:
        # Read SQL schema file
        with open('ids_database_schema.sql', 'r') as f:
            sql_script = f.read()
        
        # Execute the SQL script
        conn.executescript(sql_script)
        conn.commit()
        
        print("✓ Database initialized from ids_database_schema.sql successfully")
        
    except FileNotFoundError:
        print("ERROR: ids_database_schema.sql file not found!")
        print("Make sure the file exists in the same folder as main.py")
        conn.close()
        exit(1)
        
    except Exception as e:
        print(f"ERROR initializing database: {e}")
        conn.rollback()
        conn.close()
        exit(1)
    
    finally:
        conn.close()

# ==================== UTILITY FUNCTIONS ====================

def get_ip_location(ip):
    """Simulate IP geolocation lookup"""
    return f"Location_{hash(ip) % 10}"

def validate_ip(ip):
    """Validate IP address format"""
    parts = ip.split('.')
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except:
        return False

def log_event(username, ip, status, location):
    """Log login event to database"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    timestamp = datetime.now().isoformat()
    c.execute('''INSERT INTO login_events 
                 (username, ip_address, timestamp, status, location)
                 VALUES (?, ?, ?, ?, ?)''',
              (username, ip, timestamp, status, location))
    
    LOGIN_HISTORY[username].append({
        'ip': ip,
        'timestamp': timestamp,
        'status': status,
        'location': location
    })
    
    conn.commit()
    conn.close()

def create_alert(alert_type, username, ip, severity="medium"):
    """Create a security alert"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    timestamp = datetime.now().isoformat()
    c.execute('''INSERT INTO alerts 
                 (alert_type, username, ip_address, timestamp, severity, resolved)
                 VALUES (?, ?, ?, ?, ?, 0)''',
              (alert_type, username, ip, timestamp, severity))
    
    conn.commit()
    conn.close()

def log_forensic_action(event_type, user, ip, action, details=""):
    """Log forensic action for audit trail"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    timestamp = datetime.now().isoformat()
    c.execute('''INSERT INTO forensic_logs 
                 (event_type, user, ip_address, action, timestamp, details)
                 VALUES (?, ?, ?, ?, ?, ?)''',
              (event_type, user, ip, action, timestamp, details))
    
    conn.commit()
    conn.close()

# ==================== DETECTION RULES ====================

def check_multiple_failed_attempts(username, ip):
    """Rule 1: Detect multiple failed login attempts within time window"""
    now = datetime.now()
    recent_fails = [
        e for e in LOGIN_HISTORY[username]
        if e['status'] == 'failed' and 
        (now - datetime.fromisoformat(e['timestamp'])).total_seconds() < IDS_CONFIG['failed_attempts_window']
    ]
    
    if len(recent_fails) >= IDS_CONFIG['max_failed_attempts']:
        return True, f"Failed attempts: {len(recent_fails)}/{IDS_CONFIG['max_failed_attempts']}"
    return False, ""

def check_blacklisted_ip(ip):
    """Rule 2: Check if IP is blacklisted"""
    return ip in BLOCKED_IPS, "IP is blacklisted"

def check_simultaneous_locations(username):
    """Rule 3: Detect simultaneous logins from different locations"""
    recent_logins = [
        e for e in LOGIN_HISTORY[username]
        if e['status'] == 'success' and
        (datetime.now() - datetime.fromisoformat(e['timestamp'])).total_seconds() < 60
    ]
    
    if len(set(l['location'] for l in recent_logins)) > 1:
        return True, f"Simultaneous logins from {len(set(l['location'] for l in recent_logins))} locations"
    return False, ""

def process_login(username, ip, password_correct):
    """Main IDS login processing logic - CORE FUNCTION"""
    
    # Validate inputs
    if not username or not ip:
        return False, "Invalid username or IP"
    
    location = get_ip_location(ip)
    timestamp = datetime.now()
    
    # Check 1: Is user already locked?
    if username in LOCKED_USERS:
        if datetime.now() < LOCKED_USERS[username]['until']:
            log_forensic_action("LOGIN_ATTEMPT", username, ip, "REJECTED_LOCKED", "User account is locked")
            return False, "Account temporarily locked due to suspicious activity"
        else:
            del LOCKED_USERS[username]
            log_forensic_action("ACCOUNT_UNLOCKED_AUTO", username, ip, "AUTO_UNLOCK", "Lockout period expired")
    
    # Check 2: Is IP blocked?
    if ip in BLOCKED_IPS:
        log_forensic_action("LOGIN_ATTEMPT", username, ip, "REJECTED_BLOCKED_IP", "IP is blacklisted")
        return False, "IP address is blocked"
    
    # Log the login attempt
    status = "success" if password_correct else "failed"
    log_event(username, ip, status, location)
    
    # Process failed login
    if not password_correct:
        # Rule 1: Check for multiple failed attempts
        suspicious, reason = check_multiple_failed_attempts(username, ip)
        if suspicious:
            create_alert("MULTIPLE_FAILED_ATTEMPTS", username, ip, "high")
            log_forensic_action("LOGIN_ATTEMPT", username, ip, "TRIGGER_LOCKOUT", reason)
            LOCKED_USERS[username] = {
                'until': datetime.now() + timedelta(seconds=IDS_CONFIG['lockout_duration']),
                'reason': 'Multiple failed attempts',
                'ip': ip
            }
            return False, "Too many failed attempts. Account locked for 15 minutes."
        
        log_forensic_action("LOGIN_ATTEMPT", username, ip, "FAILED_ATTEMPT", "Invalid credentials")
        return False, "Invalid credentials"
    
    # Process successful login
    # Rule 2: Check if IP is blacklisted
    suspicious, reason = check_blacklisted_ip(ip)
    if suspicious:
        create_alert("BLACKLISTED_IP", username, ip, "critical")
        log_forensic_action("LOGIN_ATTEMPT", username, ip, "BLOCKED_IP", reason)
        return False, reason
    
    # Rule 3: Check for simultaneous locations
    suspicious, reason = check_simultaneous_locations(username)
    if suspicious:
        create_alert("SUSPICIOUS_LOCATION", username, ip, "medium")
        log_forensic_action("LOGIN_ATTEMPT", username, ip, "FLAG_SUSPICIOUS", reason)
        # Still allow login but flag as suspicious
    
    log_forensic_action("LOGIN_SUCCESS", username, ip, "ALLOWED", "Login successful")
    return True, "Login successful"

# ==================== AUTHENTICATION ENDPOINTS ====================

@app.route('/api/login', methods=['POST'])
def api_login():
    """API endpoint for user login attempts with password hashing"""
    try:
        data = request.json
        username = data.get('username', '').strip()
        ip = request.remote_addr
        password = data.get('password', '')
        
        if not username or not password:
            return jsonify({'success': False, 'message': 'Username and password required'}), 400
        
        # Get stored password hash from database
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        conn.close()
        
        if result:
            stored_hash = result[0]
            password_correct = check_password_hash(stored_hash, password)
        else:
            # Default test user
            if username == 'testuser':
                test_hash = generate_password_hash('correct_password')
                password_correct = check_password_hash(test_hash, password)
            else:
                password_correct = False
        
        # Core IDS processing
        success, message = process_login(username, ip, password_correct)
        
        return jsonify({
            'success': success,
            'message': message,
            'timestamp': datetime.now().isoformat(),
            'username': username
        })
    except Exception as e:
        log_forensic_action("LOGIN_ERROR", "SYSTEM", request.remote_addr, "ERROR", str(e))
        return jsonify({'success': False, 'message': 'System error'}), 500

# ==================== DASHBOARD ENDPOINTS ====================

@app.route('/api/dashboard/stats', methods=['GET'])
def dashboard_stats():
    """Get real-time dashboard statistics"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        
        c.execute('SELECT COUNT(*) FROM login_events')
        total_logins = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM login_events WHERE status='failed'")
        failed_attempts = c.fetchone()[0]
        
        c.execute("SELECT COUNT(*) FROM alerts WHERE resolved=0")
        active_alerts = c.fetchone()[0]
        
        conn.close()
        
        return jsonify({
            'total_logins': total_logins,
            'failed_attempts': failed_attempts,
            'active_alerts': active_alerts,
            'blocked_ips': len(BLOCKED_IPS),
            'locked_users': len(LOCKED_USERS),
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard/alerts', methods=['GET'])
def get_alerts():
    """Get active security alerts"""
    try:
        limit = request.args.get('limit', 20, type=int)
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''SELECT id, alert_type, username, ip_address, timestamp, severity 
                     FROM alerts WHERE resolved=0 
                     ORDER BY timestamp DESC LIMIT ?''', (limit,))
        alerts = c.fetchall()
        conn.close()
        
        alerts_list = [
            {
                'id': a[0],
                'alert_type': a[1],
                'username': a[2],
                'ip_address': a[3],
                'timestamp': a[4],
                'severity': a[5]
            } for a in alerts
        ]
        
        return jsonify({'alerts': alerts_list, 'count': len(alerts_list)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/dashboard/login-history', methods=['GET'])
def get_login_history():
    """Get login history for all users"""
    try:
        limit = request.args.get('limit', 50, type=int)
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''SELECT username, ip_address, timestamp, status, location 
                     FROM login_events 
                     ORDER BY timestamp DESC LIMIT ?''', (limit,))
        history = c.fetchall()
        conn.close()
        
        history_list = [
            {
                'username': h[0],
                'ip_address': h[1],
                'timestamp': h[2],
                'status': h[3],
                'location': h[4]
            } for h in history
        ]
        
        return jsonify({'history': history_list, 'count': len(history_list)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== ADMIN MANAGEMENT ENDPOINTS ====================

@app.route('/api/admin/block-ip', methods=['POST'])
def block_ip():
    """Block an IP address from login attempts"""
    try:
        data = request.json
        ip = data.get('ip', '').strip()
        
        if not ip:
            return jsonify({'success': False, 'message': 'IP address required'}), 400
        
        if not validate_ip(ip):
            return jsonify({'success': False, 'message': 'Invalid IP address format'}), 400
        
        BLOCKED_IPS.add(ip)
        
        # Log to database
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''INSERT INTO blocked_ips_log (ip_address, reason, blocked_at, blocked_by)
                     VALUES (?, ?, ?, ?)''',
                  (ip, 'Admin blocked', datetime.now().isoformat(), 'ADMIN'))
        conn.commit()
        conn.close()
        
        log_forensic_action("IP_BLOCKED", "ADMIN", ip, "BLOCKLIST_UPDATED", "IP added to blocklist")
        
        return jsonify({'success': True, 'message': f'IP {ip} blocked successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/admin/unblock-ip', methods=['POST'])
def unblock_ip():
    """Unblock an IP address"""
    try:
        data = request.json
        ip = data.get('ip', '').strip()
        
        if not ip:
            return jsonify({'success': False, 'message': 'IP address required'}), 400
        
        if ip in BLOCKED_IPS:
            BLOCKED_IPS.remove(ip)
            log_forensic_action("IP_UNBLOCKED", "ADMIN", ip, "BLOCKLIST_UPDATED", "IP removed from blocklist")
            return jsonify({'success': True, 'message': f'IP {ip} unblocked successfully'})
        else:
            return jsonify({'success': False, 'message': f'IP {ip} is not blocked'}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/admin/lock-account', methods=['POST'])
def lock_account():
    """Manually lock a user account"""
    try:
        data = request.json
        username = data.get('username', '').strip()
        
        if not username:
            return jsonify({'success': False, 'message': 'Username required'}), 400
        
        LOCKED_USERS[username] = {
            'until': datetime.now() + timedelta(seconds=IDS_CONFIG['lockout_duration']),
            'reason': 'Admin locked',
            'locked_at': datetime.now().isoformat()
        }
        
        # Log to database
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        unlock_time = (datetime.now() + timedelta(seconds=IDS_CONFIG['lockout_duration'])).isoformat()
        c.execute('''INSERT INTO locked_accounts_log (username, reason, locked_at, locked_by, unlock_time)
                     VALUES (?, ?, ?, ?, ?)''',
                  (username, 'Admin locked', datetime.now().isoformat(), 'ADMIN', unlock_time))
        conn.commit()
        conn.close()
        
        log_forensic_action("ACCOUNT_LOCKED", username, "ADMIN", "MANUAL_LOCKOUT", "Admin locked account")
        
        return jsonify({'success': True, 'message': f'Account {username} locked successfully'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/admin/unlock-account', methods=['POST'])
def unlock_account():
    """Manually unlock a user account"""
    try:
        data = request.json
        username = data.get('username', '').strip()
        
        if not username:
            return jsonify({'success': False, 'message': 'Username required'}), 400
        
        if username in LOCKED_USERS:
            del LOCKED_USERS[username]
            log_forensic_action("ACCOUNT_UNLOCKED", username, "ADMIN", "MANUAL_UNLOCK", "Admin unlocked account")
            return jsonify({'success': True, 'message': f'Account {username} unlocked successfully'})
        else:
            return jsonify({'success': False, 'message': f'Account {username} is not locked'}), 400
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/admin/resolve-alert', methods=['POST'])
def resolve_alert():
    """Resolve a security alert"""
    try:
        data = request.json
        alert_id = data.get('alert_id')
        
        if not alert_id:
            return jsonify({'success': False, 'message': 'Alert ID required'}), 400
        
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('UPDATE alerts SET resolved=1 WHERE id=?', (alert_id,))
        conn.commit()
        conn.close()
        
        log_forensic_action("ALERT_RESOLVED", "ANALYST", "SYSTEM", "RESOLVED", f"Alert {alert_id} resolved")
        
        return jsonify({'success': True, 'message': 'Alert resolved'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# ==================== CONFIGURATION ENDPOINTS ====================

@app.route('/api/config', methods=['GET'])
def get_config():
    """Get current IDS configuration"""
    try:
        return jsonify(IDS_CONFIG)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/config', methods=['POST'])
def update_config():
    """Update IDS configuration"""
    try:
        data = request.json
        
        if 'max_failed_attempts' in data:
            IDS_CONFIG['max_failed_attempts'] = int(data['max_failed_attempts'])
        if 'failed_attempts_window' in data:
            IDS_CONFIG['failed_attempts_window'] = int(data['failed_attempts_window'])
        if 'lockout_duration' in data:
            IDS_CONFIG['lockout_duration'] = int(data['lockout_duration'])
        if 'cooldown_period' in data:
            IDS_CONFIG['cooldown_period'] = int(data['cooldown_period'])
        
        log_forensic_action("CONFIG_UPDATED", "ADMIN", "SYSTEM", "CONFIG_CHANGE", json.dumps(data))
        
        return jsonify({'success': True, 'config': IDS_CONFIG})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# ==================== EXPORT ENDPOINTS ====================

@app.route('/api/export/forensic-logs', methods=['GET'])
def export_forensic_logs():
    """Export forensic logs as CSV"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT id, event_type, user, ip_address, action, timestamp, details FROM forensic_logs ORDER BY timestamp DESC')
        logs = c.fetchall()
        conn.close()
        
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['ID', 'Event Type', 'User', 'IP Address', 'Action', 'Timestamp', 'Details'])
        writer.writerows(logs)
        
        return output.getvalue(), 200, {
            'Content-Disposition': 'attachment; filename=forensic_logs.csv',
            'Content-Type': 'text/csv'
        }
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/export/alerts', methods=['GET'])
def export_alerts():
    """Export alerts as CSV"""
    try:
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('SELECT id, alert_type, username, ip_address, timestamp, severity, resolved FROM alerts ORDER BY timestamp DESC')
        alerts = c.fetchall()
        conn.close()
        
        output = StringIO()
        writer = csv.writer(output)
        writer.writerow(['ID', 'Alert Type', 'Username', 'IP Address', 'Timestamp', 'Severity', 'Resolved'])
        writer.writerows(alerts)
        
        return output.getvalue(), 200, {
            'Content-Disposition': 'attachment; filename=alerts_report.csv',
            'Content-Type': 'text/csv'
        }
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ==================== HEALTH CHECK ====================

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'OK',
        'timestamp': datetime.now().isoformat(),
        'database': 'Connected',
        'blocked_ips': len(BLOCKED_IPS),
        'locked_users': len(LOCKED_USERS)
    })

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    log_forensic_action("SYSTEM_ERROR", "SYSTEM", "SYSTEM", "ERROR", str(error))
    return jsonify({'error': 'Internal server error'}), 500

# ==================== MAIN ====================

if __name__ == '__main__':
    init_db()
    
    print("\n" + "="*60)
    print("🔒 IDS BACKEND API - PRODUCTION READY")
    print("="*60)
    print("\n📊 Configuration:")
    print(f"   Max Failed Attempts: {IDS_CONFIG['max_failed_attempts']}")
    print(f"   Time Window: {IDS_CONFIG['failed_attempts_window']}s")
    print(f"   Lockout Duration: {IDS_CONFIG['lockout_duration']}s ({IDS_CONFIG['lockout_duration']//60} min)")
    print(f"   Cooldown Period: {IDS_CONFIG['cooldown_period']}s ({IDS_CONFIG['cooldown_period']//60} min)")
    
    print("\n🔐 Available Endpoints:")
    print("   POST   /api/login")
    print("   GET    /api/health")
    print("   GET    /api/dashboard/stats")
    print("   GET    /api/dashboard/alerts")
    print("   GET    /api/dashboard/login-history")
    print("   POST   /api/admin/block-ip")
    print("   POST   /api/admin/unblock-ip")
    print("   POST   /api/admin/lock-account")
    print("   POST   /api/admin/unlock-account")
    print("   POST   /api/admin/resolve-alert")
    print("   GET    /api/config")
    print("   POST   /api/config")
    print("   GET    /api/export/forensic-logs")
    print("   GET    /api/export/alerts")
    
    print("\n🚀 Running on http://localhost:5000")
    print("="*60 + "\n")
    
    app.run(debug=False, port=5000, use_reloader=False)