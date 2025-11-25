from flask import Flask, request, jsonify, g, Response
from flask_cors import CORS
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from functools import wraps
from contextlib import contextmanager
from typing import Optional, Tuple, List, Dict, Any, Union
from enum import Enum
from dataclasses import dataclass, field
import sqlite3
import threading
import logging
import csv
import os
from io import StringIO
from collections import defaultdict
import secrets
import bcrypt
import re
import secrets
import string

# ============================================================================
# CONFIGURATION
# ============================================================================

@dataclass
class Config:
    """Application Configuration"""
    ENV: str = os.environ.get('FLASK_ENV', 'development')
    DEBUG: bool = field(init=False)
    DB_PATH: str = os.environ.get('IDS_DB_PATH', 'ids_system.db')
    HOST: str = os.environ.get('IDS_HOST', '127.0.0.1')  # CHANGED: Default to localhost, not 0.0.0.0
    PORT: int = int(os.environ.get('IDS_PORT', 5000))
    SESSION_TIMEOUT: int = int(os.environ.get('SESSION_TIMEOUT', 30))
    RATE_LIMIT_MAX: int = int(os.environ.get('RATE_LIMIT_MAX', 10))
    RATE_LIMIT_WINDOW: int = int(os.environ.get('RATE_LIMIT_WINDOW', 60))
    RATE_LIMIT_BLOCK: int = int(os.environ.get('RATE_LIMIT_BLOCK', 60))
    # SECURITY FIX: CORS restricted by default - set CORS_ORIGINS env var in production
    CORS_ORIGINS: str = os.environ.get('CORS_ORIGINS', 'http://localhost:5000')
    # Secret key for additional security (sessions, CSRF if implemented)
    SECRET_KEY: str = os.environ.get('IDS_SECRET_KEY', secrets.token_hex(32))
    
    def __post_init__(self):
        self.DEBUG = self.ENV == 'development'

config = Config()

# ============================================================================
# ENUMERATIONS
# ============================================================================

class AlertType(Enum):
    BRUTE_FORCE = "BRUTE_FORCE_ATTACK"
    SUSTAINED_ATTACK = "SUSTAINED_ATTACK_PATTERN"
    DISTRIBUTED = "DISTRIBUTED_ATTACK"
    CREDENTIAL_STUFFING = "CREDENTIAL_STUFFING_ATTACK"
    BLACKLISTED_IP = "BLACKLISTED_IP_ATTEMPT"
    ACCOUNT_LOCKED = "LOCKED_ACCOUNT_ATTEMPT"
    RATE_LIMITED = "RATE_LIMIT_EXCEEDED"

class Severity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

class UserRole(Enum):
    USER = "user"
    ANALYST = "analyst"
    ADMIN = "admin"

class LoginStatus(Enum):
    SUCCESS = "success"
    FAILED = "failed"
    RATE_LIMITED = "rate_limited"
    BLOCKED_IP = "blocked_ip"
    LOCKED_ACCOUNT = "locked_account"

class ReviewStatus(Enum):
    PENDING = "pending"
    ESCALATED = "escalated"
    ARCHIVED = "archived"
    FALSE_POSITIVE = "false_positive"

# ============================================================================
# DETECTION THRESHOLDS
# ============================================================================

@dataclass
class DetectionThresholds:
    max_failed_attempts: int = 3
    detection_window: int = 120
    lockout_duration: int = 900
    distributed_threshold: int = 5
    credential_stuffing_threshold: int = 10
    sustained_attack_threshold: int = 10
    sustained_attack_window: int = 600

# ============================================================================
# INPUT VALIDATOR
# ============================================================================

class InputValidator:
    _IP_PATTERN = re.compile(r'^((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}$')
    _USERNAME_PATTERN = re.compile(r'^[a-zA-Z0-9_]{3,50}$')
    # SECURITY: Whitelist of allowed count conditions to prevent SQL injection
    _ALLOWED_COUNT_CONDITIONS = frozenset([
        "1=1",
        "status='failed'",
        "resolved=0",
        "analyst_review='pending'",
        "is_active=1",
    ])
    
    @classmethod
    def validate_ip(cls, ip: str) -> Tuple[bool, str]:
        if not ip:
            return False, "IP address required"
        if not cls._IP_PATTERN.match(ip):
            return False, "Invalid IP format"
        return True, ""
    
    @classmethod
    def validate_username(cls, username: str) -> Tuple[bool, str]:
        if not username:
            return False, "Username required"
        if len(username) < 3:
            return False, "Username must be at least 3 characters"
        if len(username) > 50:
            return False, "Username too long (max 50)"
        if not cls._USERNAME_PATTERN.match(username):
            return False, "Username must be alphanumeric"
        return True, ""
    
    @classmethod
    def validate_number(cls, val: Any, min_v: int, max_v: int, name: str) -> Tuple[bool, str]:
        try:
            n = int(val)
            if n < min_v or n > max_v:
                return False, f"{name} must be between {min_v} and {max_v}"
            return True, ""
        except (TypeError, ValueError):
            return False, f"{name} must be a number"
    
    @classmethod
    def validate_count_condition(cls, condition: str) -> bool:
        """SECURITY: Validate that count condition is in whitelist"""
        return condition in cls._ALLOWED_COUNT_CONDITIONS
    
    @classmethod
    def sanitize(cls, text: str) -> str:
        if not text:
            return ""
        replacements = {'<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '&': '&amp;'}
        result = str(text)
        for char, repl in replacements.items():
            result = result.replace(char, repl)
        return result

# ============================================================================
# DATABASE MANAGER
# ============================================================================

class DatabaseManager:
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, db_path: str = None):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._db_path = db_path or config.DB_PATH
        return cls._instance
    
    @contextmanager
    def connection(self):
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def query(self, sql: str, params: tuple = ()) -> List[sqlite3.Row]:
        with self.connection() as conn:
            return conn.execute(sql, params).fetchall()
    
    def query_one(self, sql: str, params: tuple = ()) -> Optional[sqlite3.Row]:
        rows = self.query(sql, params)
        return rows[0] if rows else None
    
    def execute(self, sql: str, params: tuple = ()) -> int:
        with self.connection() as conn:
            cursor = conn.execute(sql, params)
            conn.commit()
            return cursor.lastrowid
    
    def execute_script(self, script: str) -> None:
        with self.connection() as conn:
            conn.executescript(script)
            conn.commit()

db = DatabaseManager()

# ============================================================================
# LOGGER
# ============================================================================

class Logger:
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._setup()
        return cls._instance
    
    def _setup(self):
        import sys, io
        if sys.platform == 'win32':
            try:
                sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8', errors='replace')
            except: pass
        
        self._logger = logging.getLogger('IDS')
        self._logger.setLevel(logging.INFO)
        self._logger.handlers.clear()
        
        fmt = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
        
        ch = logging.StreamHandler(sys.stdout)
        ch.setFormatter(fmt)
        
        fh = logging.FileHandler('ids_system.log', encoding='utf-8')
        fh.setFormatter(fmt)
        
        self._logger.addHandler(ch)
        self._logger.addHandler(fh)
    
    def info(self, msg: str): self._logger.info(msg)
    def warning(self, msg: str): self._logger.warning(msg)
    def error(self, msg: str): self._logger.error(msg)
    def debug(self, msg: str): self._logger.debug(msg)

logger = Logger()

# ============================================================================
# BASE MODEL - SECURITY HARDENED
# ============================================================================

class BaseModel(ABC):
    @classmethod
    @abstractmethod
    def table_name(cls) -> str:
        pass
    
    @classmethod
    def find_by_id(cls, id: int) -> Optional[Dict]:
        row = db.query_one(f"SELECT * FROM {cls.table_name()} WHERE id = ?", (id,))
        return dict(row) if row else None
    
    @classmethod
    def find_all(cls, limit: int = 100) -> List[Dict]:
        rows = db.query(f"SELECT * FROM {cls.table_name()} ORDER BY id DESC LIMIT ?", (limit,))
        return [dict(r) for r in rows]
    
    @classmethod
    def count(cls, condition: str = "1=1") -> int:
        """
        SECURITY FIX: Only allow whitelisted conditions to prevent SQL injection.
        For custom conditions, use count_where() with parameterized queries.
        """
        if not InputValidator.validate_count_condition(condition):
            logger.warning(f"Blocked potentially unsafe count condition: {condition}")
            raise ValueError(f"Invalid count condition: {condition}")
        row = db.query_one(f"SELECT COUNT(*) as c FROM {cls.table_name()} WHERE {condition}")
        return row['c'] if row else 0
    
    @classmethod
    def count_where(cls, column: str, value: Any) -> int:
        """SECURITY: Parameterized count query for dynamic conditions"""
        # Whitelist allowed columns
        allowed_columns = {'status', 'resolved', 'analyst_review', 'is_active', 'severity', 'role'}
        if column not in allowed_columns:
            raise ValueError(f"Column '{column}' not allowed in count query")
        row = db.query_one(f"SELECT COUNT(*) as c FROM {cls.table_name()} WHERE {column} = ?", (value,))
        return row['c'] if row else 0
    
    @classmethod
    def delete_by_id(cls, id: int) -> bool:
        db.execute(f"DELETE FROM {cls.table_name()} WHERE id = ?", (id,))
        return True

# ============================================================================
# USER MODEL - WITH PASSWORD CHANGE TRACKING
# ============================================================================

class UserModel(BaseModel):
    @classmethod
    def table_name(cls) -> str:
        return "users"
    
    @classmethod
    def find_by_username(cls, username: str) -> Optional[Dict]:
        row = db.query_one(
            "SELECT id, username, password_hash, role, is_active, must_change_password FROM users WHERE username = ?",
            (username,))
        return dict(row) if row else None
    
    @classmethod
    def create(cls, username: str, password: str, role: str = 'user', must_change_password: bool = False) -> bool:
        try:
            hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
            db.execute('''
                INSERT INTO users (username, password_hash, role, created_at, is_active, must_change_password)
                VALUES (?, ?, ?, ?, 1, ?)
            ''', (username, hashed, role, datetime.now().isoformat(), 1 if must_change_password else 0))
            # SECURITY FIX: Don't log password or username details
            logger.info(f"New user account created with role '{role}'")
            return True
        except Exception as e:
            logger.error(f"Failed to create user: {type(e).__name__}")
            return False
    
    @classmethod
    def update_password(cls, username: str, new_password: str) -> bool:
        """Update user password and clear must_change_password flag"""
        try:
            hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
            db.execute(
                'UPDATE users SET password_hash=?, must_change_password=0 WHERE username=?',
                (hashed, username))
            logger.info(f"Password updated for user")
            return True
        except Exception:
            return False
    
    @classmethod
    def verify_password(cls, password: str, hashed: Union[bytes, str]) -> bool:
        try:
            if isinstance(hashed, str):
                hashed = hashed.encode('utf-8')
            return bcrypt.checkpw(password.encode('utf-8'), hashed)
        except Exception:
            return False
    
    @classmethod
    def authenticate(cls, username: str, password: str) -> Optional[Dict]:
        user = cls.find_by_username(username)
        if not user or not user['is_active']:
            return None
        if not cls.verify_password(password, user['password_hash']):
            return None
        return user

# ============================================================================
# ALERT MODEL
# ============================================================================

class AlertModel(BaseModel):
    @classmethod
    def table_name(cls) -> str:
        return "alerts"
    
    @classmethod
    def create(cls, alert_type: str, username: str, ip: str, severity: str) -> int:
        return db.execute('''
            INSERT INTO alerts (alert_type, username, ip_address, timestamp, severity)
            VALUES (?, ?, ?, ?, ?)
        ''', (alert_type, username, ip, datetime.now().isoformat(), severity))
    
    @classmethod
    def find_unresolved(cls, limit: int = 100) -> List[Dict]:
        rows = db.query('SELECT * FROM alerts WHERE resolved = 0 ORDER BY timestamp DESC LIMIT ?', (limit,))
        return [dict(r) for r in rows]
    
    @classmethod
    def resolve(cls, alert_id: int, resolved_by: str) -> bool:
        db.execute('UPDATE alerts SET resolved=1, resolved_at=?, resolved_by=? WHERE id=?',
                   (datetime.now().isoformat(), resolved_by, alert_id))
        return True

# ============================================================================
# LOG MODELS
# ============================================================================

class LoginEventModel(BaseModel):
    @classmethod
    def table_name(cls) -> str:
        return "login_events"
    
    @classmethod
    def create(cls, username: str, ip: str, status: str, location: str) -> int:
        return db.execute('''
            INSERT INTO login_events (username, ip_address, timestamp, status, location)
            VALUES (?, ?, ?, ?, ?)
        ''', (username, ip, datetime.now().isoformat(), status, location))

class ForensicLogModel(BaseModel):
    @classmethod
    def table_name(cls) -> str:
        return "forensic_logs"
    
    @classmethod
    def create(cls, event_type: str, user: str, ip: str, action: str, details: str = "") -> int:
        return db.execute('''
            INSERT INTO forensic_logs (event_type, user, ip_address, action, timestamp, details)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (event_type, user, ip or 'N/A', action, datetime.now().isoformat(), details))

class BlockedIPModel(BaseModel):
    @classmethod
    def table_name(cls) -> str:
        return "blocked_ips_log"
    
    @classmethod
    def is_blocked(cls, ip: str) -> Optional[Dict]:
        row = db.query_one("SELECT reason FROM blocked_ips_log WHERE ip_address=? AND is_active=1", (ip,))
        return dict(row) if row else None
    
    @classmethod
    def block(cls, ip: str, reason: str, blocked_by: str = "SYSTEM") -> int:
        return db.execute('''
            INSERT INTO blocked_ips_log (ip_address, reason, blocked_at, blocked_by, is_active)
            VALUES (?, ?, ?, ?, 1)
        ''', (ip, reason, datetime.now().isoformat(), blocked_by))
    
    @classmethod
    def unblock(cls, ip: str) -> bool:
        db.execute("UPDATE blocked_ips_log SET is_active=0 WHERE ip_address=? AND is_active=1", (ip,))
        return True

class LockedAccountModel(BaseModel):
    @classmethod
    def table_name(cls) -> str:
        return "locked_accounts_log"
    
    @classmethod
    def is_locked(cls, username: str) -> Optional[Dict]:
        row = db.query_one(
            "SELECT reason, unlock_time FROM locked_accounts_log WHERE username=? AND is_active=1",
            (username,))
        if row:
            # Check if lock has expired
            unlock_time = datetime.fromisoformat(row['unlock_time'])
            if datetime.now() > unlock_time:
                # Auto-unlock expired locks
                db.execute("UPDATE locked_accounts_log SET is_active=0 WHERE username=? AND is_active=1", (username,))
                return None
        return dict(row) if row else None
    
    @classmethod
    def lock(cls, username: str, reason: str, duration: int, locked_by: str = "SYSTEM") -> int:
        unlock_time = (datetime.now() + timedelta(seconds=duration)).isoformat()
        return db.execute('''
            INSERT INTO locked_accounts_log (username, reason, locked_at, locked_by, unlock_time, is_active)
            VALUES (?, ?, ?, ?, ?, 1)
        ''', (username, reason, datetime.now().isoformat(), locked_by, unlock_time))
    
    @classmethod
    def unlock(cls, username: str) -> bool:
        db.execute("UPDATE locked_accounts_log SET is_active=0 WHERE username=? AND is_active=1", (username,))
        return True

class DetectionPatternModel(BaseModel):
    @classmethod
    def table_name(cls) -> str:
        return "detection_patterns"
    
    @classmethod
    def create(cls, pattern_type: str, username: str, ip: str, severity: str, details: str) -> int:
        return db.execute('''
            INSERT INTO detection_patterns (pattern_type, username, ip_address, timestamp, severity, details, analyst_review)
            VALUES (?, ?, ?, ?, ?, ?, 'pending')
        ''', (pattern_type, username, ip, datetime.now().isoformat(), severity, details))
    
    @classmethod
    def update_review(cls, id: int, status: str, analyst: str, notes: str = "") -> bool:
        db.execute('''
            UPDATE detection_patterns SET analyst_review=?, reviewed_by=?, reviewed_at=?, analyst_notes=?
            WHERE id=?
        ''', (status, analyst, datetime.now().isoformat(), notes, id))
        return True

class DetectionRuleModel(BaseModel):
    @classmethod
    def table_name(cls) -> str:
        return "detection_rules"
    
    @classmethod
    def create(cls, name: str, condition: str, severity: str, action: str) -> int:
        return db.execute('''
            INSERT INTO detection_rules (rule_name, rule_condition, severity, action, created_at, is_active)
            VALUES (?, ?, ?, ?, ?, 1)
        ''', (name, condition, severity, action, datetime.now().isoformat()))
    
    @classmethod
    def toggle(cls, rule_id: int, active: bool) -> bool:
        db.execute('UPDATE detection_rules SET is_active=? WHERE id=?', (1 if active else 0, rule_id))
        return True

class ConfigModel(BaseModel):
    @classmethod
    def table_name(cls) -> str:
        return "config"
    
    @classmethod
    def get_all(cls) -> Dict[str, int]:
        rows = db.query('SELECT key, value FROM config')
        return {r['key']: int(r['value']) for r in rows}
    
    @classmethod
    def set(cls, key: str, value: int) -> bool:
        db.execute('INSERT OR REPLACE INTO config (key, value, updated_at) VALUES (?, ?, ?)',
                   (key, str(value), datetime.now().isoformat()))
        return True

# ============================================================================
# SESSION MANAGER
# ============================================================================

class SessionManager:
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, timeout_minutes: int = 30):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._sessions = {}
                    cls._instance._timeout = timedelta(minutes=timeout_minutes)
                    cls._instance._session_lock = threading.RLock()
        return cls._instance
    
    def create(self, username: str, role: str, ip: str) -> str:
        token = secrets.token_urlsafe(32)
        now = datetime.now()
        with self._session_lock:
            self._cleanup()
            self._sessions[token] = {
                'username': username, 'role': role, 'ip': ip,
                'created_at': now, 'last_activity': now
            }
        logger.info(f"Session created for user from {ip}")
        return token
    
    def validate(self, token: str) -> Optional[Dict]:
        if not token:
            return None
        with self._session_lock:
            session = self._sessions.get(token)
            if not session:
                return None
            if datetime.now() - session['last_activity'] > self._timeout:
                del self._sessions[token]
                return None
            session['last_activity'] = datetime.now()
            return session.copy()
    
    def invalidate(self, token: str) -> bool:
        with self._session_lock:
            if token in self._sessions:
                del self._sessions[token]
                return True
            return False
    
    def _cleanup(self):
        now = datetime.now()
        expired = [t for t, s in self._sessions.items() if now - s['last_activity'] > self._timeout]
        for token in expired:
            del self._sessions[token]
    
    @property
    def active_count(self) -> int:
        with self._session_lock:
            self._cleanup()
            return len(self._sessions)

# ============================================================================
# RATE LIMITER
# ============================================================================

class RateLimiter:
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls, max_req: int = 10, window: int = 60, block: int = 60):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._max = max_req
                    cls._instance._window = window
                    cls._instance._block_duration = block
                    cls._instance._attempts = defaultdict(list)
                    cls._instance._blocked = {}
                    cls._instance._rate_lock = threading.RLock()
        return cls._instance
    
    def check(self, ip: str) -> Tuple[bool, int]:
        with self._rate_lock:
            now = datetime.now()
            if ip in self._blocked:
                if now < self._blocked[ip]:
                    return False, int((self._blocked[ip] - now).total_seconds())
                del self._blocked[ip]
            cutoff = now - timedelta(seconds=self._window)
            self._attempts[ip] = [t for t in self._attempts[ip] if t > cutoff]
            if len(self._attempts[ip]) >= self._max:
                self._blocked[ip] = now + timedelta(seconds=self._block_duration)
                logger.warning(f"Rate limit exceeded for IP")
                return False, self._block_duration
            self._attempts[ip].append(now)
            return True, 0
    
    def unblock(self, ip: str) -> bool:
        with self._rate_lock:
            if ip in self._blocked:
                del self._blocked[ip]
                return True
            return False
    
    def get_blocked(self) -> List[Dict]:
        now = datetime.now()
        with self._rate_lock:
            return [{'ip': ip, 'blocked_until': until.isoformat(),
                     'remaining': int((until - now).total_seconds())}
                    for ip, until in self._blocked.items() if until > now]
    
    @property
    def stats(self) -> Dict:
        now = datetime.now()
        with self._rate_lock:
            return {'max_requests': self._max, 'window_seconds': self._window,
                    'block_duration': self._block_duration, 'active_ips': len(self._attempts),
                    'blocked_ips': sum(1 for t in self._blocked.values() if t > now)}

# ============================================================================
# IDS DETECTOR
# ============================================================================

class IDSDetector:
    _instance = None
    _lock = threading.Lock()
    
    def __new__(cls):
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = super().__new__(cls)
                    cls._instance._login_cache = defaultdict(list)
                    cls._instance._ip_cache = defaultdict(list)
                    cls._instance._alert_dedup = {}
                    cls._instance._detector_lock = threading.RLock()
                    cls._instance._thresholds = DetectionThresholds()
                    cls._instance._load_thresholds()
        return cls._instance
    
    def _load_thresholds(self):
        try:
            for key, val in ConfigModel.get_all().items():
                if hasattr(self._thresholds, key):
                    setattr(self._thresholds, key, val)
        except Exception:
            pass
    
    def reload_thresholds(self):
        self._load_thresholds()
        logger.info("IDS thresholds reloaded")
    
    def analyze(self, username: str, ip: str, success: bool) -> List[Dict]:
        now = datetime.now()
        with self._detector_lock:
            self._login_cache[username].append({'ip': ip, 'time': now, 'success': success})
            self._ip_cache[ip].append({'user': username, 'time': now, 'success': success})
            self._cleanup()
        if success:
            return []
        return self._detect_all(username, ip)
    
    def _detect_all(self, username: str, ip: str) -> List[Dict]:
        threats = []
        t = self._thresholds
        
        # BRUTE FORCE - Dynamic severity
        failed_count = sum(1 for a in self._get_user_attempts(username, t.detection_window) if not a['success'])
        if failed_count >= t.max_failed_attempts:
            if self._should_alert(f"brute:{username}"):
                if failed_count >= 10:
                    severity = Severity.CRITICAL
                elif failed_count >= 6:
                    severity = Severity.HIGH
                elif failed_count >= 4:
                    severity = Severity.MEDIUM
                else:
                    severity = Severity.LOW
                threats.append(self._threat(AlertType.BRUTE_FORCE, severity, username, ip,
                    f"{failed_count} failed attempts"))
        
        # DISTRIBUTED - Dynamic severity
        recent = self._get_user_attempts(username, t.detection_window * 2)
        unique_ips = len(set(a['ip'] for a in recent if not a['success']))
        if unique_ips >= t.distributed_threshold:
            if self._should_alert(f"dist:{username}"):
                if unique_ips >= 15:
                    severity = Severity.CRITICAL
                elif unique_ips >= 10:
                    severity = Severity.HIGH
                elif unique_ips >= 7:
                    severity = Severity.MEDIUM
                else:
                    severity = Severity.LOW
                threats.append(self._threat(AlertType.DISTRIBUTED, severity, username, ip,
                    f"Attack from {unique_ips} IPs"))
        
        # CREDENTIAL STUFFING
        if self._check_credential_stuffing(ip, t.credential_stuffing_threshold):
            if self._should_alert(f"stuff:{ip}"):
                threats.append(self._threat(AlertType.CREDENTIAL_STUFFING, Severity.HIGH, username, ip,
                    "Credential stuffing detected"))
        
        # SUSTAINED ATTACK
        if self._check_sustained(username, t.sustained_attack_threshold, t.sustained_attack_window):
            if self._should_alert(f"sust:{username}"):
                threats.append(self._threat(AlertType.SUSTAINED_ATTACK, Severity.CRITICAL, username, ip,
                    "Sustained attack detected"))
        
        return threats
    
    def _check_credential_stuffing(self, ip: str, threshold: int) -> bool:
        cutoff = datetime.now() - timedelta(seconds=300)
        with self._detector_lock:
            recent = [a for a in self._ip_cache.get(ip, []) if a['time'] > cutoff]
        return len(set(a['user'] for a in recent if not a['success'])) >= threshold
    
    def _check_sustained(self, username: str, threshold: int, window: int) -> bool:
        recent = self._get_user_attempts(username, window)
        return sum(1 for a in recent if not a['success']) >= threshold
    
    def _get_user_attempts(self, username: str, seconds: int) -> List[Dict]:
        cutoff = datetime.now() - timedelta(seconds=seconds)
        with self._detector_lock:
            return [a for a in self._login_cache.get(username, []) if a['time'] > cutoff]
    
    def _should_alert(self, key: str, minutes: int = 5) -> bool:
        now = datetime.now()
        with self._detector_lock:
            if key in self._alert_dedup and now - self._alert_dedup[key] < timedelta(minutes=minutes):
                return False
            self._alert_dedup[key] = now
        return True
    
    def _threat(self, atype: AlertType, severity: Severity, user: str, ip: str, details: str) -> Dict:
        return {
            'type': atype.value,
            'severity': severity.value,
            'username': user,
            'ip': ip,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
    
    def _cleanup(self):
        cutoff = datetime.now() - timedelta(hours=1)
        for cache in [self._login_cache, self._ip_cache]:
            for key in list(cache.keys()):
                cache[key] = [a for a in cache[key] if a['time'] > cutoff]
                if not cache[key]:
                    del cache[key]
# ============================================================================
# SERVICES
# ============================================================================

class AlertManager:
    @staticmethod
    def create(alert_type: str, username: str, ip: str, severity: str, details: str = '') -> int:
        alert_id = AlertModel.create(alert_type, username, ip, severity)
        ForensicLogModel.create("ALERT_CREATED", "SYSTEM", ip, f"ALERT_{severity.upper()}", f"{alert_type}")
        icon = {'low': '🟢', 'medium': '🟡', 'high': '🟠', 'critical': '🔴'}.get(severity, '⚪')
        logger.warning(f"{icon} ALERT: {alert_type} | {severity.upper()}")
        return alert_id
    
    @staticmethod
    def process_threats(threats: List[Dict]) -> None:
        for threat in threats:
            AlertManager.create(threat['type'], threat['username'], threat['ip'], threat['severity'], threat['details'])
            NotificationService.security_alert(threat['username'], threat['type'], threat['severity'])

class NotificationService:
    @staticmethod
    def account_locked(username: str, reason: str):
        logger.info(f"📧 NOTIFICATION: Account locked")
        ForensicLogModel.create("NOTIFICATION", "SYSTEM", "N/A", "ACCOUNT_LOCKED", "Account locked")
    
    @staticmethod
    def account_unlocked(username: str):
        logger.info(f"📧 NOTIFICATION: Account unlocked")
        ForensicLogModel.create("NOTIFICATION", "SYSTEM", "N/A", "ACCOUNT_UNLOCKED", "Account unlocked")
    
    @staticmethod
    def security_alert(username: str, alert_type: str, severity: str):
        logger.info(f"📧 SECURITY ALERT: {alert_type} [{severity}]")

class IPLocationService:
    @staticmethod
    def get_location(ip: str) -> str:
        return f"Location_{hash(ip) % 10}"

class ReportGenerator:
    @staticmethod
    def weekly_report() -> Dict:
        """Generate comprehensive weekly security report"""
        week_ago = (datetime.now() - timedelta(days=7)).isoformat()
        return ReportGenerator._generate_report(week_ago, 'weekly')
    
    @staticmethod
    def monthly_report() -> Dict:
        """Generate comprehensive monthly security report"""
        month_ago = (datetime.now() - timedelta(days=30)).isoformat()
        return ReportGenerator._generate_report(month_ago, 'monthly')
    
    @staticmethod
    def _generate_report(since_date: str, report_type: str) -> Dict:
        """Generate comprehensive security report"""
        # Login statistics
        total = db.query_one('SELECT COUNT(*) as c FROM login_events WHERE timestamp > ?', (since_date,))['c']
        failed = db.query_one("SELECT COUNT(*) as c FROM login_events WHERE status='failed' AND timestamp > ?", (since_date,))['c']
        success = total - failed
        
        # Alert statistics by severity
        severity_breakdown = {}
        for severity in ['critical', 'high', 'medium', 'low']:
            count = db.query_one(
                'SELECT COUNT(*) as c FROM alerts WHERE timestamp > ? AND severity = ?', 
                (since_date, severity)
            )['c']
            severity_breakdown[severity] = count
        
        # Top attacked users
        top_attacked = db.query('''
            SELECT username, COUNT(*) as count FROM login_events 
            WHERE status='failed' AND timestamp > ? 
            GROUP BY username 
            ORDER BY count DESC 
            LIMIT 10
        ''', (since_date,))
        
        # Alert type breakdown
        alert_types = db.query('''
            SELECT alert_type, COUNT(*) as count 
            FROM alerts 
            WHERE timestamp > ? 
            GROUP BY alert_type 
            ORDER BY count DESC
        ''', (since_date,))
        
        # Top attacking IPs
        top_ips = db.query('''
            SELECT ip_address, COUNT(*) as count 
            FROM login_events 
            WHERE status='failed' AND timestamp > ? 
            GROUP BY ip_address 
            ORDER BY count DESC 
            LIMIT 10
        ''', (since_date,))
        
        # Hourly distribution (for trend analysis)
        hourly_dist = db.query('''
            SELECT strftime('%H', timestamp) as hour, COUNT(*) as count 
            FROM login_events 
            WHERE timestamp > ? 
            GROUP BY hour 
            ORDER BY hour
        ''', (since_date,))
        
        # Blocked IPs and Locked Accounts
        blocked_ips_count = db.query_one(
            'SELECT COUNT(*) as c FROM blocked_ips_log WHERE blocked_at > ? AND is_active=1', 
            (since_date,)
        )['c']
        
        locked_accounts_count = db.query_one(
            'SELECT COUNT(*) as c FROM locked_accounts_log WHERE locked_at > ? AND is_active=1', 
            (since_date,)
        )['c']
        
        return {
            'report_type': report_type,
            'period': f'{since_date[:10]} to {datetime.now().strftime("%Y-%m-%d")}',
            'summary': {
                'total_logins': total,
                'successful_logins': success,
                'failed_logins': failed,
                'success_rate': f'{((success / total * 100) if total > 0 else 0):.2f}%',
                'total_alerts': sum(severity_breakdown.values()),
                'blocked_ips': blocked_ips_count,
                'locked_accounts': locked_accounts_count
            },
            'severity_breakdown': severity_breakdown,
            'top_attacked_users': [{'username': r['username'], 'count': r['count']} for r in top_attacked],
            'alert_type_distribution': [{'type': r['alert_type'], 'count': r['count']} for r in alert_types],
            'top_attacking_ips': [{'ip': r['ip_address'], 'count': r['count']} for r in top_ips],
            'hourly_distribution': [{'hour': r['hour'], 'count': r['count']} for r in hourly_dist],
            'generated_at': datetime.now().isoformat(),
            'generated_by': 'IDS System'
        }
    
    @staticmethod
    def threat_intelligence_report() -> Dict:
        """Generate threat intelligence report"""
        week_ago = (datetime.now() - timedelta(days=7)).isoformat()
        
        # Most common attack patterns
        attack_patterns = db.query('''
            SELECT alert_type, COUNT(*) as count, 
                   AVG(CASE WHEN severity='critical' THEN 4 
                            WHEN severity='high' THEN 3 
                            WHEN severity='medium' THEN 2 
                            ELSE 1 END) as avg_severity
            FROM alerts 
            WHERE timestamp > ?
            GROUP BY alert_type
            ORDER BY count DESC
        ''', (week_ago,))
        
        # Attack timing patterns
        time_patterns = db.query('''
            SELECT strftime('%H', timestamp) as hour, 
                   COUNT(*) as attack_count
            FROM alerts
            WHERE timestamp > ?
            GROUP BY hour
            ORDER BY attack_count DESC
            LIMIT 5
        ''', (week_ago,))
        
        # Geographic patterns (based on IP)
        ip_patterns = db.query('''
            SELECT ip_address, COUNT(*) as count,
                   COUNT(DISTINCT username) as unique_targets
            FROM alerts
            WHERE timestamp > ?
            GROUP BY ip_address
            HAVING count > 5
            ORDER BY count DESC
            LIMIT 10
        ''', (week_ago,))
        
        return {
            'report_type': 'threat_intelligence',
            'period': f'Last 7 days',
            'attack_patterns': [
                {'type': r['alert_type'], 'count': r['count'], 'avg_severity': round(r['avg_severity'], 2)} 
                for r in attack_patterns
            ],
            'peak_attack_hours': [
                {'hour': f"{r['hour']}:00", 'attack_count': r['attack_count']} 
                for r in time_patterns
            ],
            'persistent_attackers': [
                {'ip': r['ip_address'], 'attacks': r['count'], 'unique_targets': r['unique_targets']} 
                for r in ip_patterns
            ],
            'generated_at': datetime.now().isoformat()
        }
    
    @staticmethod
    def incident_response_report() -> Dict:
        """Generate incident response report for escalated incidents"""
        # Get all escalated/resolved incidents from detection_patterns
        escalated = db.query('''
            SELECT * FROM detection_patterns 
            WHERE analyst_review IN ('escalated', 'archived')
            ORDER BY timestamp DESC
        ''')
        
        # Group by status
        by_status = {}
        by_severity = {}
        
        for inc in escalated:
            status = inc['analyst_review']
            severity = inc['severity']
            by_status[status] = by_status.get(status, 0) + 1
            by_severity[severity] = by_severity.get(severity, 0) + 1
        
        # Get response times (resolved incidents only)
        response_times = []
        for inc in escalated:
            if inc['reviewed_at']:
                created = datetime.fromisoformat(inc['timestamp'])
                reviewed = datetime.fromisoformat(inc['reviewed_at'])
                response_time = (reviewed - created).total_seconds() / 60  # minutes
                response_times.append(response_time)
        
        avg_response_time = sum(response_times) / len(response_times) if response_times else 0
        
        return {
            'report_type': 'incident_response',
            'total_incidents': len(escalated),
            'by_status': by_status,
            'by_severity': by_severity,
            'average_response_time_minutes': round(avg_response_time, 2),
            'incidents': [
                {
                    'id': inc['id'],
                    'type': inc['pattern_type'],
                    'username': inc['username'],
                    'ip': inc['ip_address'],
                    'severity': inc['severity'],
                    'status': inc['analyst_review'],
                    'timestamp': inc['timestamp'],
                    'reviewed_by': inc['reviewed_by'],
                    'reviewed_at': inc['reviewed_at'],
                    'notes': inc['analyst_notes']
                }
                for inc in escalated[:20]  # Top 20 recent
            ],
            'generated_at': datetime.now().isoformat()
        }
    
    @staticmethod
    def export_csv(data_type: str) -> str:
        """Export data as CSV"""
        output = StringIO()
        writer = csv.writer(output)
        
        if data_type == 'login_events':
            rows = db.query('SELECT * FROM login_events ORDER BY timestamp DESC LIMIT 1000')
            writer.writerow(['id', 'username', 'ip_address', 'timestamp', 'status', 'location'])
            for r in rows:
                writer.writerow([r['id'], r['username'], r['ip_address'], r['timestamp'], r['status'], r['location']])
        
        elif data_type == 'alerts':
            rows = db.query('SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 1000')
            writer.writerow(['id', 'alert_type', 'username', 'ip_address', 'timestamp', 'severity', 'resolved', 'resolved_by', 'resolved_at'])
            for r in rows:
                writer.writerow([r['id'], r['alert_type'], r['username'], r['ip_address'], r['timestamp'], 
                               r['severity'], r['resolved'], r['resolved_by'], r['resolved_at']])
        
        elif data_type == 'forensic_logs':
            rows = db.query('SELECT * FROM forensic_logs ORDER BY timestamp DESC LIMIT 1000')
            writer.writerow(['id', 'event_type', 'user', 'ip_address', 'action', 'timestamp', 'details'])
            for r in rows:
                writer.writerow([r['id'], r['event_type'], r['user'], r['ip_address'], r['action'], r['timestamp'], r['details']])
        
        return output.getvalue()

# ============================================================================
# RESPONSE HELPERS
# ============================================================================

class ResponseHelper:
    @staticmethod
    def success(message: str, data: Dict = None, status_code: int = 200):
        response = {'success': True, 'message': message}
        if data:
            response.update(data)
        return jsonify(response), status_code
    
    @staticmethod
    def error(message: str, status_code: int = 400):
        # SECURITY: Don't expose internal details in production
        if status_code == 500 and config.ENV != 'development':
            message = 'An internal error occurred'
        return jsonify({'success': False, 'message': message}), status_code

# ============================================================================
# AUTH DECORATORS
# ============================================================================

class AuthDecorators:
    _session_manager = None
    
    @classmethod
    def set_session_manager(cls, sm: SessionManager):
        cls._session_manager = sm
    
    @classmethod
    def require_auth(cls, f):
        @wraps(f)
        def decorated(*args, **kwargs):
            token = request.headers.get('X-Session-Token', '')
            session = cls._session_manager.validate(token)
            if not session:
                return ResponseHelper.error('Unauthorized - Please login', 401)
            g.current_user = session
            return f(*args, **kwargs)
        return decorated
    
    @classmethod
    def require_role(cls, *roles):
        def decorator(f):
            @wraps(f)
            def decorated(*args, **kwargs):
                token = request.headers.get('X-Session-Token', '')
                session = cls._session_manager.validate(token)
                if not session:
                    return ResponseHelper.error('Unauthorized - Please login', 401)
                if session['role'] not in roles:
                    ForensicLogModel.create("ACCESS_DENIED", session['username'], request.remote_addr, 
                                          "FORBIDDEN", f"Attempted access to {request.path}")
                    return ResponseHelper.error('Access denied - Insufficient privileges', 403)
                g.current_user = session
                return f(*args, **kwargs)
            return decorated
        return decorator
    
    @classmethod
    def require_admin(cls, f):
        return cls.require_role('admin')(f)
    
    @classmethod
    def require_analyst(cls, f):
        return cls.require_role('analyst', 'admin')(f)

# ============================================================================
# API CONTROLLER - WITH AUTH DECORATORS APPLIED
# ============================================================================

class APIController:
    def __init__(self, app: Flask, session_mgr: SessionManager, rate_limiter: RateLimiter, detector: IDSDetector):
        self.app = app
        self.session_mgr = session_mgr
        self.rate_limiter = rate_limiter
        self.detector = detector
        AuthDecorators.set_session_manager(session_mgr)
        self._register_routes()
    
    def _register_routes(self):
        """
        SECURITY FIX: All protected routes now use authentication decorators
        """
        # Public endpoints
        self.app.add_url_rule('/api/login', 'login', self.login, methods=['POST'])
        self.app.add_url_rule('/api/health', 'health', self.health_check, methods=['GET'])
        
        # Authenticated endpoints (any logged-in user)
        self.app.add_url_rule('/api/logout', 'logout', 
                              AuthDecorators.require_auth(self.logout), methods=['POST'])
        self.app.add_url_rule('/api/change-password', 'change_password',
                              AuthDecorators.require_auth(self.change_password), methods=['POST'])
        
        # Dashboard - require authentication
        self.app.add_url_rule('/api/dashboard/stats', 'stats', 
                              AuthDecorators.require_auth(self.get_stats), methods=['GET'])
        self.app.add_url_rule('/api/dashboard/alerts', 'alerts', 
                              AuthDecorators.require_auth(self.get_alerts), methods=['GET'])
        self.app.add_url_rule('/api/dashboard/login-history', 'login_history', 
                              AuthDecorators.require_auth(self.get_login_history), methods=['GET'])
        
        # Admin endpoints - require admin role
        self.app.add_url_rule('/api/admin/config', 'config', 
                              AuthDecorators.require_admin(self.admin_config), methods=['GET', 'POST'])
        self.app.add_url_rule('/api/admin/rules', 'rules', 
                              AuthDecorators.require_admin(self.admin_rules), methods=['GET', 'POST'])
        self.app.add_url_rule('/api/admin/rules/<int:rule_id>/toggle', 'toggle_rule', 
                              AuthDecorators.require_admin(self.toggle_rule), methods=['POST'])
        self.app.add_url_rule('/api/admin/rules/<int:rule_id>', 'delete_rule', 
                              AuthDecorators.require_admin(self.delete_rule), methods=['DELETE'])
        self.app.add_url_rule('/api/admin/block-ip', 'block_ip', 
                              AuthDecorators.require_admin(self.block_ip), methods=['POST'])
        self.app.add_url_rule('/api/admin/unblock-ip', 'unblock_ip', 
                              AuthDecorators.require_admin(self.unblock_ip), methods=['POST'])
        self.app.add_url_rule('/api/admin/lock-account', 'lock_account', 
                              AuthDecorators.require_admin(self.lock_account), methods=['POST'])
        self.app.add_url_rule('/api/admin/unlock-account', 'unlock_account', 
                              AuthDecorators.require_admin(self.unlock_account), methods=['POST'])
        self.app.add_url_rule('/api/admin/rate-limiter/stats', 'rate_stats', 
                              AuthDecorators.require_admin(self.get_rate_stats), methods=['GET'])
        self.app.add_url_rule('/api/admin/rate-limiter/blocked', 'rate_blocked', 
                              AuthDecorators.require_admin(self.get_rate_blocked), methods=['GET'])
        self.app.add_url_rule('/api/admin/rate-limiter/unblock', 'rate_unblock', 
                              AuthDecorators.require_admin(self.unblock_rate_limited), methods=['POST'])
        self.app.add_url_rule('/api/admin/reports/weekly', 'weekly_report', 
                              AuthDecorators.require_admin(self.weekly_report), methods=['GET'])
        self.app.add_url_rule('/api/admin/export/<data_type>', 'export', 
                              AuthDecorators.require_admin(self.export_data), methods=['GET'])
        
        # Analyst endpoints - require analyst or admin role
        self.app.add_url_rule('/api/analyst/detections', 'detections', 
                              AuthDecorators.require_analyst(self.get_detections), methods=['GET'])
        self.app.add_url_rule('/api/analyst/escalate-incident', 'escalate', 
                              AuthDecorators.require_analyst(self.escalate_incident), methods=['POST'])
        self.app.add_url_rule('/api/analyst/archive-incident', 'archive', 
                              AuthDecorators.require_analyst(self.archive_incident), methods=['POST'])
        self.app.add_url_rule('/api/analyst/tag-incident', 'tag', 
                              AuthDecorators.require_analyst(self.tag_incident), methods=['POST'])
    
        # Analyst report endpoints
        self.app.add_url_rule('/api/analyst/reports/threat', 'threat_report',
                            AuthDecorators.require_analyst(self.threat_report), methods=['GET'])
        self.app.add_url_rule('/api/analyst/reports/incident', 'incident_report',
                            AuthDecorators.require_analyst(self.incident_report), methods=['GET'])
        self.app.add_url_rule('/api/analyst/reports/monthly', 'monthly_report',
                            AuthDecorators.require_analyst(self.monthly_report_endpoint), methods=['GET'])

    # ---------- Public Endpoints ----------
    def health_check(self):
        """Health check endpoint for monitoring"""
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'version': '4.0',
            'environment': config.ENV
        })
    
    def login(self):
        try:
            data = request.json or {}
            username = InputValidator.sanitize(data.get('username', ''))
            password = data.get('password', '')
            ip = request.remote_addr
            location = IPLocationService.get_location(ip)
            
            # Rate limiting check
            is_allowed, remaining = self.rate_limiter.check(ip)
            if not is_allowed:
                LoginEventModel.create(username, ip, LoginStatus.RATE_LIMITED.value, location)
                ForensicLogModel.create("LOGIN_RATE_LIMITED", username, ip, "BLOCKED", f"Rate limited")
                return ResponseHelper.error(f'Too many requests. Please wait {remaining} seconds.', 429)
            
            # Check if IP is blocked
            blocked = BlockedIPModel.is_blocked(ip)
            if blocked:
                LoginEventModel.create(username, ip, LoginStatus.BLOCKED_IP.value, location)
                ForensicLogModel.create("LOGIN_BLOCKED", username, ip, "BLOCKED_IP", "Blocked IP attempt")
                AlertManager.create(AlertType.BLACKLISTED_IP.value, username, ip, Severity.HIGH.value, "Blocked IP attempt")
                return ResponseHelper.error("Access denied: Your IP has been blocked", 403)
            
            # Check if account is locked
            locked = LockedAccountModel.is_locked(username)
            if locked:
                LoginEventModel.create(username, ip, LoginStatus.LOCKED_ACCOUNT.value, location)
                ForensicLogModel.create("LOGIN_BLOCKED", username, ip, "LOCKED_ACCOUNT", "Locked account attempt")
                return ResponseHelper.error(f"Account temporarily locked. Try again after {locked['unlock_time']}", 403)
            
            # Authenticate
            user = UserModel.authenticate(username, password)
            if user:
                LoginEventModel.create(username, ip, LoginStatus.SUCCESS.value, location)
                ForensicLogModel.create("LOGIN_SUCCESS", username, ip, "AUTHENTICATED", "Login successful")
                self.detector.analyze(username, ip, success=True)
                token = self.session_mgr.create(username, user['role'], ip)
                
                response_data = {
                    'session_token': token, 
                    'role': user['role'], 
                    'username': username
                }
                
                # Check if password change is required
                if user.get('must_change_password'):
                    response_data['must_change_password'] = True
                    response_data['message'] = 'Password change required'
                
                return ResponseHelper.success('Login successful', response_data)
            else:
                LoginEventModel.create(username, ip, LoginStatus.FAILED.value, location)
                ForensicLogModel.create("LOGIN_FAILED", username, ip, "INVALID_CREDENTIALS", "Authentication failed")
                threats = self.detector.analyze(username, ip, success=False)
                AlertManager.process_threats(threats)
                # Generic message to prevent user enumeration
                return ResponseHelper.error('Invalid credentials', 401)
        except Exception as e:
            logger.error(f"Login error: {type(e).__name__}")
            return ResponseHelper.error('Server error', 500)
    
    # ---------- Authenticated Endpoints ----------
    def logout(self):
        token = request.headers.get('X-Session-Token', '')
        self.session_mgr.invalidate(token)
        ForensicLogModel.create("LOGOUT", g.current_user['username'], request.remote_addr, "SESSION_ENDED", "Logout")
        return ResponseHelper.success('Logged out successfully')
    
    def change_password(self):
        """Allow users to change their password"""
        try:
            data = request.json or {}
            current_password = data.get('current_password', '')
            new_password = data.get('new_password', '')
            
            if not current_password or not new_password:
                return ResponseHelper.error('Current and new password required', 400)
            
            if len(new_password) < 8:
                return ResponseHelper.error('New password must be at least 8 characters', 400)
            
            username = g.current_user['username']
            user = UserModel.find_by_username(username)
            
            if not UserModel.verify_password(current_password, user['password_hash']):
                return ResponseHelper.error('Current password is incorrect', 401)
            
            if UserModel.update_password(username, new_password):
                ForensicLogModel.create("PASSWORD_CHANGED", username, request.remote_addr, "UPDATE", "Password changed")
                return ResponseHelper.success('Password changed successfully')
            else:
                return ResponseHelper.error('Failed to change password', 500)
        except Exception as e:
            logger.error(f"Password change error: {type(e).__name__}")
            return ResponseHelper.error('Server error', 500)
    
    # ---------- Dashboard ----------
    def get_stats(self):
        try:
            return jsonify({
                'total_logins': LoginEventModel.count(),
                'failed_attempts': LoginEventModel.count("status='failed'"),
                'active_alerts': AlertModel.count('resolved=0'),
                'unreviewed_detections': DetectionPatternModel.count("analyst_review='pending'"),
                'blocked_ips': BlockedIPModel.count('is_active=1'),
                'locked_accounts': LockedAccountModel.count('is_active=1'),
                'rate_limited_ips': self.rate_limiter.stats['blocked_ips'],
                'active_sessions': self.session_mgr.active_count
            })
        except Exception as e:
            logger.error(f"Stats error: {type(e).__name__}")
            return ResponseHelper.error('Server error', 500)
    
    def get_alerts(self):
        try:
            limit = min(request.args.get('limit', 100, type=int), 1000)  # Cap at 1000
            rows = db.query('SELECT id, alert_type, username, ip_address, timestamp, severity, resolved FROM alerts ORDER BY timestamp DESC LIMIT ?', (limit,))
            alerts = [{'id': r['id'], 'alert_type': r['alert_type'], 'username': r['username'], 'ip_address': r['ip_address'],
                       'timestamp': r['timestamp'], 'severity': r['severity'], 'resolved': r['resolved']} for r in rows]
            return jsonify({'alerts': alerts, 'count': len(alerts)})
        except Exception as e:
            logger.error(f"Alerts error: {type(e).__name__}")
            return ResponseHelper.error('Server error', 500)
    
    def get_login_history(self):
        try:
            limit = min(request.args.get('limit', 100, type=int), 1000)
            rows = db.query('SELECT username, ip_address, timestamp, status, location FROM login_events ORDER BY timestamp DESC LIMIT ?', (limit,))
            history = [{'username': r['username'], 'ip_address': r['ip_address'], 'timestamp': r['timestamp'],
                        'status': r['status'], 'location': r['location'] or 'Unknown'} for r in rows]
            return jsonify({'history': history, 'count': len(history)})
        except Exception as e:
            logger.error(f"Login history error: {type(e).__name__}")
            return ResponseHelper.error('Server error', 500)
    
    # ---------- Admin ----------
    def admin_config(self):
        if request.method == 'GET':
            try:
                config_data = ConfigModel.get_all()
                return jsonify(config_data)
            except Exception as e:
                logger.error(f"Config GET error: {type(e).__name__}")
                return ResponseHelper.error('Server error', 500)
        else:
            try:
                data = request.json or {}
                for key, value in data.items():
                    valid, msg = InputValidator.validate_number(value, 1, 86400, key)
                    if not valid:
                        return ResponseHelper.error(msg, 400)
                    ConfigModel.set(key, value)
                self.detector.reload_thresholds()
                ForensicLogModel.create('CONFIG_UPDATED', g.current_user['username'], request.remote_addr, 
                                       'UPDATE', f'Config keys updated: {len(data)}')
                return ResponseHelper.success('Configuration updated')
            except Exception as e:
                logger.error(f"Config POST error: {type(e).__name__}")
                return ResponseHelper.error('Server error', 500)
    
    def admin_rules(self):
        if request.method == 'GET':
            try:
                rows = db.query('SELECT id, rule_name, rule_condition, severity, action, created_at, is_active FROM detection_rules ORDER BY id')
                rules = [{'id': r['id'], 'name': r['rule_name'], 'condition': r['rule_condition'], 'severity': r['severity'],
                          'action': r['action'], 'created_at': r['created_at'], 'is_active': r['is_active']} for r in rows]
                return jsonify({'rules': rules})
            except Exception as e:
                logger.error(f"Rules GET error: {type(e).__name__}")
                return ResponseHelper.error('Server error', 500)
        else:
            try:
                data = request.json or {}
                name = InputValidator.sanitize(data.get('name', ''))
                condition = InputValidator.sanitize(data.get('condition', ''))
                if not name or not condition:
                    return ResponseHelper.error('Rule name and condition required', 400)
                DetectionRuleModel.create(name, condition, data.get('severity', 'medium'), data.get('action', 'alert'))
                ForensicLogModel.create('RULE_CREATED', g.current_user['username'], request.remote_addr, 'CREATE', f"Rule created")
                return ResponseHelper.success('Rule created successfully')
            except Exception as e:
                logger.error(f"Rules POST error: {type(e).__name__}")
                return ResponseHelper.error('Server error', 500)
    
    def toggle_rule(self, rule_id: int):
        try:
            data = request.json or {}
            active = data.get('active', True)
            DetectionRuleModel.toggle(rule_id, active)
            ForensicLogModel.create('RULE_TOGGLED', g.current_user['username'], request.remote_addr, 
                                   'ENABLE' if active else 'DISABLE', f"Rule ID: {rule_id}")
            return ResponseHelper.success('Rule updated')
        except Exception as e:
            logger.error(f"Toggle rule error: {type(e).__name__}")
            return ResponseHelper.error('Server error', 500)
    
    def delete_rule(self, rule_id: int):
        try:
            DetectionRuleModel.delete_by_id(rule_id)
            ForensicLogModel.create('RULE_DELETED', g.current_user['username'], request.remote_addr, 'DELETE', f"Rule ID: {rule_id}")
            return ResponseHelper.success('Rule deleted')
        except Exception as e:
            logger.error(f"Delete rule error: {type(e).__name__}")
            return ResponseHelper.error('Server error', 500)
    
    def block_ip(self):
        try:
            data = request.json or {}
            ip = data.get('ip', '')
            reason = InputValidator.sanitize(data.get('reason', 'Admin manual block'))
            valid, msg = InputValidator.validate_ip(ip)
            if not valid:
                return ResponseHelper.error(msg, 400)
            if BlockedIPModel.is_blocked(ip):
                return ResponseHelper.error('IP is already blocked', 400)
            BlockedIPModel.block(ip, reason, g.current_user['username'])
            ForensicLogModel.create('IP_BLOCKED', g.current_user['username'], ip, 'BLOCK', reason)
            logger.info(f"IP blocked by admin")
            return ResponseHelper.success(f'IP blocked successfully')
        except Exception as e:
            logger.error(f"Block IP error: {type(e).__name__}")
            return ResponseHelper.error('Server error', 500)
    
    def unblock_ip(self):
        try:
            data = request.json or {}
            ip = data.get('ip', '')
            valid, msg = InputValidator.validate_ip(ip)
            if not valid:
                return ResponseHelper.error(msg, 400)
            BlockedIPModel.unblock(ip)
            ForensicLogModel.create('IP_UNBLOCKED', g.current_user['username'], ip, 'UNBLOCK', 'Manual unblock')
            logger.info(f"IP unblocked by admin")
            return ResponseHelper.success(f'IP unblocked successfully')
        except Exception as e:
            logger.error(f"Unblock IP error: {type(e).__name__}")
            return ResponseHelper.error('Server error', 500)
    
    def lock_account(self):
        try:
            data = request.json or {}
            username = InputValidator.sanitize(data.get('username', ''))
            reason = InputValidator.sanitize(data.get('reason', 'Security precaution'))
            valid, msg = InputValidator.validate_username(username)
            if not valid:
                return ResponseHelper.error(msg, 400)
            if LockedAccountModel.is_locked(username):
                return ResponseHelper.error('Account is already locked', 400)
            LockedAccountModel.lock(username, reason, DetectionThresholds().lockout_duration, g.current_user['username'])
            ForensicLogModel.create('ACCOUNT_LOCKED', g.current_user['username'], request.remote_addr, 'LOCK', f'Account locked')
            NotificationService.account_locked(username, reason)
            logger.info(f"Account locked by admin")
            return ResponseHelper.success(f'Account locked successfully')
        except Exception as e:
            logger.error(f"Lock account error: {type(e).__name__}")
            return ResponseHelper.error('Server error', 500)
    
    def unlock_account(self):
        try:
            data = request.json or {}
            username = InputValidator.sanitize(data.get('username', ''))
            valid, msg = InputValidator.validate_username(username)
            if not valid:
                return ResponseHelper.error(msg, 400)
            LockedAccountModel.unlock(username)
            ForensicLogModel.create('ACCOUNT_UNLOCKED', g.current_user['username'], request.remote_addr, 'UNLOCK', 'Account unlocked')
            NotificationService.account_unlocked(username)
            logger.info(f"Account unlocked by admin")
            return ResponseHelper.success(f'Account unlocked successfully')
        except Exception as e:
            logger.error(f"Unlock account error: {type(e).__name__}")
            return ResponseHelper.error('Server error', 500)
    
    def get_rate_stats(self):
        return jsonify(self.rate_limiter.stats)
    
    def get_rate_blocked(self):
        return jsonify({'blocked_ips': self.rate_limiter.get_blocked()})
    
    def unblock_rate_limited(self):
        try:
            data = request.json or {}
            ip = data.get('ip', '')
            valid, msg = InputValidator.validate_ip(ip)
            if not valid:
                return ResponseHelper.error(msg, 400)
            if self.rate_limiter.unblock(ip):
                ForensicLogModel.create('RATE_LIMIT_UNBLOCK', g.current_user['username'], ip, 'UNBLOCK', 'Manual removal')
                return ResponseHelper.success(f'IP unblocked from rate limiter')
            return ResponseHelper.error('IP not found in rate limiter', 404)
        except Exception as e:
            logger.error(f"Rate unblock error: {type(e).__name__}")
            return ResponseHelper.error('Server error', 500)
    
    def weekly_report(self):
        try:
            report = ReportGenerator.weekly_report()
            ForensicLogModel.create('REPORT_GENERATED', g.current_user['username'], request.remote_addr, 'REPORT', 'Weekly report')
            return jsonify(report)
        except Exception as e:
            logger.error(f"Weekly report error: {type(e).__name__}")
            return ResponseHelper.error('Server error', 500)
    
    def export_data(self, data_type: str):
        try:
            if data_type not in ['login_events', 'alerts', 'forensic_logs']:
                return ResponseHelper.error('Invalid data type', 400)
            csv_data = ReportGenerator.export_csv(data_type)
            ForensicLogModel.create('DATA_EXPORT', g.current_user['username'], request.remote_addr, 'EXPORT', f'{data_type}')
            return Response(csv_data, mimetype='text/csv', headers={'Content-Disposition': f'attachment;filename={data_type}.csv'})
        except Exception as e:
            logger.error(f"Export error: {type(e).__name__}")
            return ResponseHelper.error('Server error', 500)
    
    # ---------- Analyst ----------
    def get_detections(self):
        try:
            limit = min(request.args.get('limit', 50, type=int), 500)
            status = request.args.get('status', 'all')
            if status == 'pending':
                query = "SELECT * FROM detection_patterns WHERE analyst_review='pending' ORDER BY timestamp DESC LIMIT ?"
            elif status == 'reviewed':
                query = "SELECT * FROM detection_patterns WHERE analyst_review!='pending' ORDER BY timestamp DESC LIMIT ?"
            else:
                query = "SELECT * FROM detection_patterns ORDER BY timestamp DESC LIMIT ?"
            rows = db.query(query, (limit,))
            detections = [{'id': r['id'], 'pattern_type': r['pattern_type'], 'username': r['username'],
                           'ip_address': r['ip_address'], 'timestamp': r['timestamp'], 'severity': r['severity'],
                           'details': r['details'], 'analyst_review': r['analyst_review'], 'analyst_notes': r['analyst_notes'],
                           'reviewed_at': r['reviewed_at'], 'reviewed_by': r['reviewed_by']} for r in rows]
            return jsonify({'detections': detections, 'count': len(detections)})
        except Exception as e:
            logger.error(f"Detections error: {type(e).__name__}")
            return ResponseHelper.error('Server error', 500)
    
    def escalate_incident(self):
        try:
            data = request.json or {}
            incident_id = data.get('incident_id')
            if not incident_id:
                return ResponseHelper.error('Incident ID required', 400)
            analyst = g.current_user['username']
            AlertModel.resolve(incident_id, analyst)
            DetectionPatternModel.update_review(incident_id, ReviewStatus.ESCALATED.value, analyst)
            ForensicLogModel.create("INCIDENT_ESCALATED", analyst, request.remote_addr, "ESCALATE", f"Alert #{incident_id}")
            logger.info(f"Alert #{incident_id} escalated")
            return ResponseHelper.success('Incident escalated to administrator')
        except Exception as e:
            logger.error(f"Escalate error: {type(e).__name__}")
            return ResponseHelper.error('Server error', 500)
    
    def archive_incident(self):
        try:
            data = request.json or {}
            incident_id = data.get('incident_id')
            if not incident_id:
                return ResponseHelper.error('Incident ID required', 400)
            analyst = g.current_user['username']
            AlertModel.resolve(incident_id, analyst)
            DetectionPatternModel.update_review(incident_id, ReviewStatus.ARCHIVED.value, analyst)
            ForensicLogModel.create("INCIDENT_ARCHIVED", analyst, request.remote_addr, "ARCHIVE", f"Alert #{incident_id}")
            logger.info(f"Alert #{incident_id} archived")
            return ResponseHelper.success('Incident archived')
        except Exception as e:
            logger.error(f"Archive error: {type(e).__name__}")
            return ResponseHelper.error('Server error', 500)
    
    def tag_incident(self):
        try:
            data = request.json or {}
            incident_id = data.get('incident_id')
            tag = InputValidator.sanitize(data.get('tag', ''))
            if not incident_id or not tag:
                return ResponseHelper.error('Incident ID and tag required', 400)
            analyst = g.current_user['username']
            ForensicLogModel.create("INCIDENT_TAGGED", analyst, request.remote_addr, "TAG", f"Alert #{incident_id} tagged: {tag}")
            logger.info(f"Alert #{incident_id} tagged")
            return ResponseHelper.success(f'Incident tagged with: {tag}')
        except Exception as e:
            logger.error(f"Tag error: {type(e).__name__}")
            return ResponseHelper.error('Server error', 500)

    def monthly_report_endpoint(self):
        """Monthly report endpoint for analysts"""
        try:
            report = ReportGenerator.monthly_report()
            ForensicLogModel.create('REPORT_GENERATED', g.current_user['username'], 
                                request.remote_addr, 'REPORT', 'Monthly report')
            return jsonify(report)
        except Exception as e:
            logger.error(f"Monthly report error: {type(e).__name__}")
            return ResponseHelper.error('Server error', 500)

    def threat_report(self):
        """Threat intelligence report endpoint"""
        try:
            report = ReportGenerator.threat_intelligence_report()
            ForensicLogModel.create('REPORT_GENERATED', g.current_user['username'], 
                                request.remote_addr, 'REPORT', 'Threat intelligence')
            return jsonify(report)
        except Exception as e:
            logger.error(f"Threat report error: {type(e).__name__}")
            return ResponseHelper.error('Server error', 500)

    def incident_report(self):
        """Incident response report endpoint"""
        try:
            report = ReportGenerator.incident_response_report()
            ForensicLogModel.create('REPORT_GENERATED', g.current_user['username'], 
                                request.remote_addr, 'REPORT', 'Incident response')
            return jsonify(report)
        except Exception as e:
            logger.error(f"Incident report error: {type(e).__name__}")
            return ResponseHelper.error('Server error', 500)

# ============================================================================
# IDS APPLICATION - MAIN CLASS
# ============================================================================

class IDSApplication:
    def __init__(self):
        self.app = Flask(__name__)
        self.app.secret_key = config.SECRET_KEY
        self._setup_cors()
        self._setup_security_headers()
        self.session_mgr = SessionManager(config.SESSION_TIMEOUT)
        self.rate_limiter = RateLimiter(config.RATE_LIMIT_MAX, config.RATE_LIMIT_WINDOW, config.RATE_LIMIT_BLOCK)
        self.detector = IDSDetector()
        self.controller = APIController(self.app, self.session_mgr, self.rate_limiter, self.detector)
        self._init_database()
    
    def _setup_cors(self):
        """Configure CORS with restricted origins"""
        CORS(self.app, origins=['http://localhost:5000', 'http://127.0.0.1:5000',
                            'http://localhost:5001', 'http://127.0.0.1:5001'])
    
    def _setup_security_headers(self):
        """Add security headers to all responses"""
        @self.app.after_request
        def add_security_headers(response):
            response.headers['X-Content-Type-Options'] = 'nosniff'
            response.headers['X-Frame-Options'] = 'DENY'
            response.headers['X-XSS-Protection'] = '1; mode=block'
            response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
            if config.ENV != 'development':
                response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
            return response
    
    def _init_database(self):
        try:
            schema = '''
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, 
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL, 
                    role TEXT DEFAULT 'user', 
                    created_at TEXT, 
                    is_active INTEGER DEFAULT 1,
                    must_change_password INTEGER DEFAULT 0
                );
                CREATE TABLE IF NOT EXISTS login_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, 
                    username TEXT, 
                    ip_address TEXT,
                    timestamp TEXT, 
                    status TEXT, 
                    location TEXT
                );
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, 
                    alert_type TEXT, 
                    username TEXT, 
                    ip_address TEXT,
                    timestamp TEXT, 
                    severity TEXT, 
                    resolved INTEGER DEFAULT 0, 
                    resolved_at TEXT, 
                    resolved_by TEXT
                );
                CREATE TABLE IF NOT EXISTS forensic_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, 
                    event_type TEXT, 
                    user TEXT, 
                    ip_address TEXT,
                    action TEXT, 
                    timestamp TEXT, 
                    details TEXT
                );
                CREATE TABLE IF NOT EXISTS blocked_ips_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, 
                    ip_address TEXT, 
                    reason TEXT,
                    blocked_at TEXT, 
                    blocked_by TEXT, 
                    is_active INTEGER DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS locked_accounts_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, 
                    username TEXT, 
                    reason TEXT,
                    locked_at TEXT, 
                    locked_by TEXT, 
                    unlock_time TEXT, 
                    is_active INTEGER DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS detection_patterns (
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
                );
                CREATE TABLE IF NOT EXISTS detection_rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, 
                    rule_name TEXT, 
                    rule_condition TEXT,
                    severity TEXT, 
                    action TEXT, 
                    created_at TEXT, 
                    is_active INTEGER DEFAULT 1
                );
                CREATE TABLE IF NOT EXISTS config (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, 
                    key TEXT UNIQUE, 
                    value TEXT, 
                    updated_at TEXT
                );
            '''
            db.execute_script(schema)
            self._create_default_users()
            self._create_default_config()
            logger.info("Database initialized successfully")
        except Exception as e:
            logger.error(f"Database initialization failed: {type(e).__name__}")
            raise
    
    def _create_default_users(self):
        """
        SECURITY: Use environment variables in production
        Development uses strong test passwords
        """
        # Development: Use strong test passwords
        # Production: Use environment variables
        admin_pass = os.environ.get('IDS_ADMIN_PASSWORD', 'Admin2024!Strong')
        analyst_pass = os.environ.get('IDS_ANALYST_PASSWORD', 'Analyst2024!Strong')
        user_pass = os.environ.get('IDS_USER_PASSWORD', 'User2024!Strong')
        
        # Log passwords ONLY in development mode
        if config.ENV == 'development':
            logger.warning(f"🔐 DEVELOPMENT MODE - Test Credentials:")
            logger.warning(f"Admin: admin / {admin_pass}")
            logger.warning(f"Analyst: analyst / {analyst_pass}")
            logger.warning(f"User: testuser / {user_pass}")
        
        defaults = [
            ('admin', admin_pass, 'admin'),
            ('analyst', analyst_pass, 'analyst'),
            ('testuser', user_pass, 'user')
        ]
        
        for username, password, role in defaults:
            if not UserModel.find_by_username(username):
                # SECURITY: Flag default accounts to require password change (production only)
                # In development mode, don't require password change for easier testing
                must_change = (config.ENV != 'development' and 
                            os.environ.get(f'IDS_{role.upper()}_PASSWORD') is None)
                UserModel.create(username, password, role, must_change_password=must_change)
                if must_change:
                    logger.info(f"Default {role} account created - PASSWORD CHANGE REQUIRED ON FIRST LOGIN")
                else:
                    logger.info(f"Default {role} account created")

    def _create_default_config(self):
        defaults = {
            'max_failed_attempts': 10, 
            'detection_window': 120, 
            'lockout_duration': 900,
            'distributed_threshold': 5, 
            'credential_stuffing_threshold': 10,
            'sustained_attack_threshold': 10, 
            'sustained_attack_window': 600
        }
        for key, value in defaults.items():
            try:
                ConfigModel.set(key, value)
            except Exception:
                pass
    def run(self, host: str = None, port: int = None, debug: bool = None):
        self.app.run(
            host=host or config.HOST, 
            port=port or config.PORT, 
            debug=debug if debug is not None else config.DEBUG
        )
# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ == '__main__':
    ids = IDSApplication()
    app = IDSApplication().app

    
    # SECURITY FIX: Don't log credentials
    logger.info(f"DS System starting on {config.HOST}:{config.PORT}")
    logger.info(f"Environment: {config.ENV}")
    logger.info(f"Default accounts created with PASSWORD CHANGE REQUIRED")
    logger.info(f"Set IDS_ADMIN_PASSWORD, IDS_ANALYST_PASSWORD, IDS_USER_PASSWORD environment variables for production")
    logger.info(f"CORS Origins: {config.CORS_ORIGINS}")
    
    ids.run()

app = IDSApplication().app    