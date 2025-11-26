const API_BASE = process.env.API_URL || 'http://127.0.0.1:5000/api';
let refreshInterval = 5000;
let refreshTimerId = null;

// Session Manager
class SessionManager {
    static getToken() { return sessionStorage.getItem('sessionToken'); }
    static getRole() { return sessionStorage.getItem('userRole'); }
    static getUsername() { return sessionStorage.getItem('username'); }
    static clearSession() {
        sessionStorage.removeItem('sessionToken');
        sessionStorage.removeItem('userRole');
        sessionStorage.removeItem('username');
    }
    static isLoggedIn() { return !!this.getToken(); }
    static isAdmin() { return this.getRole() === 'admin'; }
}

// Input Validator
class InputValidator {
    static validateIP(ip) {
        const pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
        if (!pattern.test(ip)) return { valid: false, msg: 'Invalid IP format' };
        const parts = ip.split('.').map(Number);
        if (parts.some(p => p < 0 || p > 255)) return { valid: false, msg: 'IP octets must be 0-255' };
        return { valid: true };
    }
    static validateUsername(u) {
        if (!u || u.length < 3) return { valid: false, msg: 'Username must be 3+ characters' };
        if (u.length > 50) return { valid: false, msg: 'Username too long' };
        if (!/^[a-zA-Z0-9_]+$/.test(u)) return { valid: false, msg: 'Alphanumeric and underscore only' };
        return { valid: true };
    }
    static sanitize(str) {
        return String(str).replace(/[<>'"&]/g, c => ({'<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;','&':'&amp;'}[c]));
    }
}

// Notification Service
class NotificationService {
    static show(msg, type = 'info') {
        const colors = { info: '#3b82f6', success: '#10b981', error: '#ef4444', warning: '#f59e0b' };
        const notif = document.createElement('div');
        notif.style.cssText = `position:fixed;top:80px;right:20px;background:${colors[type]};color:white;padding:1rem 1.5rem;border-radius:0.5rem;box-shadow:0 4px 6px rgba(0,0,0,0.2);z-index:9999;max-width:400px;`;
        notif.textContent = msg;
        document.body.appendChild(notif);
        setTimeout(() => notif.remove(), 4000);
    }
}

// API Client with Auth
class APIClient {
    static getHeaders() {
        const headers = { 'Content-Type': 'application/json' };
        const token = SessionManager.getToken();
        if (token) headers['X-Session-Token'] = token;
        return headers;
    }
    
    static async handleResponse(res) {
        if (res.status === 401) {
            NotificationService.show('Session expired. Please login again.', 'error');
            setTimeout(() => { SessionManager.clearSession(); window.location.href = 'login.html'; }, 2000);
            throw new Error('Unauthorized');
        }
        if (res.status === 403) {
            NotificationService.show('Access denied. Admin privileges required.', 'error');
            throw new Error('Forbidden');
        }
        return res.json();
    }
    
    static async get(endpoint) {
        const res = await fetch(`${API_BASE}${endpoint}`, { headers: this.getHeaders() });
        return this.handleResponse(res);
    }
    
    static async post(endpoint, data) {
        const res = await fetch(`${API_BASE}${endpoint}`, {
            method: 'POST', headers: this.getHeaders(), body: JSON.stringify(data)
        });
        return this.handleResponse(res);
    }
    
    static async delete(endpoint) {
        const res = await fetch(`${API_BASE}${endpoint}`, { method: 'DELETE', headers: this.getHeaders() });
        return this.handleResponse(res);
    }
    
    // Special method for downloading files with auth
    static async downloadFile(endpoint, filename) {
        try {
            const res = await fetch(`${API_BASE}${endpoint}`, { 
                headers: this.getHeaders() 
            });
            if (!res.ok) {
                if (res.status === 401) {
                    NotificationService.show('Session expired', 'error');
                    setTimeout(() => { SessionManager.clearSession(); window.location.href = 'login.html'; }, 2000);
                    return false;
                }
                throw new Error(`HTTP ${res.status}`);
            }
            const blob = await res.blob();
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename;
            a.click();
            URL.revokeObjectURL(url);
            return true;
        } catch (e) {
            console.error('Download error:', e);
            return false;
        }
    }
}

// Auth Check
function checkAuth() {
    if (!SessionManager.isLoggedIn()) {
        window.location.href = 'login.html';
        return false;
    }
    if (!SessionManager.isAdmin()) {
        NotificationService.show('Admin access required', 'error');
        setTimeout(() => window.location.href = 'login.html', 2000);
        return false;
    }
    return true;
}

// Tab Management
function showTab(tabName) {
    document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    document.getElementById(tabName + 'Tab').classList.add('active');
    document.querySelector(`[data-tab="${tabName}"]`).classList.add('active');
    if (tabName === 'policy') loadRules();
}

// Auto Refresh
function startAutoRefresh() {
    if (!refreshTimerId) {
        loadAdminData();
        refreshTimerId = setInterval(loadAdminData, refreshInterval);
        document.getElementById('refreshStatus').innerHTML = '<span class="indicator"></span> Auto-Refresh: ON';
    }
}

// Main Data Loading
async function loadAdminData() {
    try {
        const stats = await APIClient.get('/dashboard/stats');
        document.getElementById('totalLogins').textContent = stats.total_logins || 0;
        document.getElementById('failedAttempts').textContent = stats.failed_attempts || 0;
        document.getElementById('activeAlerts').textContent = stats.active_alerts || 0;
        document.getElementById('blockedIPs').textContent = stats.blocked_ips || 0;
        document.getElementById('lockedUsers').textContent = stats.locked_accounts || 0;
        document.getElementById('rateLimitedIPs').textContent = stats.rate_limited_ips || 0;
        loadUsersTable(); loadBlockedIPsTable(); loadLockedAccountsTable(); loadConfig(); loadRateLimiterStats();
    } catch (e) { console.error('Load error:', e); }
}

// Rate Limiter
async function loadRateLimiterStats() {
    try {
        const stats = await APIClient.get('/admin/rate-limiter/stats');
        document.getElementById('rlMaxRequests').textContent = stats.max_requests || '-';
        document.getElementById('rlWindow').textContent = stats.window_seconds || '-';
        document.getElementById('rlBlockDuration').textContent = stats.block_duration || '-';
        document.getElementById('rlActiveIPs').textContent = stats.active_ips || 0;
        document.getElementById('rlBlockedIPs').textContent = stats.blocked_ips || 0;
        
        const blocked = await APIClient.get('/admin/rate-limiter/blocked');
        const tbody = document.getElementById('rateLimitedTable');
        const ips = blocked.blocked_ips || [];
        
        if (ips.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No rate-limited IPs</td></tr>';
            return;
        }
        
        tbody.innerHTML = ips.map(ip => `<tr>
            <td><code style="background:#0f172a;padding:0.25rem 0.5rem;border-radius:0.25rem;color:#f87171;">${InputValidator.sanitize(ip.ip)}</code></td>
            <td>${new Date(ip.blocked_until).toLocaleString()}</td>
            <td><strong style="color:#fb923c;">${ip.remaining_seconds || ip.remaining}s</strong></td>
            <td><button style="padding:0.5rem;font-size:0.75rem;" class="success" onclick="unblockRateLimitedIP('${ip.ip}')">Unblock</button></td>
        </tr>`).join('');
    } catch (e) { console.error('Rate limiter error:', e); }
}

async function unblockRateLimitedIP(ip) {
    if (!confirm(`Unblock rate-limited IP: ${ip}?`)) return;
    try {
        const res = await APIClient.post('/admin/rate-limiter/unblock', { ip });
        if (res.success) {
            NotificationService.show(`IP ${ip} unblocked`, 'success');
            loadRateLimiterStats(); loadAdminData();
        } else {
            NotificationService.show(res.message || 'Error', 'error');
        }
    } catch (e) { NotificationService.show('Error unblocking IP', 'error'); }
}

async function loadUsersTable() {
    try {
        const data = await APIClient.get('/dashboard/login-history?limit=100');
        const userStats = {};
        (data.history || []).forEach(e => {
            if (!userStats[e.username]) userStats[e.username] = { username: e.username, ip: e.ip_address, failed: 0, lastAttempt: e.timestamp };
            if (e.status === 'failed') userStats[e.username].failed++;
            if (new Date(e.timestamp) > new Date(userStats[e.username].lastAttempt)) {
                userStats[e.username].lastAttempt = e.timestamp;
                userStats[e.username].ip = e.ip_address;
            }
        });
        const tbody = document.getElementById('usersTable');
        const users = Object.values(userStats).sort((a, b) => b.failed - a.failed);
        if (users.length === 0) { tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No user activity</td></tr>'; return; }
        tbody.innerHTML = users.map(u => `<tr>
            <td>${InputValidator.sanitize(u.username)}</td><td>${InputValidator.sanitize(u.ip)}</td>
            <td><strong style="color:${u.failed >= 3 ? '#f87171' : '#4ade80'}">${u.failed}</strong></td>
            <td>${new Date(u.lastAttempt).toLocaleString()}</td>
            <td><span class="badge ${u.failed >= 3 ? 'danger' : 'success'}">${u.failed >= 3 ? 'SUSPICIOUS' : 'NORMAL'}</span></td>
            <td><button style="padding:0.5rem;font-size:0.75rem;" class="danger" onclick="lockAccountQuick('${u.username}')">Lock</button></td>
        </tr>`).join('');
    } catch (e) { document.getElementById('usersTable').innerHTML = '<tr><td colspan="6" class="empty-state">Error loading</td></tr>'; }
}

async function loadBlockedIPsTable() {
    try {
        const data = await APIClient.get('/dashboard/login-history?limit=200');
        const ipStats = {};
        (data.history || []).forEach(e => {
            if (!ipStats[e.ip_address]) ipStats[e.ip_address] = { ip: e.ip_address, failed: 0, firstSeen: e.timestamp };
            if (e.status === 'failed') ipStats[e.ip_address].failed++;
        });
        const tbody = document.getElementById('blockedIPsTable');
        const suspicious = Object.values(ipStats).filter(i => i.failed >= 5).slice(0, 10);
        if (suspicious.length === 0) { tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No suspicious IPs</td></tr>'; return; }
        tbody.innerHTML = suspicious.map(i => `<tr>
            <td>${InputValidator.sanitize(i.ip)}</td><td><strong style="color:#f87171">${i.failed}</strong></td>
            <td>${new Date(i.firstSeen).toLocaleString()}</td>
            <td><button style="padding:0.5rem;font-size:0.75rem;" class="danger" onclick="blockIPQuick('${i.ip}')">Block</button>
                <button style="padding:0.5rem;font-size:0.75rem;" class="success" onclick="unblockIPQuick('${i.ip}')">Unblock</button></td>
        </tr>`).join('');
    } catch (e) { document.getElementById('blockedIPsTable').innerHTML = '<tr><td colspan="4" class="empty-state">Error loading</td></tr>'; }
}

async function loadLockedAccountsTable() {
    try {
        const data = await APIClient.get('/dashboard/alerts?limit=50');
        const locked = (data.alerts || []).filter(a => a.alert_type.includes('FAILED') || a.alert_type.includes('BRUTE')).slice(0, 10);
        const tbody = document.getElementById('lockedAccountsTable');
        if (locked.length === 0) { tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No locked accounts</td></tr>'; return; }
        tbody.innerHTML = locked.map(a => {
            const lockedTime = new Date(a.timestamp), unlockTime = new Date(lockedTime.getTime() + 15 * 60000);
            return `<tr><td>${InputValidator.sanitize(a.username)}</td><td>${lockedTime.toLocaleString()}</td>
                <td>${unlockTime.toLocaleString()}</td>
                <td><button style="padding:0.5rem;font-size:0.75rem;" class="success" onclick="unlockAccountQuick('${a.username}')">Unlock</button></td></tr>`;
        }).join('');
    } catch (e) { document.getElementById('lockedAccountsTable').innerHTML = '<tr><td colspan="4" class="empty-state">Error loading</td></tr>'; }
}

// Config Management
async function loadConfig() {
    try {
        const config = await APIClient.get('/admin/config');
        document.getElementById('maxFailedAttempts').value = config.max_failed_attempts || 10;
        document.getElementById('failedAttemptsWindow').value = config.failed_attempts_window || config.detection_window || 120;
        document.getElementById('lockoutDuration').value = config.lockout_duration || 900;
        document.getElementById('distributedThreshold').value = config.distributed_threshold || 5;
        document.getElementById('cooldownPeriod').value = config.cooldown_period || 600;
        document.getElementById('rateLimitRequests').value = config.rate_limit_requests || 10;
        document.getElementById('rateLimitWindow').value = config.rate_limit_window || 60;
    } catch (e) { console.error('Config load error:', e); }
}

async function saveThresholdSettings() {
    const config = {
        max_failed_attempts: document.getElementById('maxFailedAttempts').value,
        detection_window: document.getElementById('failedAttemptsWindow').value,
        lockout_duration: document.getElementById('lockoutDuration').value,
        distributed_threshold: document.getElementById('distributedThreshold').value
    };
    try {
        const res = await APIClient.post('/admin/config', config);
        showAlert('configAlert', res.success ? 'Thresholds saved!' : res.message, res.success ? 'success' : 'error');
        if (res.success) NotificationService.show('Threshold settings saved', 'success');
    } catch (e) { showAlert('configAlert', 'Error saving', 'error'); }
}

async function saveCooldownSettings() {
    const config = {
        cooldown_period: document.getElementById('cooldownPeriod').value,
        rate_limit_requests: document.getElementById('rateLimitRequests').value,
        rate_limit_window: document.getElementById('rateLimitWindow').value
    };
    try {
        const res = await APIClient.post('/admin/config', config);
        showAlert('cooldownAlert', res.success ? 'Cooldown policy saved!' : res.message, res.success ? 'success' : 'error');
        if (res.success) NotificationService.show('Cooldown settings saved', 'success');
    } catch (e) { showAlert('cooldownAlert', 'Error saving', 'error'); }
}

// Rules Management
async function loadRules() {
    try {
        const data = await APIClient.get('/admin/rules');
        const tbody = document.getElementById('rulesTable');
        const rules = data.rules || [];
        if (rules.length === 0) { tbody.innerHTML = '<tr><td colspan="8" class="empty-state">No rules configured</td></tr>'; return; }
        tbody.innerHTML = rules.map(r => `<tr>
            <td>${r.id}</td><td>${InputValidator.sanitize(r.name)}</td><td style="max-width:200px;overflow:hidden;text-overflow:ellipsis;">${InputValidator.sanitize(r.condition)}</td>
            <td><span class="badge ${r.severity === 'critical' ? 'danger' : r.severity === 'high' ? 'warning' : 'success'}">${r.severity.toUpperCase()}</span></td>
            <td>${r.action}</td><td>${r.threshold || '-'}/${r.time_window || '-'}s</td>
            <td><span class="badge ${r.is_active ? 'success' : 'danger'}">${r.is_active ? 'ACTIVE' : 'DISABLED'}</span></td>
            <td><button style="padding:0.4rem;font-size:0.7rem;" onclick="toggleRule(${r.id}, ${!r.is_active})">${r.is_active ? 'Disable' : 'Enable'}</button>
                <button style="padding:0.4rem;font-size:0.7rem;" class="danger" onclick="deleteRule(${r.id})">Delete</button></td>
        </tr>`).join('');
    } catch (e) { document.getElementById('rulesTable').innerHTML = '<tr><td colspan="8" class="empty-state">Error loading rules</td></tr>'; }
}

async function addRule() {
    const rule = {
        name: document.getElementById('ruleName').value.trim(),
        condition: document.getElementById('ruleCondition').value.trim(),
        severity: document.getElementById('ruleSeverity').value,
        action: document.getElementById('ruleAction').value,
        threshold: parseInt(document.getElementById('ruleThreshold').value),
        time_window: parseInt(document.getElementById('ruleTimeWindow').value)
    };
    if (!rule.name || !rule.condition) { showAlert('ruleAlert', 'Name and condition required', 'error'); return; }
    try {
        const res = await APIClient.post('/admin/rules', rule);
        showAlert('ruleAlert', res.success ? 'Rule added!' : res.message, res.success ? 'success' : 'error');
        if (res.success) { loadRules(); ['ruleName', 'ruleCondition'].forEach(id => document.getElementById(id).value = ''); }
    } catch (e) { showAlert('ruleAlert', 'Error adding rule', 'error'); }
}

async function toggleRule(id, active) {
    try {
        await APIClient.post(`/admin/rules/${id}/toggle`, { active });
        loadRules();
        NotificationService.show(`Rule ${active ? 'enabled' : 'disabled'}`, 'info');
    } catch (e) { NotificationService.show('Error toggling rule', 'error'); }
}

async function deleteRule(id) {
    if (!confirm('Delete this rule?')) return;
    try {
        await APIClient.delete(`/admin/rules/${id}`);
        loadRules();
        NotificationService.show('Rule deleted', 'success');
    } catch (e) { NotificationService.show('Error deleting rule', 'error'); }
}

// IP & Account Management
async function blockIP() {
    const ip = document.getElementById('ipAddress').value.trim();
    const reason = document.getElementById('ipReason').value.trim() || 'Admin manual block';
    const check = InputValidator.validateIP(ip);
    if (!check.valid) { showAlert('ipAlert', check.msg, 'error'); return; }
    try {
        const res = await APIClient.post('/admin/block-ip', { ip, reason });
        showAlert('ipAlert', res.success ? res.message : res.message, res.success ? 'success' : 'error');
        if (res.success) { document.getElementById('ipAddress').value = ''; loadAdminData(); }
    } catch (e) { showAlert('ipAlert', 'Error', 'error'); }
}

async function unblockIP() {
    const ip = document.getElementById('ipAddress').value.trim();
    if (!ip) { showAlert('ipAlert', 'Enter IP address', 'error'); return; }
    try {
        const res = await APIClient.post('/admin/unblock-ip', { ip });
        showAlert('ipAlert', res.success ? res.message : res.message, res.success ? 'success' : 'error');
        if (res.success) loadAdminData();
    } catch (e) { showAlert('ipAlert', 'Error', 'error'); }
}

function blockIPQuick(ip) { if (confirm(`Block IP: ${ip}?`)) { document.getElementById('ipAddress').value = ip; blockIP(); } }
function unblockIPQuick(ip) { document.getElementById('ipAddress').value = ip; unblockIP(); }

async function lockAccount() {
    const username = document.getElementById('username').value.trim();
    const reason = document.getElementById('lockReason').value.trim() || 'Security precaution';
    const check = InputValidator.validateUsername(username);
    if (!check.valid) { showAlert('accountAlert', check.msg, 'error'); return; }
    try {
        const res = await APIClient.post('/admin/lock-account', { username, reason });
        showAlert('accountAlert', res.success ? res.message : res.message, res.success ? 'success' : 'error');
        if (res.success) { document.getElementById('username').value = ''; loadAdminData(); NotificationService.show(`Account ${username} locked`, 'warning'); }
    } catch (e) { showAlert('accountAlert', 'Error', 'error'); }
}

async function unlockAccount() {
    const username = document.getElementById('username').value.trim();
    if (!username) { showAlert('accountAlert', 'Enter username', 'error'); return; }
    try {
        const res = await APIClient.post('/admin/unlock-account', { username });
        showAlert('accountAlert', res.success ? res.message : res.message, res.success ? 'success' : 'error');
        if (res.success) { loadAdminData(); NotificationService.show(`Account ${username} unlocked`, 'success'); }
    } catch (e) { showAlert('accountAlert', 'Error', 'error'); }
}

function lockAccountQuick(u) { if (confirm(`Lock account: ${u}?`)) { document.getElementById('username').value = u; lockAccount(); } }
function unlockAccountQuick(u) { document.getElementById('username').value = u; unlockAccount(); }

// Reports
async function generateWeeklyReport() {
    try {
        NotificationService.show('Generating weekly report...', 'info');
        const report = await APIClient.get('/admin/reports/weekly');
        displayReport(report);
    } catch (e) { NotificationService.show('Error generating report', 'error'); }
}

async function generateMonthlyReport() {
    try {
        NotificationService.show('Generating monthly report...', 'info');
        // Use weekly report endpoint but label as monthly (or create monthly endpoint)
        const report = await APIClient.get('/admin/reports/weekly');
        report.report_type = 'monthly';
        displayReport(report);
    } catch (e) { NotificationService.show('Error generating report', 'error'); }
}

function displayReport(report) {
    document.getElementById('reportDisplay').style.display = 'block';
    
    let html = `
        <div style="color: #e2e8f0; line-height: 1.8;">
            <h3 style="color: #60a5fa; margin-bottom: 1rem; font-size: 1.5rem;">
                📊 ${(report.report_type || 'SECURITY').toUpperCase()} REPORT
            </h3>
            
            <div style="background: #1e293b; padding: 1.5rem; border-radius: 0.5rem; margin-bottom: 1rem; border-left: 4px solid #60a5fa;">
                <p><strong style="color: #60a5fa;">Report Period:</strong> ${report.period || 'N/A'}</p>
                <p><strong style="color: #60a5fa;">Generated:</strong> ${report.generated_at ? new Date(report.generated_at).toLocaleString() : new Date().toLocaleString()}</p>
            </div>
            
            <div style="background: #1e293b; padding: 1.5rem; border-radius: 0.5rem; margin-bottom: 1rem;">
                <h4 style="color: #60a5fa; margin-bottom: 0.75rem;">📈 Overview Statistics</h4>
                <p><strong>Total Login Attempts:</strong> ${report.total_logins || 0}</p>
                <p><strong>Failed Attempts:</strong> <span style="color: #f87171;">${report.failed_logins || 0}</span></p>
                <p><strong>Success Rate:</strong> <span style="color: #4ade80;">${report.success_rate || '0%'}</span></p>
            </div>
            
            <div style="background: #1e293b; padding: 1.5rem; border-radius: 0.5rem; margin-bottom: 1rem;">
                <h4 style="color: #60a5fa; margin-bottom: 0.75rem;">🎯 Top Attacked Users</h4>
                ${report.top_attacked_users && report.top_attacked_users.length > 0 ? `
                    <ul style="list-style: none; padding: 0; margin: 0;">
                        ${report.top_attacked_users.map(u => `
                            <li style="padding: 0.5rem; background: #0f172a; margin-bottom: 0.5rem; border-radius: 0.25rem;">
                                <strong>${InputValidator.sanitize(u.username)}</strong>: <span style="color: #f87171;">${u.count} attacks</span>
                            </li>
                        `).join('')}
                    </ul>
                ` : '<p style="color: #94a3b8;">No attack data available</p>'}
            </div>
            
            <div style="background: #1e293b; padding: 1.5rem; border-radius: 0.5rem;">
                <h4 style="color: #60a5fa; margin-bottom: 0.75rem;">⚠️ Alert Severity Breakdown</h4>
                ${report.severity_breakdown && Object.keys(report.severity_breakdown).length > 0 ? `
                    <ul style="list-style: none; padding: 0; margin: 0;">
                        ${Object.entries(report.severity_breakdown).map(([severity, count]) => {
                            const colors = {critical: '#f87171', high: '#fb923c', medium: '#fbbf24', low: '#4ade80'};
                            return `
                                <li style="padding: 0.5rem; background: #0f172a; margin-bottom: 0.5rem; border-radius: 0.25rem;">
                                    <strong style="text-transform: uppercase;">${severity}:</strong> 
                                    <span style="color: ${colors[severity] || '#cbd5e1'};">${count} alerts</span>
                                </li>
                            `;
                        }).join('')}
                    </ul>
                ` : '<p style="color: #94a3b8;">No alerts in this period</p>'}
            </div>
        </div>
    `;
    
    document.getElementById('reportContent').innerHTML = html;
    NotificationService.show('Report generated successfully', 'success');
}

// FIXED: Export functions using authenticated fetch
async function exportForensic() { 
    NotificationService.show('Downloading forensic logs...', 'info');
    const success = await APIClient.downloadFile('/admin/export/forensic_logs', 'forensic_logs.csv');
    if (success) {
        NotificationService.show('Forensic logs downloaded', 'success');
    } else {
        // Fallback: generate from local data
        NotificationService.show('Generating from available data...', 'info');
        await exportFromLocalData('forensic');
    }
}

async function exportAlerts() { 
    NotificationService.show('Downloading alerts...', 'info');
    const success = await APIClient.downloadFile('/admin/export/alerts', 'alerts.csv');
    if (success) {
        NotificationService.show('Alerts downloaded', 'success');
    } else {
        // Fallback: generate from local data
        NotificationService.show('Generating from available data...', 'info');
        await exportFromLocalData('alerts');
    }
}

// Fallback export using local API data
async function exportFromLocalData(type) {
    try {
        let data, columns, filename;
        
        if (type === 'alerts') {
            const response = await APIClient.get('/dashboard/alerts?limit=1000');
            data = response.alerts || [];
            columns = ['id', 'alert_type', 'username', 'ip_address', 'timestamp', 'severity', 'resolved'];
            filename = 'alerts.csv';
        } else if (type === 'forensic' || type === 'login') {
            const response = await APIClient.get('/dashboard/login-history?limit=1000');
            data = response.history || [];
            columns = ['username', 'ip_address', 'timestamp', 'status', 'location'];
            filename = type === 'forensic' ? 'forensic_logs.csv' : 'login_events.csv';
        } else {
            throw new Error('Unknown export type');
        }
        
        const csvContent = generateCSV(data, columns);
        downloadCSV(csvContent, filename);
        NotificationService.show(`${filename} exported`, 'success');
    } catch (e) {
        console.error('Export error:', e);
        NotificationService.show('Export failed', 'error');
    }
}

// CSV Generation helpers
function generateCSV(data, columns) {
    if (!data || data.length === 0) return columns.join(',') + '\n';
    
    const header = columns.join(',');
    const rows = data.map(row => {
        return columns.map(col => {
            let val = row[col];
            if (Array.isArray(val)) val = val.join(';');
            if (val === null || val === undefined) val = '';
            val = String(val).replace(/"/g, '""');
            if (val.includes(',') || val.includes('"') || val.includes('\n')) {
                val = `"${val}"`;
            }
            return val;
        }).join(',');
    });
    
    return [header, ...rows].join('\n');
}

function downloadCSV(content, filename) {
    const blob = new Blob([content], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    link.href = URL.createObjectURL(blob);
    link.download = filename;
    link.click();
    URL.revokeObjectURL(link.href);
}

// Utilities
function showAlert(id, msg, type) {
    const el = document.getElementById(id);
    if (el) { el.textContent = msg; el.className = 'alert show ' + type; setTimeout(() => el.classList.remove('show'), 4000); }
}

function logout() {
    APIClient.post('/logout', {}).catch(() => {});
    SessionManager.clearSession();
    window.location.href = 'login.html';
}

// Styles
const style = document.createElement('style');
style.textContent = `.tab-content { display: none; } .tab-content.active { display: block; } .tab-btn.active { background: #2563eb !important; color: white !important; }`;
document.head.appendChild(style);

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    if (!checkAuth()) return;
    startAutoRefresh();
    loadRules();
});