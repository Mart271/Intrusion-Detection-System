const API_BASE = 'http://localhost:5000/api';
let refreshInterval = 5000; // 5 seconds
let refreshTimerId = null;

function logout() {
    if (confirm('Are you sure you want to logout?')) {
        window.location.href = 'login.html';
    }
}

function startAutoRefresh() {
    if (!refreshTimerId) {
        loadAdminData();
        refreshTimerId = setInterval(loadAdminData, refreshInterval);
        document.getElementById('refreshStatus').innerHTML = '🟢 Auto-Refresh: ON (' + (refreshInterval/1000) + 's)';
    }
}

function stopAutoRefresh() {
    if (refreshTimerId) {
        clearInterval(refreshTimerId);
        refreshTimerId = null;
        document.getElementById('refreshStatus').innerHTML = '🔴 Auto-Refresh: OFF';
    }
}

async function loadAdminData() {
    try {
        await Promise.all([
            loadStats(),
            loadConfig(),
            loadDetections(),
            loadAlerts(),
            loadAuditLog()
        ]);
    } catch (error) {
        console.error('Error loading admin data:', error);
    }
}

async function loadStats() {
    try {
        const statsRes = await fetch(`${API_BASE}/dashboard/stats`);
        const stats = await statsRes.json();

        document.getElementById('totalLogins').textContent = stats.total_logins || 0;
        document.getElementById('failedAttempts').textContent = stats.failed_attempts || 0;
        document.getElementById('activeAlerts').textContent = stats.active_alerts || 0;
        document.getElementById('unreviewedDetections').textContent = stats.unreviewed_detections || 0;
        document.getElementById('blockedIPs').textContent = stats.blocked_ips || 0;
        document.getElementById('lockedAccounts').textContent = stats.locked_accounts || 0;
    } catch (error) {
        console.error('Error loading stats:', error);
    }
}

async function loadConfig() {
    try {
        const res = await fetch(`${API_BASE}/config`);
        const config = await res.json();

        // Populate form fields
        document.getElementById('detectionWindow').value = config.detection_window || 120;
        document.getElementById('rapidThreshold').value = config.rapid_failure_threshold || 3;
        document.getElementById('sustainedThreshold').value = config.sustained_failure_threshold || 10;
        document.getElementById('distributedThreshold').value = config.distributed_attack_threshold || 5;
        document.getElementById('stuffingThreshold').value = config.credential_stuffing_threshold || 10;
        document.getElementById('travelTime').value = config.impossible_travel_time || 300;

        // Display current settings
        document.getElementById('currentSettings').innerHTML = `
            <p><strong>Detection Window:</strong> ${config.detection_window}s (${Math.round(config.detection_window/60)} min)</p>
            <p><strong>Rapid Failure Threshold:</strong> ${config.rapid_failure_threshold} attempts</p>
            <p><strong>Sustained Attack Threshold:</strong> ${config.sustained_failure_threshold} attempts</p>
            <p><strong>Distributed Attack Threshold:</strong> ${config.distributed_attack_threshold} IPs</p>
            <p><strong>Credential Stuffing Threshold:</strong> ${config.credential_stuffing_threshold} usernames</p>
            <p><strong>Impossible Travel Time:</strong> ${config.impossible_travel_time}s (${Math.round(config.impossible_travel_time/60)} min)</p>
            <p style="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid #334155;"><strong>Active Detection Rules:</strong></p>
            ${config.detection_rules ? config.detection_rules.map(rule => 
                `<p style="margin-left: 1rem;">• ${rule.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())}</p>`
            ).join('') : '<p style="margin-left: 1rem; color: #94a3b8;">No rules configured</p>'}
        `;
    } catch (error) {
        console.error('Error loading config:', error);
    }
}

async function loadDetections() {
    try {
        const res = await fetch(`${API_BASE}/analyst/detections?limit=20`);
        const data = await res.json();
        const detections = data.detections || [];

        const tbody = document.getElementById('detectionsTable');
        
        if (detections.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="empty-state">No detections</td></tr>';
            return;
        }

        tbody.innerHTML = detections.map(d => {
            const severityBadge = getSeverityBadge(d.severity);
            const reviewBadge = getReviewBadge(d.analyst_review);
            
            return `
                <tr>
                    <td><strong>#${d.id}</strong></td>
                    <td>${formatPatternName(d.pattern_type)}</td>
                    <td>${d.username || '-'}</td>
                    <td>${d.ip_address || '-'}</td>
                    <td>${severityBadge}</td>
                    <td>${new Date(d.timestamp).toLocaleString()}</td>
                    <td>${reviewBadge}</td>
                </tr>
            `;
        }).join('');
    } catch (error) {
        console.error('Error loading detections:', error);
    }
}

async function loadAlerts() {
    try {
        const res = await fetch(`${API_BASE}/dashboard/alerts?limit=20`);
        const data = await res.json();
        const alerts = data.alerts || [];

        const tbody = document.getElementById('alertsTable');
        
        if (alerts.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No active alerts</td></tr>';
            return;
        }

        tbody.innerHTML = alerts.map(a => {
            const severityBadge = getSeverityBadge(a.severity);
            
            return `
                <tr>
                    <td>${a.alert_type}</td>
                    <td>${a.username}</td>
                    <td>${a.ip_address}</td>
                    <td>${severityBadge}</td>
                    <td>${new Date(a.timestamp).toLocaleString()}</td>
                </tr>
            `;
        }).join('');
    } catch (error) {
        console.error('Error loading alerts:', error);
    }
}

async function loadAuditLog() {
    try {
        const res = await fetch(`${API_BASE}/audit-log?limit=30`);
        const data = await res.json();
        const logs = data.audit_log || [];

        const tbody = document.getElementById('auditTable');
        
        if (logs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No audit entries</td></tr>';
            return;
        }

        tbody.innerHTML = logs.map(l => `
            <tr>
                <td>${l.event_type}</td>
                <td>${l.user}</td>
                <td>${l.ip || '-'}</td>
                <td>${l.action}</td>
                <td>${new Date(l.timestamp).toLocaleString()}</td>
                <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${l.details || '-'}</td>
            </tr>
        `).join('');
    } catch (error) {
        console.error('Error loading audit log:', error);
    }
}

async function saveConfig() {
    try {
        const config = {
            detection_window: parseInt(document.getElementById('detectionWindow').value),
            rapid_failure_threshold: parseInt(document.getElementById('rapidThreshold').value),
            sustained_failure_threshold: parseInt(document.getElementById('sustainedThreshold').value),
            distributed_attack_threshold: parseInt(document.getElementById('distributedThreshold').value),
            credential_stuffing_threshold: parseInt(document.getElementById('stuffingThreshold').value),
            impossible_travel_time: parseInt(document.getElementById('travelTime').value)
        };

        const res = await fetch(`${API_BASE}/config`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(config)
        });
        
        const data = await res.json();
        
        if (data.success) {
            showAlert('configAlert', '✅ Configuration saved successfully!', 'success');
            loadConfig();
        } else {
            showAlert('configAlert', '❌ Error saving configuration: ' + data.message, 'error');
        }
    } catch (error) {
        showAlert('configAlert', '❌ Error: ' + error.message, 'error');
    }
}

// ==================== ENFORCEMENT FUNCTIONS ====================

async function blockIP() {
    try {
        const ip = document.getElementById('blockIpAddress').value.trim();
        const reason = document.getElementById('blockIpReason').value.trim();
        
        if (!ip) {
            showAlert('enforcementAlert', '❌ Please enter an IP address', 'error');
            return;
        }
        
        if (!reason) {
            showAlert('enforcementAlert', '❌ Please enter a reason for blocking', 'error');
            return;
        }
        
        const res = await fetch(`${API_BASE}/admin/block-ip`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                ip: ip,
                reason: reason,
                admin: 'ADMIN'
            })
        });
        
        const data = await res.json();
        
        if (data.success) {
            showAlert('enforcementAlert', `✅ ${data.message}`, 'success');
            document.getElementById('blockIpAddress').value = '';
            document.getElementById('blockIpReason').value = '';
            loadAdminData();
        } else {
            showAlert('enforcementAlert', '❌ Error: ' + data.message, 'error');
        }
    } catch (error) {
        showAlert('enforcementAlert', '❌ Error blocking IP: ' + error.message, 'error');
    }
}

async function unblockIP() {
    try {
        const ip = document.getElementById('unblockIpAddress').value.trim();
        
        if (!ip) {
            showAlert('enforcementAlert', '❌ Please enter an IP address', 'error');
            return;
        }
        
        const res = await fetch(`${API_BASE}/admin/unblock-ip`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ ip: ip })
        });
        
        const data = await res.json();
        
        if (data.success) {
            showAlert('enforcementAlert', `✅ ${data.message}`, 'success');
            document.getElementById('unblockIpAddress').value = '';
            loadAdminData();
        } else {
            showAlert('enforcementAlert', '❌ Error: ' + data.message, 'error');
        }
    } catch (error) {
        showAlert('enforcementAlert', '❌ Error unblocking IP: ' + error.message, 'error');
    }
}

async function lockAccount() {
    try {
        const username = document.getElementById('lockUsername').value.trim();
        const reason = document.getElementById('lockReason').value.trim();
        
        if (!username) {
            showAlert('enforcementAlert', '❌ Please enter a username', 'error');
            return;
        }
        
        if (!reason) {
            showAlert('enforcementAlert', '❌ Please enter a reason for locking', 'error');
            return;
        }
        
        const res = await fetch(`${API_BASE}/admin/lock-account`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                username: username,
                reason: reason,
                admin: 'ADMIN'
            })
        });
        
        const data = await res.json();
        
        if (data.success) {
            showAlert('enforcementAlert', `✅ ${data.message}`, 'success');
            document.getElementById('lockUsername').value = '';
            document.getElementById('lockReason').value = '';
            loadAdminData();
        } else {
            showAlert('enforcementAlert', '❌ Error: ' + data.message, 'error');
        }
    } catch (error) {
        showAlert('enforcementAlert', '❌ Error locking account: ' + error.message, 'error');
    }
}

async function unlockAccount() {
    try {
        const username = document.getElementById('unlockUsername').value.trim();
        
        if (!username) {
            showAlert('enforcementAlert', '❌ Please enter a username', 'error');
            return;
        }
        
        const res = await fetch(`${API_BASE}/admin/unlock-account`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({
                username: username,
                admin: 'ADMIN'
            })
        });
        
        const data = await res.json();
        
        if (data.success) {
            showAlert('enforcementAlert', `✅ ${data.message}`, 'success');
            document.getElementById('unlockUsername').value = '';
            loadAdminData();
        } else {
            showAlert('enforcementAlert', '❌ Error: ' + data.message, 'error');
        }
    } catch (error) {
        showAlert('enforcementAlert', '❌ Error unlocking account: ' + error.message, 'error');
    }
}

function exportForensicLogs() {
    window.location.href = `${API_BASE}/export/forensic-logs`;
}

function exportDetections() {
    window.location.href = `${API_BASE}/export/detections`;
}

function exportAlerts() {
    window.location.href = `${API_BASE}/export/alerts`;
}

function showAlert(id, message, type) {
    const el = document.getElementById(id);
    el.textContent = message;
    el.className = 'alert show ' + type;
    setTimeout(() => el.classList.remove('show'), 5000);
}

// ==================== HELPER FUNCTIONS ====================

function formatPatternName(pattern) {
    return pattern.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
}

function getSeverityBadge(severity) {
    const badges = {
        'critical': '<span class="badge danger">🚨 CRITICAL</span>',
        'high': '<span class="badge danger">⚠️ HIGH</span>',
        'medium': '<span class="badge warning">⚡ MEDIUM</span>',
        'low': '<span class="badge success">ℹ️ LOW</span>'
    };
    return badges[severity] || '<span class="badge">-</span>';
}

function getReviewBadge(status) {
    const badges = {
        'pending': '<span class="badge warning">⏳ Pending</span>',
        'true_positive': '<span class="badge danger">✅ True Positive</span>',
        'false_positive': '<span class="badge success">❌ False Positive</span>',
        'investigate': '<span class="badge" style="background: #1e3a8a; color: #93c5fd;">🔍 Investigating</span>'
    };
    return badges[status] || '<span class="badge">Unknown</span>';
}

// ==================== INITIALIZATION ====================

document.addEventListener('DOMContentLoaded', () => {
    startAutoRefresh();
});