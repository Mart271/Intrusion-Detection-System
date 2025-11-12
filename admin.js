const API_BASE = 'http://localhost:5000/api';
let refreshInterval = 500;
let refreshTimerId = null;
let pendingNotifications = [];

function logout() {
    window.location.href = 'index.html';
}

function startAutoRefresh() {
    if (!refreshTimerId) {
        loadAdminData();
        refreshTimerId = setInterval(loadAdminData, refreshInterval);
        document.getElementById('refreshStatus').innerHTML = '🟢 Auto-Refresh: ON (' + refreshInterval + 'ms)';
    }
}

function stopAutoRefresh() {
    if (refreshTimerId) {
        clearInterval(refreshTimerId);
        refreshTimerId = null;
        document.getElementById('refreshStatus').innerHTML = '🔴 Auto-Refresh: OFF';
    }
}

function setRefreshSpeed(speed) {
    refreshInterval = speed;
    if (refreshTimerId) {
        stopAutoRefresh();
        startAutoRefresh();
    }
}

// Check for analyst notifications
async function checkAnalystNotifications() {
    try {
        const res = await fetch(`${API_BASE}/dashboard/alerts?limit=10`);
        const data = await res.json();
        const recentResolved = (data.alerts || []).filter(a => 
            a.resolved === 1 && 
            new Date(a.timestamp) > new Date(Date.now() - 60000) // Last minute
        );
        
        recentResolved.forEach(alert => {
            const notifKey = `alert_${alert.id}`;
            if (!pendingNotifications.includes(notifKey)) {
                pendingNotifications.push(notifKey);
                showNotification(`🔔 Analyst resolved alert for ${alert.username} (${alert.ip_address})`);
            }
        });
    } catch (error) {
        console.error('Error checking notifications:', error);
    }
}

function showNotification(message) {
    // Create notification element
    const notif = document.createElement('div');
    notif.style.cssText = `
        position: fixed;
        top: 80px;
        right: 20px;
        background: #3b82f6;
        color: white;
        padding: 1rem 1.5rem;
        border-radius: 0.5rem;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        z-index: 9999;
        animation: slideIn 0.3s ease-out;
    `;
    notif.textContent = message;
    document.body.appendChild(notif);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        notif.style.animation = 'slideOut 0.3s ease-out';
        setTimeout(() => notif.remove(), 300);
    }, 5000);
}

async function loadAdminData() {
    try {
        const statsRes = await fetch(`${API_BASE}/dashboard/stats`);
        const stats = await statsRes.json();

        // Update all stat cards with safe defaults
        document.getElementById('totalLogins').textContent = stats.total_logins || 0;
        document.getElementById('failedAttempts').textContent = stats.failed_attempts || 0;
        document.getElementById('activeAlerts').textContent = stats.active_alerts || 0;
        document.getElementById('unreviewedDetections').textContent = stats.unreviewed_detections || 0;
        document.getElementById('blockedIPs').textContent = stats.blocked_ips || 0;
        document.getElementById('lockedUsers').textContent = stats.locked_accounts || 0;
        document.getElementById('rateLimitedIPs').textContent = stats.rate_limited_ips || 0;

        // Load all tables
        loadUsersTable();
        loadBlockedIPsTable();
        loadLockedAccountsTable();
        checkAnalystNotifications();
    } catch (error) {
        console.error('Error loading admin data:', error);
        // Set all stats to 0 on error
        ['totalLogins', 'failedAttempts', 'activeAlerts', 'unreviewedDetections', 
         'blockedIPs', 'lockedUsers', 'rateLimitedIPs'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.textContent = '0';
        });
    }
}

// Configuration functions removed - settings are managed in backend
// async function loadConfig() { ... }

async function loadUsersTable() {
    try {
        const res = await fetch(`${API_BASE}/dashboard/login-history?limit=100`);
        const data = await res.json();
        const history = data.history || [];

        const userStats = {};
        history.forEach(entry => {
            if (!userStats[entry.username]) {
                userStats[entry.username] = {
                    username: entry.username,
                    ip: entry.ip_address,
                    failed: 0,
                    lastAttempt: entry.timestamp,
                };
            }
            
            if (entry.status === 'failed') {
                userStats[entry.username].failed++;
            }
            
            if (new Date(entry.timestamp) > new Date(userStats[entry.username].lastAttempt)) {
                userStats[entry.username].lastAttempt = entry.timestamp;
                userStats[entry.username].ip = entry.ip_address;
            }
        });

        const tbody = document.getElementById('usersTable');
        const users = Object.values(userStats).sort((a, b) => b.failed - a.failed);
        
        if (users.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No user activity</td></tr>';
            return;
        }

        tbody.innerHTML = users.map(user => {
            const statusClass = user.failed >= 3 ? 'danger' : 'success';
            const statusText = user.failed >= 3 ? 'SUSPICIOUS' : 'NORMAL';
            
            return `
                <tr>
                    <td>${user.username}</td>
                    <td>${user.ip}</td>
                    <td><strong style="color: ${user.failed >= 3 ? '#f87171' : '#4ade80'}">${user.failed}</strong></td>
                    <td>${new Date(user.lastAttempt).toLocaleString()}</td>
                    <td><span class="badge ${statusClass}">${statusText}</span></td>
                    <td>
                        <button style="padding: 0.5rem; font-size: 0.75rem;" onclick="lockAccountQuick('${user.username}')" class="danger">Lock</button>
                    </td>
                </tr>
            `;
        }).join('');
    } catch (error) {
        console.error('Error loading users table:', error);
        const tbody = document.getElementById('usersTable');
        if (tbody) tbody.innerHTML = '<tr><td colspan="6" class="empty-state">Error loading user data</td></tr>';
    }
}

async function loadBlockedIPsTable() {
    try {
        const res = await fetch(`${API_BASE}/dashboard/login-history?limit=200`);
        const data = await res.json();
        const history = data.history || [];

        const ipStats = {};
        history.forEach(entry => {
            if (!ipStats[entry.ip_address]) {
                ipStats[entry.ip_address] = {
                    ip: entry.ip_address,
                    failed: 0,
                    firstSeen: entry.timestamp
                };
            }
            
            if (entry.status === 'failed') {
                ipStats[entry.ip_address].failed++;
            }
        });

        const tbody = document.getElementById('blockedIPsTable');
        const suspicious = Object.values(ipStats).filter(ip => ip.failed >= 5).slice(0, 10);
        
        if (suspicious.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No suspicious IPs</td></tr>';
            return;
        }

        tbody.innerHTML = suspicious.map(ip => `
            <tr>
                <td>${ip.ip}</td>
                <td><strong style="color: #f87171">${ip.failed}</strong></td>
                <td>${new Date(ip.firstSeen).toLocaleString()}</td>
                <td>
                    <button style="padding: 0.5rem; font-size: 0.75rem; margin-right: 0.25rem;" 
                            onclick="blockIPQuick('${ip.ip}')" class="danger">Block</button>
                    <button style="padding: 0.5rem; font-size: 0.75rem;" 
                            onclick="unblockIPQuick('${ip.ip}')" class="success">Unblock</button>
                </td>
            </tr>
        `).join('');
    } catch (error) {
        console.error('Error loading blocked IPs table:', error);
        const tbody = document.getElementById('blockedIPsTable');
        if (tbody) tbody.innerHTML = '<tr><td colspan="4" class="empty-state">Error loading IP data</td></tr>';
    }
}

async function loadLockedAccountsTable() {
    try {
        const res = await fetch(`${API_BASE}/dashboard/alerts?limit=50`);
        const data = await res.json();
        const alerts = data.alerts || [];

        const locked = alerts.filter(a => a.alert_type === 'MULTIPLE_FAILED_ATTEMPTS' || a.alert_type === 'multiple_failed_attempts').slice(0, 10);
        const tbody = document.getElementById('lockedAccountsTable');
        
        if (locked.length === 0) {
            tbody.innerHTML = '<tr><td colspan="4" class="empty-state">No locked accounts</td></tr>';
            return;
        }

        tbody.innerHTML = locked.map(a => {
            const lockedTime = new Date(a.timestamp);
            const unlockTime = new Date(lockedTime.getTime() + 15 * 60000);
            
            return `
                <tr>
                    <td>${a.username}</td>
                    <td>${lockedTime.toLocaleString()}</td>
                    <td>${unlockTime.toLocaleString()}</td>
                    <td><button style="padding: 0.5rem; font-size: 0.75rem;" onclick="unlockAccountQuick('${a.username}')" class="success">Unlock</button></td>
                </tr>
            `;
        }).join('');
    } catch (error) {
        console.error('Error loading locked accounts table:', error);
        const tbody = document.getElementById('lockedAccountsTable');
        if (tbody) tbody.innerHTML = '<tr><td colspan="4" class="empty-state">Error loading locked accounts</td></tr>';
    }
}

async function blockIP() {
    const ip = document.getElementById('ipAddress').value.trim();
    if (!ip) {
        showAlert('ipAlert', '⚠️ Please enter an IP address', 'error');
        return;
    }

    // Validate IP format
    const ipPattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipPattern.test(ip)) {
        showAlert('ipAlert', '⚠️ Invalid IP address format', 'error');
        return;
    }

    try {
        console.log('Blocking IP:', ip);
        
        const res = await fetch(`${API_BASE}/admin/block-ip`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ ip: ip })
        });
        
        console.log('Response status:', res.status);
        
        const data = await res.json();
        console.log('Response data:', data);
        
        if (data.success) {
            showAlert('ipAlert', '✅ ' + data.message, 'success');
            document.getElementById('ipAddress').value = '';
            setTimeout(() => loadAdminData(), 500);
        } else {
            showAlert('ipAlert', '❌ ' + data.message, 'error');
        }
    } catch (error) {
        console.error('Block IP Error:', error);
        showAlert('ipAlert', '❌ Error: ' + error.message, 'error');
    }
}

async function unblockIP() {
    const ip = document.getElementById('ipAddress').value.trim();
    if (!ip) {
        showAlert('ipAlert', '⚠️ Please enter an IP address', 'error');
        return;
    }

    try {
        const res = await fetch(`${API_BASE}/admin/unblock-ip`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ip})
        });
        const data = await res.json();
        showAlert('ipAlert', data.success ? '✅ ' + data.message : '❌ ' + data.message, data.success ? 'success' : 'error');
        if (data.success) {
            document.getElementById('ipAddress').value = '';
            setTimeout(() => loadAdminData(), 500);
        }
    } catch (error) {
        showAlert('ipAlert', '❌ Error: ' + error.message, 'error');
    }
}

async function blockIPQuick(ip) {
    if (!confirm(`Block IP address: ${ip}?`)) return;
    document.getElementById('ipAddress').value = ip;
    await blockIP();
}

async function unblockIPQuick(ip) {
    document.getElementById('ipAddress').value = ip;
    await unblockIP();
}

async function lockAccount() {
    const username = document.getElementById('username').value.trim();
    if (!username) {
        showAlert('accountAlert', '⚠️ Please enter a username', 'error');
        return;
    }

    try {
        const res = await fetch(`${API_BASE}/admin/lock-account`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username})
        });
        const data = await res.json();
        showAlert('accountAlert', data.success ? '✅ ' + data.message : '❌ ' + data.message, data.success ? 'success' : 'error');
        if (data.success) {
            document.getElementById('username').value = '';
            setTimeout(() => loadAdminData(), 500);
        }
    } catch (error) {
        showAlert('accountAlert', '❌ Error: ' + error.message, 'error');
    }
}

async function unlockAccount() {
    const username = document.getElementById('username').value.trim();
    if (!username) {
        showAlert('accountAlert', '⚠️ Please enter a username', 'error');
        return;
    }

    try {
        const res = await fetch(`${API_BASE}/admin/unlock-account`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username})
        });
        const data = await res.json();
        showAlert('accountAlert', data.success ? '✅ ' + data.message : '❌ ' + data.message, data.success ? 'success' : 'error');
        if (data.success) {
            document.getElementById('username').value = '';
            setTimeout(() => loadAdminData(), 500);
        }
    } catch (error) {
        showAlert('accountAlert', '❌ Error: ' + error.message, 'error');
    }
}

async function lockAccountQuick(username) {
    if (!confirm(`Lock account: ${username}?`)) return;
    document.getElementById('username').value = username;
    await lockAccount();
}

async function unlockAccountQuick(username) {
    document.getElementById('username').value = username;
    await unlockAccount();
}

// saveConfig function removed - settings are managed in backend
// async function saveConfig() { ... }

function exportForensic() {
    window.location.href = `${API_BASE}/export/forensic-logs`;
}

function exportAlerts() {
    window.location.href = `${API_BASE}/export/alerts`;
}

function showAlert(id, message, type) {
    const el = document.getElementById(id);
    if (el) {
        el.textContent = message;
        el.className = 'alert show ' + type;
        setTimeout(() => el.classList.remove('show'), 4000);
    }
}

// Add CSS for notifications
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(400px); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(400px); opacity: 0; }
    }
`;
document.head.appendChild(style);

// Initialize
document.addEventListener('DOMContentLoaded', () => {
    startAutoRefresh();
    // Check for notifications every 10 seconds
    setInterval(checkAnalystNotifications, 10000);
});