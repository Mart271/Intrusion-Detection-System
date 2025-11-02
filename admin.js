const API_BASE = 'http://localhost:5000/api';

function logout() {
    alert('Logged out successfully');
    window.location.href = 'index.html';
}

async function loadAdminData() {
    try {
        // Fetch statistics
        const statsRes = await fetch(`${API_BASE}/dashboard/stats`);
        const stats = await statsRes.json();

        document.getElementById('totalLogins').textContent = stats.total_logins;
        document.getElementById('failedAttempts').textContent = stats.failed_attempts;
        document.getElementById('blockedIPs').textContent = stats.blocked_ips;
        document.getElementById('lockedUsers').textContent = stats.locked_users;
        document.getElementById('activeAlerts').textContent = stats.active_alerts;

        // Load configuration
        loadConfig();
        
        // Load users with failed attempts
        loadUsersTable();
        
        // Load blocked IPs
        loadBlockedIPsTable();
        
        // Load locked accounts
        loadLockedAccountsTable();
    } catch (error) {
        console.error('Error loading admin data:', error);
    }
}

async function loadUsersTable() {
    try {
        const res = await fetch(`${API_BASE}/dashboard/login-history?limit=100`);
        const data = await res.json();
        const history = data.history || [];

        // Group by username and count failed attempts
        const userStats = {};
        
        history.forEach(entry => {
            if (!userStats[entry.username]) {
                userStats[entry.username] = {
                    username: entry.username,
                    ip: entry.ip_address,
                    failed: 0,
                    success: 0,
                    lastAttempt: entry.timestamp,
                    status: 'active'
                };
            }
            
            if (entry.status === 'failed') {
                userStats[entry.username].failed++;
            } else {
                userStats[entry.username].success++;
            }
            
            // Keep most recent timestamp
            if (new Date(entry.timestamp) > new Date(userStats[entry.username].lastAttempt)) {
                userStats[entry.username].lastAttempt = entry.timestamp;
                userStats[entry.username].ip = entry.ip_address;
            }
        });

        const tbody = document.getElementById('usersTable');
        const users = Object.values(userStats);
        
        if (users.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No user activity</td></tr>';
            return;
        }

        // Sort by failed attempts (highest first)
        users.sort((a, b) => b.failed - a.failed);

        tbody.innerHTML = users.map(user => {
            const statusClass = user.failed >= 3 ? 'status-failed' : 'status-success';
            const statusText = user.failed >= 3 ? 'SUSPICIOUS' : 'NORMAL';
            
            return `
                <tr>
                    <td>${user.username}</td>
                    <td>${user.ip}</td>
                    <td><strong style="color: ${user.failed >= 3 ? '#f87171' : '#4ade80'}">${user.failed}</strong></td>
                    <td>${new Date(user.lastAttempt).toLocaleString()}</td>
                    <td><span class="${statusClass}">${statusText}</span></td>
                    <td>
                        <button class="btn" style="padding: 0.5rem 0.75rem; font-size: 0.85rem;" onclick="blockIP('${user.ip}')">Block IP</button>
                        <button class="btn danger" style="padding: 0.5rem 0.75rem; font-size: 0.85rem;" onclick="lockAccount('${user.username}')">Lock User</button>
                    </td>
                </tr>
            `;
        }).join('');
    } catch (error) {
        console.error('Error loading users table:', error);
    }
}

async function loadBlockedIPsTable() {
    try {
        const res = await fetch(`${API_BASE}/dashboard/login-history?limit=200`);
        const data = await res.json();
        const history = data.history || [];

        // Get IPs with multiple failed attempts (simulating blocked IPs)
        const ipStats = {};
        
        history.forEach(entry => {
            if (!ipStats[entry.ip_address]) {
                ipStats[entry.ip_address] = {
                    ip: entry.ip_address,
                    users: new Set(),
                    failed: 0,
                    firstSeen: entry.timestamp
                };
            }
            
            ipStats[entry.ip_address].users.add(entry.username);
            if (entry.status === 'failed') {
                ipStats[entry.ip_address].failed++;
            }
        });

        const tbody = document.getElementById('blockedIPsTable');
        const suspiciousIPs = Object.values(ipStats).filter(ip => ip.failed >= 5);
        
        if (suspiciousIPs.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No blocked IPs</td></tr>';
            return;
        }

        tbody.innerHTML = suspiciousIPs.map(ip => `
            <tr>
                <td>${ip.ip}</td>
                <td>${Array.from(ip.users).join(', ')}</td>
                <td><strong style="color: #f87171">${ip.failed}</strong></td>
                <td>${new Date(ip.firstSeen).toLocaleString()}</td>
                <td>
                    <button class="btn secondary" style="padding: 0.5rem 0.75rem; font-size: 0.85rem;" onclick="quickUnblockIP('${ip.ip}')">Unblock</button>
                </td>
            </tr>
        `).join('');
    } catch (error) {
        console.error('Error loading blocked IPs:', error);
    }
}

async function loadLockedAccountsTable() {
    try {
        const alertsRes = await fetch(`${API_BASE}/dashboard/alerts?limit=50`);
        const alertsData = await alertsRes.json();
        const alerts = alertsData.alerts || [];

        // Filter for lockout alerts
        const lockedAccounts = alerts.filter(a => 
            a.alert_type === 'BRUTE_FORCE_ATTACK' || 
            a.alert_type === 'MULTIPLE_FAILED_ATTEMPTS'
        );

        const tbody = document.getElementById('lockedAccountsTable');
        
        if (lockedAccounts.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No locked accounts</td></tr>';
            return;
        }

        tbody.innerHTML = lockedAccounts.slice(0, 10).map(account => {
            const lockedTime = new Date(account.timestamp);
            const unlockTime = new Date(lockedTime.getTime() + 15 * 60000); // +15 min
            
            return `
                <tr>
                    <td>${account.username}</td>
                    <td>${account.ip_address}</td>
                    <td>${lockedTime.toLocaleString()}</td>
                    <td>${unlockTime.toLocaleString()}</td>
                    <td>Brute-force detected</td>
                    <td>
                        <button class="btn secondary" style="padding: 0.5rem 0.75rem; font-size: 0.85rem;" onclick="quickUnlockAccount('${account.username}')">Unlock</button>
                    </td>
                </tr>
            `;
        }).join('');
    } catch (error) {
        console.error('Error loading locked accounts:', error);
    }
}

async function loadConfig() {
    try {
        const res = await fetch(`${API_BASE}/config`);
        const config = await res.json();

        document.getElementById('maxFailed').value = config.max_failed_attempts;
        document.getElementById('timeWindow').value = config.failed_attempts_window;
        document.getElementById('lockoutDuration').value = config.lockout_duration;
        document.getElementById('cooldownPeriod').value = config.cooldown_period;

        document.getElementById('currentSettings').innerHTML = `
            <p><strong>Max Failed Attempts:</strong> ${config.max_failed_attempts}</p>
            <p><strong>Time Window:</strong> ${config.failed_attempts_window}s (${Math.round(config.failed_attempts_window/60)} min)</p>
            <p><strong>Lockout Duration:</strong> ${config.lockout_duration}s (${Math.round(config.lockout_duration/60)} min)</p>
            <p><strong>Cooldown Period:</strong> ${config.cooldown_period}s (${Math.round(config.cooldown_period/60)} min)</p>
        `;
    } catch (error) {
        console.error('Error loading config:', error);
    }
}

async function blockIP() {
    const ip = document.getElementById('ipAddress').value.trim();
    
    if (!ip) {
        showAlert('ipAlert', 'Please enter an IP address', 'error');
        return;
    }

    try {
        const res = await fetch(`${API_BASE}/admin/block-ip`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ip})
        });
        
        const data = await res.json();
        showAlert('ipAlert', data.message, data.success ? 'success' : 'error');
        
        if (data.success) {
            document.getElementById('ipAddress').value = '';
            loadAdminData();
        }
    } catch (error) {
        showAlert('ipAlert', 'Error: ' + error.message, 'error');
    }
}

async function unblockIP() {
    const ip = document.getElementById('ipAddress').value.trim();
    
    if (!ip) {
        showAlert('ipAlert', 'Please enter an IP address', 'error');
        return;
    }

    try {
        const res = await fetch(`${API_BASE}/admin/unblock-ip`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ip})
        });
        
        const data = await res.json();
        showAlert('ipAlert', data.message, data.success ? 'success' : 'error');
        
        if (data.success) {
            document.getElementById('ipAddress').value = '';
            loadAdminData();
        }
    } catch (error) {
        showAlert('ipAlert', 'Error: ' + error.message, 'error');
    }
}

async function lockAccount() {
    const username = document.getElementById('username').value.trim();
    
    if (!username) {
        showAlert('accountAlert', 'Please enter a username', 'error');
        return;
    }

    try {
        const res = await fetch(`${API_BASE}/admin/lock-account`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username})
        });
        
        const data = await res.json();
        showAlert('accountAlert', data.message, data.success ? 'success' : 'error');
        
        if (data.success) {
            document.getElementById('username').value = '';
            loadAdminData();
        }
    } catch (error) {
        showAlert('accountAlert', 'Error: ' + error.message, 'error');
    }
}

async function unlockAccount() {
    const username = document.getElementById('username').value.trim();
    
    if (!username) {
        showAlert('accountAlert', 'Please enter a username', 'error');
        return;
    }

    try {
        const res = await fetch(`${API_BASE}/admin/unlock-account`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username})
        });
        
        const data = await res.json();
        showAlert('accountAlert', data.message, data.success ? 'success' : 'error');
        
        if (data.success) {
            document.getElementById('username').value = '';
            loadAdminData();
        }
    } catch (error) {
        showAlert('accountAlert', 'Error: ' + error.message, 'error');
    }
}

async function saveConfig() {
    try {
        const config = {
            max_failed_attempts: parseInt(document.getElementById('maxFailed').value),
            failed_attempts_window: parseInt(document.getElementById('timeWindow').value),
            lockout_duration: parseInt(document.getElementById('lockoutDuration').value),
            cooldown_period: parseInt(document.getElementById('cooldownPeriod').value)
        };

        const res = await fetch(`${API_BASE}/config`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(config)
        });
        
        const data = await res.json();
        showAlert('configAlert', 'Configuration saved successfully!', 'success');
        loadConfig();
    } catch (error) {
        showAlert('configAlert', 'Error: ' + error.message, 'error');
    }
}

function exportForensic() {
    window.location.href = `${API_BASE}/export/forensic-logs`;
}

function exportAlerts() {
    window.location.href = `${API_BASE}/export/alerts`;
}

function showAlert(id, message, type) {
    const el = document.getElementById(id);
    el.textContent = message;
    el.className = 'alert show ' + type;
    setTimeout(() => el.classList.remove('show'), 3000);
}

// Initial load
window.addEventListener('load', loadAdminData);

// Auto-refresh every 3 seconds
setInterval(loadAdminData, 3000);