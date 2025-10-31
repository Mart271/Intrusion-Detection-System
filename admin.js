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
    } catch (error) {
        console.error('Error loading admin data:', error);
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