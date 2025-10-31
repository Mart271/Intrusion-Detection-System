const API_BASE = 'http://localhost:5000/api';
let allLogs = [];

function logout() {
    alert('Logged out successfully');
    window.location.href = 'index.html';
}

async function loadAnalystData() {
    try {
        // Fetch alerts
        const alertsRes = await fetch(`${API_BASE}/dashboard/alerts?limit=20`);
        const alertsData = await alertsRes.json();
        const alerts = alertsData.alerts || [];

        // Count by severity
        const critical = alerts.filter(a => a.severity === 'critical').length;
        const high = alerts.filter(a => a.severity === 'high').length;

        document.getElementById('criticalCount').textContent = critical;
        document.getElementById('highCount').textContent = high;
        document.getElementById('totalAlerts').textContent = alerts.length;

        // Calculate success rate
        const statsRes = await fetch(`${API_BASE}/dashboard/stats`);
        const stats = await statsRes.json();
        const rate = stats.total_logins > 0 
            ? Math.round(((stats.total_logins - stats.failed_attempts) / stats.total_logins) * 100)
            : 0;
        document.getElementById('successRate').textContent = rate + '%';

        // Load alerts table
        loadAlertsTable(alerts);

        // Fetch login history
        const historyRes = await fetch(`${API_BASE}/dashboard/login-history?limit=50`);
        const historyData = await historyRes.json();
        allLogs = historyData.history || [];
        loadLogsTable(allLogs);
    } catch (error) {
        console.error('Error loading analyst data:', error);
    }
}

function loadAlertsTable(alerts) {
    const tbody = document.getElementById('alertsTable');
    
    if (alerts.length === 0) {
        tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No active alerts</td></tr>';
        return;
    }

    tbody.innerHTML = alerts.map(a => `
        <tr>
            <td>${a.alert_type}</td>
            <td>${a.username}</td>
            <td>${a.ip_address}</td>
            <td><span class="severity-${a.severity}">${a.severity.toUpperCase()}</span></td>
            <td>${new Date(a.timestamp).toLocaleString()}</td>
            <td><button class="btn" onclick="resolveAlert(${a.id})">Resolve</button></td>
        </tr>
    `).join('');
}

function loadLogsTable(logs) {
    const tbody = document.getElementById('logsTable');
    
    if (logs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="empty-state">No logs found</td></tr>';
        return;
    }

    tbody.innerHTML = logs.map(l => `
        <tr>
            <td>${new Date(l.timestamp).toLocaleString()}</td>
            <td>${l.username}</td>
            <td>${l.ip_address}</td>
            <td>${l.location}</td>
            <td><span class="status-${l.status}">${l.status.toUpperCase()}</span></td>
        </tr>
    `).join('');
}

function filterLogs() {
    const filter = document.getElementById('logFilter').value.toLowerCase();
    const filtered = allLogs.filter(log => 
        log.username.toLowerCase().includes(filter) || 
        log.ip_address.toLowerCase().includes(filter)
    );
    loadLogsTable(filtered);
}

async function resolveAlert(alertId) {
    try {
        const res = await fetch(`${API_BASE}/admin/resolve-alert`, {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({alert_id: alertId})
        });
        
        const data = await res.json();
        alert(data.message);
        loadAnalystData();
    } catch (error) {
        alert('Error resolving alert: ' + error.message);
    }
}

function exportLogs() {
    window.location.href = `${API_BASE}/export/forensic-logs`;
}

// Initial load
window.addEventListener('load', loadAnalystData);

// Auto-refresh every 3 seconds
setInterval(loadAnalystData, 3000);